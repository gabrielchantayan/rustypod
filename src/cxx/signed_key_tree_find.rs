//! Signed-key tree value lookup — original: `FUN_0839bccc` @ `0x0839bccc`
//! (**84 bytes**, exactly `0x0839bccc..0x0839bd20`; the next separately
//! linked function starts with `push {r4-r8,lr}` at `0x0839bd20`).
//!
//! Decoding every ARM B/BL word in `osos.dec` finds exactly **8 direct
//! unconditional `bl` call sites** — 0x081bca78, 0x081bd1fc, 0x081bd67c,
//! 0x081bdcf4, 0x081bdf74, 0x081be008, 0x081be0cc, and 0x081be144. There are
//! no predicated calls, direct `b` transfers, or aligned data-word references.
//!
//! The body materializes the signed `key` on its stack, calls the still-retail
//! `std::_Rb_tree::lower_bound` specialization at 0x083dbab4, then compares
//! the returned node with `tree->header` through the ported `equal_deref`
//! copy at 0x083cf950. A non-header node is a match: the function writes its
//! value word at node+0x14 to `out_value` and returns 1. A header node is a
//! miss: it leaves `out_value` untouched and returns 0. The lower-bound helper
//! compares signed keys through `less_signed` at 0x083d7580, establishing the
//! signed-key identity without inventing the mapped value type.
//!
//! Deliberate deviation: 0x083dbab4 is not ported, so target builds invoke its
//! retailOS load address and host tests replace only that boundary through a
//! volatile dispatch seam. The equality leaf is inlined as `candidate !=
//! header`, which is its exact normalized result at this call site.

use core::ptr::{addr_of, addr_of_mut};

/// The tree prefix consumed here: its header/sentinel pointer is at +0x10.
///
/// The preceding words are opaque because this wrapper neither reads nor
/// writes them. All fields are target-width words, so the layout remains 20
/// bytes on hosts as well as ARM.
#[repr(C)]
pub struct SignedKeyTree {
    pub opaque_prefix: [u32; 4],
    pub header: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(SignedKeyTree, header)];
const _: [u8; 0x14] = [0; core::mem::size_of::<SignedKeyTree>()];

/// Firmware load address of the still-unported signed-key lower-bound helper
/// `FUN_083dbab4`.
pub const SIGNED_KEY_TREE_LOWER_BOUND_ADDRESS: usize = 0x083d_bab4;

/// ABI of the lower-bound helper. It stores the selected node in `out_node`.
pub type SignedKeyTreeLowerBound = unsafe extern "C" fn(
    out_node: *mut u32,
    tree: *const SignedKeyTree,
    key: *const i32,
);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_signed_key_tree_lower_bound(
    out_node: *mut u32,
    tree: *const SignedKeyTree,
    key: *const i32,
) {
    let lower_bound: SignedKeyTreeLowerBound =
        core::mem::transmute(SIGNED_KEY_TREE_LOWER_BOUND_ADDRESS);
    lower_bound(out_node, tree, key);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_signed_key_tree_lower_bound(
    _out_node: *mut u32,
    _tree: *const SignedKeyTree,
    _key: *const i32,
) {
    panic!("signed_key_tree_find_value requires lower-bound helper 0x083dbab4")
}

/// Boundary for the still-retail lower-bound helper at 0x083dbab4.
///
/// Device builds default to the fixed load address; host tests replace this
/// mutable slot to observe the stack-materialized signed key and selected node.
#[cfg(target_os = "none")]
pub static mut SIGNED_KEY_TREE_LOWER_BOUND: SignedKeyTreeLowerBound =
    firmware_signed_key_tree_lower_bound;

#[cfg(not(target_os = "none"))]
pub static mut SIGNED_KEY_TREE_LOWER_BOUND: SignedKeyTreeLowerBound =
    missing_signed_key_tree_lower_bound;

/// signed_key_tree_find_value — original: `FUN_0839bccc` @ `0x0839bccc`
/// (84 bytes; 8 direct, unconditional `bl` call sites).
///
/// Looks up signed `key` in `tree`. On a match, stores the target-width value
/// word at the selected node's +0x14 slot into `out_value` and returns 1. On a
/// miss, leaves `out_value` untouched and returns 0.
///
/// # Safety
///
/// `tree` must designate a readable [`SignedKeyTree`], `out_value` must be
/// writable on a match, and the installed lower-bound helper must obey
/// [`SignedKeyTreeLowerBound`]. A matching node must have a readable aligned
/// word at +0x14. As in the original, none of these pointers is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_key_tree_find_value(
    tree: *const SignedKeyTree,
    key: i32,
    out_value: *mut u32,
) -> u32 {
    let mut candidate = 0u32;
    let lower_bound = core::ptr::read_volatile(addr_of!(SIGNED_KEY_TREE_LOWER_BOUND));
    lower_bound(addr_of_mut!(candidate), tree, addr_of!(key));

    let header = addr_of!((*tree).header).read();
    if candidate == header {
        return 0;
    }

    out_value.write((candidate as usize as *const u32).add(5).read());
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;
    use std::{ptr, vec, vec::Vec};

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(usize, i32)> = Vec::new();
    static mut NEXT_NODE: u32 = 0;

    unsafe extern "C" fn recording_lower_bound(
        out_node: *mut u32,
        tree: *const SignedKeyTree,
        key: *const i32,
    ) {
        (*ptr::addr_of_mut!(CALLS)).push((tree as usize, key.read()));
        out_node.write(ptr::addr_of!(NEXT_NODE).read_volatile());
    }

    struct SeamGuard;

    impl SeamGuard {
        unsafe fn install(node: u32) -> Self {
            ptr::addr_of_mut!(NEXT_NODE).write_volatile(node);
            (*ptr::addr_of_mut!(CALLS)).clear();
            ptr::addr_of_mut!(SIGNED_KEY_TREE_LOWER_BOUND).write_volatile(recording_lower_bound);
            Self
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(SIGNED_KEY_TREE_LOWER_BOUND)
                    .write_volatile(missing_signed_key_tree_lower_bound);
            }
        }
    }

    fn calls() -> Vec<(usize, i32)> {
        unsafe { (*ptr::addr_of!(CALLS)).clone() }
    }

    #[test]
    fn header_result_is_a_miss_and_preserves_output() {
        let _seam_lock = SEAM_LOCK.lock();
        let tree = SignedKeyTree { opaque_prefix: [0; 4], header: 0x3344_5566 };
        let _seam = unsafe { SeamGuard::install(tree.header) };
        let mut output = 0xa5a5_5a5a;

        let found = unsafe {
            signed_key_tree_find_value(&tree, i32::MAX, ptr::addr_of_mut!(output))
        };

        assert_eq!(found, 0);
        assert_eq!(output, 0xa5a5_5a5a);
        assert_eq!(calls(), vec![(ptr::addr_of!(tree) as usize, i32::MAX)]);
    }

    #[test]
    fn non_header_result_reads_node_value_and_forwards_negative_key() {
        let Some(node) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SIGNED_KEY_TREE_FIND_VALUE,
            0x1000,
        ) else {
            return;
        };
        let _seam_lock = SEAM_LOCK.lock();
        unsafe { node.cast::<u32>().add(5).write(0xdead_beef) };
        let node_word = node as usize as u32;
        let tree = SignedKeyTree { opaque_prefix: [0; 4], header: 0 };
        let _seam = unsafe { SeamGuard::install(node_word) };
        let mut output = 0;

        let found = unsafe {
            signed_key_tree_find_value(&tree, i32::MIN, ptr::addr_of_mut!(output))
        };

        assert_eq!(found, 1);
        assert_eq!(output, 0xdead_beef);
        assert_eq!(calls(), vec![(ptr::addr_of!(tree) as usize, i32::MIN)]);
    }
}
