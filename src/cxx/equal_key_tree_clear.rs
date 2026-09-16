//! Equality-keyed tree clear entry — original: `FUN_083dbdfc` @
//! `0x083dbdfc` (**56 bytes**, exactly `0x083dbdfc..0x083dbe34`; the next
//! separately linked function opens with `push {r1-r5,lr}` at
//! `0x083dbe34`).
//!
//! Decoding every ARM B/BL word in `osos.dec` finds exactly **4 direct,
//! unconditional `bl` call sites** — 0x080ca5bc, 0x080ca5c4, 0x080ca654,
//! and 0x080ca65c. There are no predicated calls, direct `b` transfers, or
//! aligned data-word references. The body itself contains exactly **one**
//! `bl` (to the inner helper at 0x083befac) and no predicated calls.
//!
//! The tree belongs to the libstdc++ `_Rb_tree` instantiation whose
//! comparator is the ported `equal_deref` copy @ 0x083cf6b0 — node keys
//! compare by equality, not ordering. The body loads the header/sentinel
//! pointer from tree+0x10, reads the header's left link (+0x8, the
//! leftmost node), materializes three target-width stack slots —
//! `out = header`, `key = header->left`, `guard = header` — and tail-calls
//! the still-retail inner clear @ 0x083befac with
//! `(&out, tree, &key, &guard)`. That inner helper re-derives
//! `header->left` and `header`, equality-compares them against the passed
//! `key`/`guard` slots, and — when both match and the node count at
//! tree+0x14 is nonzero — destroys the subtree rooted at header->parent
//! through 0x083bf218 and rewires the header circular with the count
//! zeroed. This wrapper is therefore the canonical "clear the tree"
//! entry for the family.
//!
//! Deliberate deviation: 0x083befac is not ported, so target builds
//! invoke its retailOS load address and host tests replace only that
//! boundary through a volatile dispatch seam. The original's redundant
//! double load of tree+0x10 and the temporary slot shuffles are
//! represented once each in Rust; the slot values observed by the callee
//! are bit-identical.

use core::ptr::{addr_of, addr_of_mut};

/// The tree prefix consumed here: its header/sentinel pointer is at +0x10.
///
/// The preceding words are opaque because this wrapper neither reads nor
/// writes them. All fields are target-width words, so the layout is 20
/// bytes on hosts as well as ARM.
#[repr(C)]
pub struct EqualKeyTree {
    pub opaque_prefix: [u32; 4],
    pub header: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(EqualKeyTree, header)];
const _: [u8; 0x14] = [0; core::mem::size_of::<EqualKeyTree>()];

/// Firmware load address of the still-unported inner clear helper
/// `FUN_083befac`.
pub const EQUAL_KEY_TREE_CLEAR_INNER_ADDRESS: usize = 0x083b_efac;

/// ABI of the inner clear helper. It may overwrite `out` and reads the
/// pointees of `key` and `guard` as aligned target-width words.
pub type EqualKeyTreeClearInner = unsafe extern "C" fn(
    out: *mut u32,
    tree: *const EqualKeyTree,
    key: *const u32,
    guard: *const u32,
);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_equal_key_tree_clear_inner(
    out: *mut u32,
    tree: *const EqualKeyTree,
    key: *const u32,
    guard: *const u32,
) {
    let inner: EqualKeyTreeClearInner =
        core::mem::transmute(EQUAL_KEY_TREE_CLEAR_INNER_ADDRESS);
    inner(out, tree, key, guard);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_equal_key_tree_clear_inner(
    _out: *mut u32,
    _tree: *const EqualKeyTree,
    _key: *const u32,
    _guard: *const u32,
) {
    panic!("equal_key_tree_clear requires inner clear helper 0x083befac")
}

/// Boundary for the still-retail inner clear helper at 0x083befac.
///
/// Device builds default to the fixed load address; host tests replace
/// this mutable slot to observe the materialized `out`/`key`/`guard`
/// slots.
#[cfg(target_os = "none")]
pub static mut EQUAL_KEY_TREE_CLEAR_INNER: EqualKeyTreeClearInner =
    firmware_equal_key_tree_clear_inner;

#[cfg(not(target_os = "none"))]
pub static mut EQUAL_KEY_TREE_CLEAR_INNER: EqualKeyTreeClearInner =
    missing_equal_key_tree_clear_inner;

/// equal_key_tree_clear — original: `FUN_083dbdfc` @ `0x083dbdfc`
/// (56 bytes; 4 direct, unconditional `bl` call sites; one plain `bl`
/// inside the body).
///
/// Loads the tree's header/sentinel and its left link (leftmost node),
/// materializes `out = header`, `key = header->left`, `guard = header`
/// slots, and invokes the inner clear helper with pointers to them.
/// Returns nothing; the helper performs any destruction.
///
/// # Safety
///
/// `tree` must designate a readable [`EqualKeyTree`] whose header word
/// designates a node with a readable aligned word at +0x8, and the
/// installed inner helper must obey [`EqualKeyTreeClearInner`]. As in
/// the original, none of these pointers is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn equal_key_tree_clear(tree: *mut EqualKeyTree) {
    let header = addr_of!((*tree).header).read();
    let leftmost = (header as usize as *const u32).add(2).read();
    let mut out = header;
    let mut key = leftmost;
    let mut guard = header;
    let inner = core::ptr::read_volatile(addr_of!(EQUAL_KEY_TREE_CLEAR_INNER));
    inner(addr_of_mut!(out), tree, addr_of!(key), addr_of!(guard));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::{ptr, vec, vec::Vec};

    /// Slab layout: header node at +0 (its +0x8 word is the left link),
    /// the tree record at +0x20 (its +0x10 word is the header pointer).
    const FIXTURE_LEN: usize = 0x1000;
    const TREE_OFFSET: usize = 0x20;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::EQUAL_KEY_TREE_CLEAR, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(u32, u32, u32)> = Vec::new();

    unsafe extern "C" fn recording_inner(
        out: *mut u32,
        _tree: *const EqualKeyTree,
        key: *const u32,
        guard: *const u32,
    ) {
        (*ptr::addr_of_mut!(CALLS)).push((out.read(), key.read(), guard.read()));
        out.write(0xdead_beef);
    }

    struct SeamGuard;

    impl SeamGuard {
        unsafe fn install() -> Self {
            (*ptr::addr_of_mut!(CALLS)).clear();
            ptr::addr_of_mut!(EQUAL_KEY_TREE_CLEAR_INNER).write_volatile(recording_inner);
            Self
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(EQUAL_KEY_TREE_CLEAR_INNER)
                    .write_volatile(missing_equal_key_tree_clear_inner);
            }
        }
    }

    /// Header node followed by its left link at +0x8; the wrapper must
    /// pass exactly these values through the three slots.
    #[test]
    fn passes_header_and_leftmost_through_slots() {
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/equal_key_tree_clear"));
            return;
        };
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { SeamGuard::install() };
        unsafe {
            ((slab + 0x8) as *mut u32).write(0x1122_3344);
            ((slab + TREE_OFFSET + 0x10) as *mut u32).write(slab as u32);
            equal_key_tree_clear((slab + TREE_OFFSET) as *mut EqualKeyTree);
        }
        let calls = unsafe { (*ptr::addr_of!(CALLS)).clone() };
        assert_eq!(calls, std::vec![(slab as u32, 0x1122_3344, slab as u32)]);
    }

    /// The header's left link is read fresh per call: two trees with
    /// different leftmost values must each observe their own.
    #[test]
    fn reads_leftmost_fresh_per_tree() {
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/equal_key_tree_clear"));
            return;
        };
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { SeamGuard::install() };
        let tree_b = slab + 0x40;
        unsafe {
            ((slab + 0x8) as *mut u32).write(0xaaaa_0001);
            ((slab + TREE_OFFSET + 0x10) as *mut u32).write(slab as u32);
            equal_key_tree_clear((slab + TREE_OFFSET) as *mut EqualKeyTree);
            ((slab + 0x8) as *mut u32).write(0xbbbb_0002);
            ((tree_b + 0x10) as *mut u32).write(slab as u32);
            equal_key_tree_clear(tree_b as *mut EqualKeyTree);
        }
        let calls = unsafe { (*ptr::addr_of!(CALLS)).clone() };
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], (slab as u32, 0xaaaa_0001, slab as u32));
        assert_eq!(calls[1], (slab as u32, 0xbbbb_0002, slab as u32));
    }

    /// The original has no NULL guard on tree+0x10's pointee; a zero
    /// left link is a supported input and must pass through unchanged.
    #[test]
    fn tolerates_zero_left_link() {
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/equal_key_tree_clear"));
            return;
        };
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { SeamGuard::install() };
        unsafe {
            ((slab + 0x8) as *mut u32).write(0);
            ((slab + TREE_OFFSET + 0x10) as *mut u32).write(slab as u32);
            equal_key_tree_clear((slab + TREE_OFFSET) as *mut EqualKeyTree);
        }
        let calls = unsafe { (*ptr::addr_of!(CALLS)).clone() };
        assert_eq!(calls, std::vec![(slab as u32, 0, slab as u32)]);
    }
}
