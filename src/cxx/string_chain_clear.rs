//! Drain a chain of owned string nodes.
//!
//! `string_chain_clear` — retailOS `FUN_081ee900` @ **0x081ee900**.
//! True extent: 60 bytes, [0x081ee900, 0x081ee93c); the next function
//! begins with an independent push. Raw A32 decoding verifies two outbound
//! plain BLs (string_object_destroy @ 0x08277484, operator_delete @
//! 0x082aad24), zero predicated BLs, and two inbound plain BLs at
//! 0x081ef450 and 0x083d5418, zero predicated inbound BLs.
//!
//! Save head->next in the owner's scratch pointer, destroy the head's leading
//! StringObject, delete the destructor's returned pointer, then advance head
//! from scratch. Repeat until empty and return the owner. An initially empty
//! chain leaves scratch untouched; a drained chain leaves both pointers NULL.
//! Deliberate deviations: repr(C) pointers widen on host; host-only lifecycle
//! seams permit testing destruction that invalidates the node. The redundant
//! BEQ at 0x081ee914 is omitted: it uses the same nonzero-head comparison that
//! entered the loop, with no intervening flag-setting instruction.

use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::heap::veneers::operator_delete;

/// Target node prefix: string at +0, opaque word at +8, successor at +12.
#[repr(C)]
pub struct StringChainNode {
    pub string: StringObject,
    pub opaque: u32,
    pub next: *mut StringChainNode,
}

/// Target owner prefix: head at +0 and saved successor at +4.
#[repr(C)]
pub struct StringChain {
    pub head: *mut StringChainNode,
    pub scratch: *mut StringChainNode,
}

#[cfg(not(target_os = "none"))]
pub static mut STRING_CHAIN_CLEAR_OPS: (
    unsafe extern "C" fn(*mut StringObject) -> *mut StringObject,
    unsafe extern "C" fn(*mut u8),
) = (string_object_destroy, operator_delete);

/// Destroy and free every node without freeing the owner.
///
/// # Safety
/// `owner` must be writable and its head must describe an acyclic chain of
/// uniquely owned nodes valid for StringObject destruction and tag-2 deletion.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_chain_clear(owner: *mut StringChain) -> *mut StringChain {
    while !(*owner).head.is_null() {
        let node = (*owner).head;
        (*owner).scratch = (*node).next;
        #[cfg(target_os = "none")]
        let destroyed = string_object_destroy(core::ptr::addr_of_mut!((*node).string));
        #[cfg(not(target_os = "none"))]
        let destroyed = {
            let (destroy, _) = core::ptr::read_volatile(core::ptr::addr_of!(STRING_CHAIN_CLEAR_OPS));
            destroy(core::ptr::addr_of_mut!((*node).string))
        };
        #[cfg(target_os = "none")]
        operator_delete(destroyed.cast());
        #[cfg(not(target_os = "none"))]
        {
            let (_, delete) = core::ptr::read_volatile(core::ptr::addr_of!(STRING_CHAIN_CLEAR_OPS));
            delete(destroyed.cast());
        }
        (*owner).head = (*owner).scratch;
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut OWNER: *mut StringChain = null_mut();
    static mut DESTROYED: [*mut StringChainNode; 3] = [null_mut(); 3];
    static mut COUNT: usize = 0;
    static mut AWAITING_DELETE: bool = false;
    static mut RETURN_TOKEN: u32 = 0;

    unsafe extern "C" fn destroy(string: *mut StringObject) -> *mut StringObject {
        assert!(!AWAITING_DELETE);
        let node = string.cast::<StringChainNode>();
        assert_eq!((*OWNER).head, node);
        assert_eq!((*OWNER).scratch, (*node).next);
        DESTROYED[COUNT] = node;
        // Destruction may invalidate the successor stored in the node.
        (*node).next = null_mut();
        AWAITING_DELETE = true;
        core::ptr::addr_of_mut!(RETURN_TOKEN).cast()
    }

    unsafe extern "C" fn delete(pointer: *mut u8) {
        assert!(AWAITING_DELETE);
        assert_eq!(pointer, core::ptr::addr_of_mut!(RETURN_TOKEN).cast());
        assert_eq!((*OWNER).head, DESTROYED[COUNT]);
        AWAITING_DELETE = false;
        COUNT += 1;
    }

    #[test]
    fn drains_saved_successors_in_order_and_preserves_empty_scratch() {
        let _guard = LOCK.lock();
        unsafe {
            let previous = STRING_CHAIN_CLEAR_OPS;
            STRING_CHAIN_CLEAR_OPS = (destroy, delete);
            for length in 0usize..=3 {
                let mut nodes: [StringChainNode; 3] = core::array::from_fn(|_| StringChainNode {
                    string: StringObject { vtable: core::ptr::null(), payload: null_mut() },
                    opaque: 0x12345678,
                    next: null_mut(),
                });
                let base = nodes.as_mut_ptr();
                for index in 0..length.saturating_sub(1) {
                    (*base.add(index)).next = base.add(index + 1);
                }
                let mut owner = StringChain {
                    head: if length == 0 { null_mut() } else { base },
                    scratch: base,
                };
                OWNER = &mut owner;
                COUNT = 0;
                AWAITING_DELETE = false;
                assert_eq!(string_chain_clear(&mut owner), core::ptr::addr_of_mut!(owner));
                assert!(owner.head.is_null());
                assert_eq!(owner.scratch, if length == 0 { base } else { null_mut() });
                assert_eq!(COUNT, length);
                for index in 0..length {
                    assert_eq!(DESTROYED[index], base.add(index));
                    assert_eq!(nodes[index].opaque, 0x12345678);
                }
                // Repeated clearing must not touch scratch or run destruction.
                owner.scratch = base;
                string_chain_clear(&mut owner);
                assert_eq!(owner.scratch, base);
                assert_eq!(COUNT, length);
            }
            STRING_CHAIN_CLEAR_OPS = previous;
        }
    }
}

