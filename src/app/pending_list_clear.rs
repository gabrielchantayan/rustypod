//! Pending-list clear — retailOS `FUN_08295fdc` @ 0x08295fdc.
//! True extent: 52 bytes, through the pop at 0x0829600c; the next function
//! starts at 0x08296010. Raw A32 has zero plain outbound BL and one BLNE
//! (0x08295ff4 -> operator_delete @ 0x082aad24). Two inbound plain BL sites
//! are at 0x08295e08 and 0x08296310; there are no predicated inbound BLs.
//!
//! Drain the owner's head at +0x2ac, advancing it to node+8 before tag-2
//! deletion and reloading it after each deletion. Clear the tail at +0x2b0
//! even for an initially empty list. No node destructor is called.
//!
//! Deliberate deviations: repr(C) pointer fields widen on the host rather
//! than truncating fixture pointers; on ARM the offsets remain exact. The
//! redundant non-null predicate inside the already non-null loop is omitted.
//! Volatile owner accesses preserve the observable store/reload across free.

use core::ptr::{addr_of, addr_of_mut};

#[repr(C)]
pub struct PendingListNode {
    pub opaque: [u32; 2],
    pub next: *mut PendingListNode,
}

#[repr(C)]
pub struct PendingListOwner {
    pub opaque: [u32; 0x2ac / 4],
    pub head: *mut PendingListNode,
    pub tail: *mut PendingListNode,
}

/// # Safety
/// `owner` must be writable; its head must describe a finite chain of valid
/// tag-2 allocations. Nodes must remain readable until passed to delete.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pending_list_clear(owner: *mut PendingListOwner) {
    loop {
        let node = addr_of!((*owner).head).read_volatile();
        if node.is_null() {
            break;
        }
        let next = addr_of!((*node).next).read();
        addr_of_mut!((*owner).head).write_volatile(next);
        crate::heap::veneers::operator_delete(node.cast());
    }
    addr_of_mut!((*owner).tail).write_volatile(core::ptr::null_mut());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::{HEAP_OPS, tests::mock_heap};
    use crate::heap::types::HeapDescriptorDescriptor;
    use std::vec::Vec;

    static mut OWNER: *mut PendingListOwner = core::ptr::null_mut();
    static mut EVENTS: Vec<(usize, usize, usize, usize)> = Vec::new();

    unsafe extern "C" fn observe_free(
        _heap: *mut HeapDescriptorDescriptor, node: *mut u8, tag: usize,
    ) {
        let owner = addr_of!(OWNER).read();
        (*addr_of_mut!(EVENTS)).push((node as usize, (*owner).head as usize,
            (*owner).tail as usize, tag));
        // A deallocator may overwrite the node. The next link must already
        // have been consumed, not loaded after this call.
        (*(node as *mut PendingListNode)).next = core::ptr::null_mut();
    }

    #[test]
    fn drains_in_order_advancing_head_before_free_and_clearing_tail_last() {
        let _lock = mock_heap();
        unsafe {
            let saved = addr_of!(HEAP_OPS).read();
            (*addr_of_mut!(HEAP_OPS)).free = observe_free;
            for count in [0usize, 1, 3] {
                let mut nodes: Vec<PendingListNode> = (0..count).map(|_| PendingListNode {
                    opaque: [0x12345678, 0x87654321], next: core::ptr::null_mut(),
                }).collect();
                for i in 1..count {
                    nodes[i - 1].next = nodes.as_mut_ptr().add(i);
                }
                let tail = if count == 0 { 1usize as *mut PendingListNode }
                    else { nodes.as_mut_ptr().add(count - 1) };
                let mut owner = PendingListOwner {
                    opaque: [0xa5a5a5a5; 0x2ac / 4],
                    head: if count == 0 { core::ptr::null_mut() } else { nodes.as_mut_ptr() },
                    tail,
                };
                addr_of_mut!(OWNER).write(&mut owner);
                (*addr_of_mut!(EVENTS)).clear();
                pending_list_clear(&mut owner);
                let expected: Vec<_> = (0..count).map(|i| (
                    nodes.as_mut_ptr().add(i) as usize,
                    if i + 1 == count { 0 } else { nodes.as_mut_ptr().add(i + 1) as usize },
                    tail as usize, 2usize,
                )).collect();
                assert_eq!(*addr_of!(EVENTS), expected);
                assert!(owner.head.is_null());
                assert!(owner.tail.is_null());
                assert_eq!(owner.opaque, [0xa5a5a5a5; 0x2ac / 4]);
                pending_list_clear(&mut owner);
                assert_eq!(*addr_of!(EVENTS), expected);
            }
            addr_of_mut!(HEAP_OPS).write(saved);
            addr_of_mut!(OWNER).write(core::ptr::null_mut());
        }
    }
}
