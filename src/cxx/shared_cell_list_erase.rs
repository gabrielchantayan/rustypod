//! Shared-cell list erase — retailOS `FUN_083dd260` @ load address
//! `0x083dd260`, 132 bytes (33 A32 words), ending at `0x083dd2e0`;
//! the next real function begins at `0x083dd2e4`. Verified raw-code calls:
//! one plain BL to `shared_cell_release_direct_secondary` @ `0x083b52f4`,
//! zero predicated BLs; one incoming plain BL at `0x0818b018`.
//!
//! A sentinel iterator returns the sentinel without mutation. Otherwise save
//! the successor, unlink the node in both directions, wrapping-decrement the
//! length, release its shared-cell handle, and push the node onto the pool's
//! free chain. Reload the iterator after release, as the firmware does, and
//! write the saved successor only after recycling. Deliberate deviations:
//! repr(C) pointer fields widen on hosts; ARM offsets remain unchanged.

use super::shared_cell::{SharedCell, shared_cell_release_direct_secondary};

#[repr(C)]
pub struct SharedCellListNode {
    pub next: *mut SharedCellListNode,
    pub previous: *mut SharedCellListNode,
    pub cell: *mut SharedCell,
}

#[repr(C)]
pub struct SharedCellList {
    pub chunks: *mut u8,
    pub free: *mut SharedCellListNode,
    pub next_unused: *mut SharedCellListNode,
    pub end: *mut SharedCellListNode,
    pub sentinel: *mut SharedCellListNode,
    pub length: u32,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::size_of::<SharedCellListNode>() == 12);
    assert!(core::mem::offset_of!(SharedCellListNode, cell) == 8);
    assert!(core::mem::offset_of!(SharedCellList, sentinel) == 16);
    assert!(core::mem::offset_of!(SharedCellList, length) == 20);
};

/// `out` and `iterator` are writable node-pointer slots; `list` and its live
/// links must be valid. A non-sentinel node's cell must satisfy the release
/// routine's contract. The caller supplies synchronization. Slots may alias.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_cell_list_erase(
    out: *mut *mut SharedCellListNode,
    list: *mut SharedCellList,
    iterator: *mut *mut SharedCellListNode,
) {
    let node = iterator.read();
    let successor = if node == (*list).sentinel {
        (*list).sentinel
    } else {
        let successor = (*node).next;
        (*(*node).previous).next = (*node).next;
        let node = iterator.read();
        (*(*node).next).previous = (*node).previous;
        (*list).length = (*list).length.wrapping_sub(1);
        shared_cell_release_direct_secondary(core::ptr::addr_of_mut!((*iterator.read()).cell));
        let node = iterator.read();
        (*node).next = (*list).free;
        (*list).free = node;
        successor
    };
    out.write(successor);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    fn node() -> SharedCellListNode {
        SharedCellListNode { next: null_mut(), previous: null_mut(), cell: null_mut() }
    }

    #[test]
    fn sentinel_does_not_touch_links_cell_or_count() {
        let mut sentinel = node();
        let mut cell = SharedCell { value: 0, refcount: 2 };
        sentinel.cell = &mut cell;
        let mut list = SharedCellList { chunks: null_mut(), free: null_mut(), next_unused: null_mut(), end: null_mut(), sentinel: &mut sentinel, length: 9 };
        let mut iterator = &mut sentinel as *mut _;
        let mut out = null_mut();
        unsafe { shared_cell_list_erase(&mut out, &mut list, &mut iterator); }
        assert_eq!(out, list.sentinel);
        assert_eq!(iterator, list.sentinel);
        assert_eq!(list.length, 9);
        assert!(list.free.is_null());
        assert!(sentinel.next.is_null() && sentinel.previous.is_null());
        assert_eq!(sentinel.cell, &mut cell as *mut _);
        assert_eq!(cell.refcount, 2);
    }

    #[test]
    fn unlink_release_recycle_and_return_successor() {
        for (single, count, refs) in [(false, 3u32, 2i32), (true, 1, 3), (true, 0, i32::MIN)] {
            let mut sentinel = node();
            let mut removed = node();
            let mut following = node();
            let mut free = node();
            let mut cell = SharedCell { value: 0, refcount: refs };
            let sentinel_ptr = &mut sentinel as *mut _;
            let removed_ptr = &mut removed as *mut _;
            let successor = if single { sentinel_ptr } else { &mut following as *mut _ };
            sentinel.next = removed_ptr;
            sentinel.previous = if single { removed_ptr } else { successor };
            removed.next = successor;
            removed.previous = sentinel_ptr;
            removed.cell = &mut cell;
            following.next = sentinel_ptr;
            following.previous = removed_ptr;
            let mut list = SharedCellList { chunks: null_mut(), free: &mut free, next_unused: null_mut(), end: null_mut(), sentinel: sentinel_ptr, length: count };
            let mut iterator = removed_ptr;
            let mut out = null_mut();
            unsafe { shared_cell_list_erase(&mut out, &mut list, &mut iterator); }
            assert_eq!(out, successor);
            assert_eq!(iterator, removed_ptr);
            assert_eq!(sentinel.next, successor);
            assert_eq!(unsafe { (*successor).previous }, sentinel_ptr);
            assert_eq!(list.length, count.wrapping_sub(1));
            assert_eq!(cell.refcount, refs.wrapping_sub(1));
            assert!(removed.cell.is_null());
            assert_eq!(list.free, removed_ptr);
            assert_eq!(removed.next, &mut free as *mut _);
            assert_eq!(removed.previous, sentinel_ptr);
        }
    }

    #[test]
    fn null_handle_and_in_place_iterator_output() {
        let mut sentinel = node();
        let mut removed = node();
        let sentinel_ptr = &mut sentinel as *mut _;
        let removed_ptr = &mut removed as *mut _;
        sentinel.next = removed_ptr;
        sentinel.previous = removed_ptr;
        removed.next = sentinel_ptr;
        removed.previous = sentinel_ptr;
        let mut list = SharedCellList { chunks: null_mut(), free: null_mut(), next_unused: null_mut(), end: null_mut(), sentinel: sentinel_ptr, length: 1 };
        let mut iterator = removed_ptr;
        let slot = &mut iterator as *mut _;
        unsafe { shared_cell_list_erase(slot, &mut list, slot); }
        assert_eq!(iterator, sentinel_ptr);
        assert_eq!(sentinel.next, sentinel_ptr);
        assert_eq!(sentinel.previous, sentinel_ptr);
        assert_eq!(list.free, removed_ptr);
        assert!(removed.next.is_null() && removed.cell.is_null());
        assert_eq!(list.length, 0);
    }
}
