//! Find a manager client by its first-word registration key.
//!
//! `FUN_0818aec0` @ `0x0818aec0`: 180 bytes, true extent
//! `[0x0818aec0, 0x0818af74)`; next function is an independent mutex thunk.
//! Raw-word scan verifies 2 incoming plain BL sites (0x0818a664, 0x0818a9d8),
//! 6 outgoing plain BL instructions, and zero predicated BL instructions.
//! Walk the circular list rooted at manager +0x28, resolving each node's
//! shared-cell handle at +8 and comparing the payload's first word to the key.
//! Assign the first match to output and return 1; on exhaustion assign an empty
//! temporary handle and return 0. No mutex is taken here: callers own locking.
//!
//! Deliberate deviations: inline the verified pointer inequality helper
//! 0x083d6f78; typed repr(C) pointers widen on hosts but retain target offsets.
//! Return only r0, not Ghidra's spurious concatenated r1/r0 return value.

use crate::cxx::handle::handle_deref_or_null;
use crate::cxx::shared_cell::{
    SharedCell, shared_cell_assign_direct_secondary,
    shared_cell_construct_tertiary, shared_cell_release_direct_secondary,
};
use core::ptr::{addr_of_mut, null_mut};

#[repr(C)]
pub struct ManagerClientList {
    pub prefix: [u32; 10],
    pub sentinel: *mut ManagerClientLink,
}

#[repr(C)]
pub struct ManagerClientLink {
    pub next: *mut ManagerClientLink,
    pub previous: *mut ManagerClientLink,
    pub handle: *mut SharedCell,
}

#[cfg(target_os = "none")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(ManagerClientList, sentinel)];
#[cfg(target_os = "none")]
const _: [u8; 8] = [0; core::mem::offset_of!(ManagerClientLink, handle)];

/// # Safety
/// Manager and circular links must be valid. Each non-sentinel link must have
/// a non-NULL cell and payload readable for its first u32. Output must satisfy
/// shared_cell_assign_direct_secondary's release preconditions. The caller
/// must prevent concurrent list/handle mutation throughout the search.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn manager_client_find(
    manager: *mut ManagerClientList,
    key: u32,
    output: *mut *mut SharedCell,
) -> u32 {
    let mut node = (*(*manager).sentinel).next;
    while node != (*manager).sentinel {
        let client = handle_deref_or_null(addr_of_mut!((*node).handle).cast());
        if client.cast::<u32>().read() == key {
            break;
        }
        node = (*node).next;
    }
    if node != (*manager).sentinel {
        shared_cell_assign_direct_secondary(output, addr_of_mut!((*node).handle));
        1
    } else {
        let mut empty = null_mut();
        shared_cell_construct_tertiary(&mut empty, null_mut());
        shared_cell_assign_direct_secondary(output, &mut empty);
        shared_cell_release_direct_secondary(&mut empty);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(handle: *mut SharedCell) -> ManagerClientLink {
        ManagerClientLink { next: null_mut(), previous: null_mut(), handle }
    }

    #[test]
    fn empty_list_clears_output_and_releases_one_reference() {
        let mut sentinel = link(null_mut());
        sentinel.next = &mut sentinel;
        let mut manager = ManagerClientList { prefix: [0; 10], sentinel: &mut sentinel };
        let mut old = SharedCell { value: 0, refcount: 3 };
        let mut output = &mut old as *mut SharedCell;
        unsafe { assert_eq!(manager_client_find(&mut manager, u32::MAX, &mut output), 0) };
        assert!(output.is_null());
        assert_eq!(old.refcount, 2);
        assert!(sentinel.handle.is_null());
    }

    #[test]
    fn finds_first_duplicate_and_late_match_then_clears_on_miss() {
        let mut keys = [0u32, u32::MAX, 0];
        let mut cells = keys.each_mut().map(|key| SharedCell {
            value: key as *mut u32 as usize, refcount: 2,
        });
        let mut nodes = cells.each_mut().map(|cell| link(cell));
        let mut sentinel = link(null_mut());
        sentinel.next = &mut nodes[0];
        nodes[0].next = &mut nodes[1];
        nodes[1].next = &mut nodes[2];
        nodes[2].next = &mut sentinel;
        let mut manager = ManagerClientList { prefix: [0; 10], sentinel: &mut sentinel };
        let mut output = null_mut();
        unsafe {
            assert_eq!(manager_client_find(&mut manager, 0, &mut output), 1);
            assert_eq!(output, &mut cells[0] as *mut SharedCell);
            assert_eq!(cells[0].refcount, 3);
            assert_eq!(cells[2].refcount, 2, "first duplicate wins");
            assert_eq!(manager_client_find(&mut manager, u32::MAX, &mut output), 1);
            assert_eq!(output, &mut cells[1] as *mut SharedCell);
            assert_eq!(cells[0].refcount, 2);
            assert_eq!(cells[1].refcount, 3);
            assert_eq!(manager_client_find(&mut manager, 17, &mut output), 0);
        }
        assert!(output.is_null());
        assert_eq!(cells.map(|cell| cell.refcount), [2, 2, 2]);
    }

    #[test]
    fn output_aliasing_matching_node_does_not_release_or_retain() {
        let mut key = 42u32;
        let mut cell = SharedCell { value: &mut key as *mut u32 as usize, refcount: 1 };
        let mut node = link(&mut cell);
        let mut sentinel = link(null_mut());
        sentinel.next = &mut node;
        node.next = &mut sentinel;
        let mut manager = ManagerClientList { prefix: [0; 10], sentinel: &mut sentinel };
        unsafe { assert_eq!(manager_client_find(&mut manager, 42, &mut node.handle), 1) };
        assert_eq!(node.handle, &mut cell as *mut SharedCell);
        assert_eq!(cell.refcount, 1);
    }
}
