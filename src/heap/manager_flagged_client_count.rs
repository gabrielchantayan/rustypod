//! Count manager clients with state flag 0x40000 set.
//!
//! `FUN_0818ae58` @ `0x0818ae58`: 104 bytes, true extent
//! `[0x0818ae58, 0x0818aec0)`, ending at the next independent push prologue.
//! Raw ARM words verify 3 outgoing plain BL instructions, no predicated BLs,
//! and 2 incoming plain BL sites. Ghidra's 56-byte extent truncates the loop;
//! its `FUN_0818ae90` is an interior instruction, not another function.
//! Walk the circular list at manager +0x28, resolve each node's handle at +8,
//! and increment a wrapping count when the client's +0x44 flags contain
//! 0x40000. Callers use the count to check their manager +0x1c0 counter.
//!
//! Deliberate deviations: inline the verified pointer inequality helper
//! 0x083d6f78; reuse the canonical handle accessor for its identical
//! 0x083d64f4 alias. Existing repr(C) list pointers widen on hosts while
//! retaining ARM field offsets. No locking or NULL-client fallback is added.

use crate::cxx::handle::handle_deref_or_null;
use crate::heap::manager_client_find::ManagerClientList;
use crate::util::state_flags::state_flags_contain;
use core::ptr::addr_of_mut;

/// # Safety
/// Manager and its sentinel-linked circular list must be readable. Every
/// non-sentinel node must resolve to a non-NULL client with an aligned,
/// readable u32 at +0x44. Caller must prevent concurrent list/handle mutation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn manager_flagged_client_count(manager: *mut ManagerClientList) -> u32 {
    let mut count = 0u32;
    let mut node = (*(*manager).sentinel).next;
    while node != (*manager).sentinel {
        let client = handle_deref_or_null(addr_of_mut!((*node).handle).cast());
        if state_flags_contain(client, 0x40000) != 0 {
            count = count.wrapping_add(1);
        }
        node = (*node).next;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::shared_cell::SharedCell;
    use crate::heap::manager_client_find::ManagerClientLink;
    use core::ptr::null_mut;

    fn link(handle: *mut SharedCell) -> ManagerClientLink {
        ManagerClientLink { next: null_mut(), previous: null_mut(), handle }
    }

    #[test]
    fn empty_list_does_not_resolve_sentinel_handle() {
        let mut sentinel = link(null_mut());
        sentinel.next = &mut sentinel;
        let mut manager = ManagerClientList { prefix: [0; 10], sentinel: &mut sentinel };
        unsafe { assert_eq!(manager_flagged_client_count(&mut manager), 0); }
    }

    #[test]
    fn counts_only_requested_bit_and_observes_updated_clients() {
        let flags = [0, 0x40000, 0x80000, u32::MAX, 0x3ffff, 0x40001];
        let mut clients = [[0u32; 18]; 6];
        for (client, flags) in clients.iter_mut().zip(flags) { client[17] = flags; }
        let mut cells = clients.each_mut().map(|client| SharedCell {
            value: client.as_mut_ptr() as usize, refcount: 7,
        });
        let mut nodes = cells.each_mut().map(|cell| link(cell));
        let mut sentinel = link(null_mut());
        sentinel.next = &mut nodes[0];
        for index in 0..nodes.len() - 1 { nodes[index].next = &mut nodes[index + 1]; }
        nodes[5].next = &mut sentinel;
        let mut manager = ManagerClientList { prefix: [0; 10], sentinel: &mut sentinel };
        unsafe { assert_eq!(manager_flagged_client_count(&mut manager), 3); }
        for client in &mut clients { client[17] = 0x40000; }
        unsafe { assert_eq!(manager_flagged_client_count(&mut manager), 6); }
        for client in &mut clients { client[17] = !0x40000; }
        unsafe { assert_eq!(manager_flagged_client_count(&mut manager), 0); }
        assert!(cells.iter().all(|cell| cell.refcount == 7));
    }
}
