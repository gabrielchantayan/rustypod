//! Masked service-handler transfer eligibility.
//!
//! `service_handler_mask_can_transfer` — `FUN_0818fa2c` @ **0x0818fa2c**,
//! 172 bytes, ending at the next function's push at 0x0818fad8. Whole-image
//! A32 decoding verifies two inbound plain BLs (0x0819106c, 0x0819292c),
//! zero predicated inbound BLs; five outbound plain BLs, zero predicated BLs,
//! and one indirect BLX through the handler vtable's +0x10 word.
//!
//! Ignore context; reject requested groups >=3 with the original signed
//! comparison. Scan mask bits 0..12. Group zero or the requested group needs
//! no query. For other groups, reload the manager, require a non-NULL handler,
//! and return zero if its +0x10 query returns unsigned 0 or 1. Return one
//! after all selected slots pass. Bits above 12 are ignored. The query's
//! concrete state names are unknown; no stronger meaning is assumed.
//!
//! Deviations: host vtable entries use native function-pointer width (the
//! handler's vtable address remains a u32). The target reads precisely word
//! four. Uses the existing singleton port, whose publication requirement is
//! documented in service_manager; fatal heap_panic paths are not host-tested.

use core::ptr;
use super::service_manager::{service_manager_instance_veneer, service_manager_handler_group_for_slot, service_manager_slot_handler_get};
use crate::heap::veneers::heap_panic;

type HandlerTransferQuery = unsafe extern "C" fn(*mut u8) -> u32;

#[inline(always)]
unsafe fn handler_transfer_query(handler: *mut u8) -> u32 {
    let vtable = ptr::read(handler.cast::<u32>()) as usize;
    #[cfg(target_os = "none")]
    let query: HandlerTransferQuery = core::mem::transmute(ptr::read((vtable as *const u32).add(4)) as usize);
    #[cfg(not(target_os = "none"))]
    let query = ptr::read((vtable as *const HandlerTransferQuery).add(4));
    query(handler)
}

/// Returns whether every selected handler can transfer to `requested_group`.
///
/// # Safety
/// The published manager must contain a valid 0xc8-byte slot table at +4.
/// Cross-group selected slots must contain valid handlers and callable vtable
/// +0x10 queries. Host tables use native-width function pointers instead.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_mask_can_transfer(
    _context: *mut u8,
    requested_group: i32,
    mask: u32,
) -> u32 {
    if requested_group >= 3 {
        heap_panic();
    }
    for slot in 0..13 {
        if mask & (1u32 << slot) == 0 {
            continue;
        }
        let manager = service_manager_instance_veneer();
        let group = service_manager_handler_group_for_slot(manager.add(4).cast(), slot);
        if (group as i32) >= 3 {
            heap_panic();
        }
        if group == 0 || group as i32 == requested_group {
            continue;
        }
        let manager = service_manager_instance_veneer();
        let handler = service_manager_slot_handler_get(manager.add(4).cast(), slot);
        if handler.is_null() {
            heap_panic();
        }
        if handler_transfer_query(handler) <= 1 {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::service_manager::{SERVICE_MANAGER_INSTANCE, SERVICE_MANAGER_INSTANCE_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    unsafe extern "C" fn query(handler: *mut u8) -> u32 {
        let words = handler.cast::<u32>();
        words.add(2).write(words.add(2).read() + 1);
        words.add(1).read()
    }

    #[test]
    fn ownership_query_boundaries_and_short_circuit() {
        let _lock = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SERVICE_HANDLER_MASK_CAN_TRANSFER, 4096) else {
            note_missing_u32_fixture("service_handler_mask_can_transfer");
            return;
        };
        unsafe {
            let previous = SERVICE_MANAGER_INSTANCE;
            SERVICE_MANAGER_INSTANCE = slab;
            let table = slab.add(4).cast::<u32>();
            let vtable = slab.add(0x200).cast::<HandlerTransferQuery>();
            for i in 0..5 { vtable.add(i).write(query); }
            for slot in 0..13 {
                let handler = slab.add(0x300 + slot * 16).cast::<u32>();
                handler.write(vtable as usize as u32);
                handler.add(1).write(2);
                table.add(25 + slot * 2).write(handler as usize as u32);
            }
            // No selected low bits must not touch even an absent singleton.
            SERVICE_MANAGER_INSTANCE = ptr::null_mut();
            assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), -1, 0xffff_e000), 1);
            SERVICE_MANAGER_INSTANCE = slab;
            // Group zero passes without querying even when its state is zero.
            let first = slab.add(0x300).cast::<u32>();
            first.add(1).write(0);
            assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), 2, 1), 1);
            assert_eq!(first.add(2).read(), 0);
            // Group one owns slots 0 and 12; same-group requests bypass queries.
            table.add(8).write(1 | (1 << 12));
            assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), 1, 1 | (1 << 12)), 1);
            assert_eq!(first.add(2).read(), 0);
            for state in [0, 1, 2, u32::MAX] {
                first.add(1).write(state);
                assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), -1, 1), u32::from(state > 1));
            }
            let last = slab.add(0x300 + 12 * 16).cast::<u32>();
            first.add(1).write(1);
            last.add(1).write(0);
            assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), 2, 1 | (1 << 12)), 0);
            assert_eq!(last.add(2).read(), 0, "first conflict stops the scan");
            first.add(1).write(2);
            assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), 2, 1 | (1 << 12)), 0);
            last.add(1).write(2);
            assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), 2, 1 | (1 << 12)), 1);
            // Group two is likewise a conflict for group one, not for itself.
            table.add(8).write(0);
            table.add(16).write(1 << 12);
            last.add(1).write(1);
            assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), 1, 1 << 12), 0);
            assert_eq!(service_handler_mask_can_transfer(ptr::null_mut(), 2, 1 << 12), 1);
            SERVICE_MANAGER_INSTANCE = previous;
        }
    }
}
