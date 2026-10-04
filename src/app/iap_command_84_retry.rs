//! Send iAP command 0x84 with a per-slot three-attempt budget.
//!
//! Original: `FUN_081f3334` @ 0x081f3334. True extent is 168 bytes
//! (0x081f3334..0x081f33dc): 156 bytes of code and three literal words.
//! Raw branch decoding verifies two inbound BL sites: one plain BL and one
//! BLNE. All six outbound BLs are unconditional. The next real entry at
//! 0x081f33dc starts with `push {r4-r9,lr}`.
//!
//! Resolve the secondary handler before checking the byte retry counter.
//! A NULL handler is fatal even when the budget is exhausted. At three or
//! more attempts return 11; otherwise increment before creating an empty
//! lingo-2 command-0x84 packet, complete it with state zero (ignoring status),
//! and schedule a wildcard-tag command-0x84 event after 300 ms. Allocation
//! failure is fatal; scheduling failure does not refund the attempt.
//!
//! Deviations: ported callees are called directly; the unported completion
//! uses the existing volatile IAP_PACKET_EVENT_SCHEDULE_OPS seam. Host-only
//! global fixtures replace the target literals. No protocol identity beyond
//! the verified lingo/command pair is assumed.

use core::ptr;
use super::iap_packet::iap_packet_create;
use super::iap_packet_event_schedule::IAP_PACKET_EVENT_SCHEDULE_OPS;
use super::pending_event_insert::pending_event_insert;
use super::service_manager::{service_manager_instance_veneer, service_manager_secondary_handler_get};
use crate::heap::veneers::heap_panic;

#[cfg(not(target_os = "none"))]
static mut HOST_RETRY_COUNTS: [u8; 3] = [0; 3];
#[cfg(not(target_os = "none"))]
static mut HOST_EVENT_CONTEXT: *mut u8 = ptr::null_mut();

#[inline(always)]
unsafe fn retry_counts() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x089c_cbbeusize as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_RETRY_COUNTS).cast() }
}

#[inline(always)]
unsafe fn event_context() -> *mut u8 {
    #[cfg(target_os = "none")]
    { ptr::read_volatile(0x089c_cbccusize as *const *mut u8) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(HOST_EVENT_CONTEXT)) }
}

#[inline(always)]
unsafe fn claim_attempt(count: *mut u8) -> bool {
    let attempts = ptr::read_volatile(count);
    if attempts >= 3 {
        return false;
    }
    ptr::write_volatile(count, attempts + 1);
    true
}

/// Original: 0x081f3334; 168 bytes; one BL and one BLNE inbound.
///
/// # Safety
/// The manager must be initialized and `slot` must select valid manager and
/// retry-table storage. The event context and its queue must be initialized
/// when the attempt is accepted. Negative slots remain unchecked, as in ARM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_command_84_retry(slot: i32) -> u32 {
    let manager = service_manager_instance_veneer();
    let owner = service_manager_secondary_handler_get(manager.add(4).cast(), slot);
    if owner.is_null() {
        heap_panic();
    }
    if !claim_attempt(retry_counts().offset(slot as isize)) {
        return 11;
    }
    let packet = iap_packet_create(owner, ptr::null_mut(), 2, 0x84, ptr::null(), 0);
    if packet.is_null() {
        heap_panic();
    }
    let ops = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
    (ops.complete_packet)(packet, 0);
    pending_event_insert(event_context(), slot as u32, 0xffff, 0x84, 0, 300)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::service_manager::{SERVICE_MANAGER_INSTANCE, SERVICE_MANAGER_INSTANCE_TEST_LOCK};

    #[test]
    fn attempt_budget_saturates_without_wrapping_or_touching_neighbors() {
        for initial in 0u8..=255 {
            let mut counts = [0xa5, initial, 0x5a];
            let accepted = unsafe { claim_attempt(counts.as_mut_ptr().add(1)) };
            assert_eq!(accepted, initial < 3);
            assert_eq!(counts, [0xa5, if initial < 3 { initial + 1 } else { initial }, 0x5a]);
        }
        let mut count = 0;
        unsafe {
            assert!(claim_attempt(&mut count));
            assert!(claim_attempt(&mut count));
            assert!(claim_attempt(&mut count));
            assert!(!claim_attempt(&mut count));
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn exhausted_slots_return_busy_and_preserve_all_counters() {
        let _lock = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock();
        unsafe {
            let old_manager = SERVICE_MANAGER_INSTANCE;
            let old_counts = HOST_RETRY_COUNTS;
            let mut manager = [0u32; 25];
            for slot in 0..3 { manager[3 + slot * 8] = 0x1234; }
            SERVICE_MANAGER_INSTANCE = manager.as_mut_ptr().cast();
            HOST_RETRY_COUNTS = [3, 4, 255];
            for slot in 0..3 { assert_eq!(iap_command_84_retry(slot), 11); }
            assert_eq!(ptr::read(ptr::addr_of!(HOST_RETRY_COUNTS)), [3, 4, 255]);
            HOST_RETRY_COUNTS = old_counts;
            SERVICE_MANAGER_INSTANCE = old_manager;
        }
    }
}
