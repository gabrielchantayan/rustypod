//! Submit a one-byte lingo-7 command-0x24 request.
//!
//! Original: `FUN_08194e78` @ **0x08194e78**, **128 bytes**, ending at
//! the independent push prologue at 0x08194ef8; no literals. Raw aligned
//! ARM word decoding verifies two incoming plain BLs (0x0825a3cc and
//! 0x0825a3ec), five internal plain BLs, and zero predicated BLs in either
//! count. Reject an unavailable active service with 11. Otherwise lock
//! context+0x2d8, create a one-byte packet from the low byte of the argument
//! for the target-width owner at +0x2d0, and schedule completion state 1
//! with delay 200 ms. Null packet returns 28; all creation paths unlock.
//!
//! Deviations: reuse canonical Rust callees instead of the mutex veneers;
//! ignore mutex statuses as retailOS does. The saved r1 stack word supplies
//! only its first (little-endian) byte, represented explicitly as u8 here.
//! The incidental third stacked argument to the six-argument packet factory
//! is not reproduced. Existing callee runtime seams retain their limitations.

use core::ptr;
use super::active_service_handler_readiness::active_service_handler_is_ready;
use super::iap_packet::iap_packet_create;
use super::iap_packet_event_schedule::schedule_iap_packet_event;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock};

/// # Safety
/// When the active service is ready, `context` must be word aligned and
/// contain a target-width owner at +0x2d0 and an initialized PosixMutex at
/// +0x2d8. Packet creation and event scheduling runtime preconditions apply.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_command_36_request(context: *mut u8, value: u32) -> u32 {
    if active_service_handler_is_ready() == 0 {
        return 11;
    }
    let mutex = context.add(0x2d8).cast();
    posix_mutex_lock(mutex);
    let payload = value as u8;
    let owner = ptr::read(context.cast::<u32>().add(0x2d0 / 4));
    let packet = iap_packet_create(
        owner as usize as *mut u8, ptr::null_mut(), 7, 0x24, &payload, 1,
    );
    let status = if packet.is_null() {
        28
    } else {
        schedule_iap_packet_event(context, packet, 1, 200)
    };
    posix_mutex_unlock(mutex);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::active_service_handler_readiness::replace_active_service_handler_context;
    use crate::testing::ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK;

    #[test]
    fn unavailable_context_rejects_without_touching_request_pointer() {
        let _guard = ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let previous = replace_active_service_handler_context(ptr::null_mut());
            for value in [0, 0xff, 0x100, u32::MAX] {
                assert_eq!(iap_command_36_request(ptr::null_mut(), value), 11);
            }
            replace_active_service_handler_context(previous);
        }
    }

    #[test]
    fn missing_owner_or_out_of_range_selector_rejects_before_request_access() {
        let _guard = ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut active = [0u32; 0x2d8 / 4];
        unsafe {
            let previous = replace_active_service_handler_context(active.as_mut_ptr().cast());
            for (owner, selector) in [(0, 0), (0, 2), (1, 3), (1, i32::MAX as u32)] {
                active[0x2d0 / 4] = owner;
                active[0x2d4 / 4] = selector;
                assert_eq!(iap_command_36_request(ptr::null_mut(), u32::MAX), 11);
            }
            replace_active_service_handler_context(previous);
        }
    }
}
