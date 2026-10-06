//! Submit a lingo-7 command-0x20 flag word.
//!
//! Original: `FUN_08195000` @ **0x08195000**. True extent is **152 bytes**:
//! 148 code bytes through the pop at 0x08195090, then mask 0x0feafee0 at
//! 0x08195094; the next function starts at 0x08195098. Raw word decoding
//! finds **2 incoming plain BLs, 0 predicated BLs**, and **6 internal plain
//! BLs, 0 predicated BLs**.
//!
//! Reject unless the active service is ready and no forbidden flag is set.
//! Lock context+0x2d8, pack the flags big-endian, create a four-byte lingo-7
//! command-0x20 packet for the handler word at +0x2d0, then schedule it with
//! completion state 1 and delay 200 ms. Return 11 on rejection, 28 on packet
//! creation failure, otherwise the scheduler status; always unlock after
//! packet creation. Mutex statuses are deliberately ignored, as in retailOS.
//!
//! Deviations: call the existing canonical ports directly, bypassing the two
//! mutex veneers. Return only r0's status: the raw pop restores incoming r1,
//! not a second result as Ghidra's undefined8 signature implies.

use core::ptr;
use super::active_service_handler_readiness::active_service_handler_is_ready;
use super::iap_packet::iap_packet_create;
use super::iap_packet_event_schedule::schedule_iap_packet_event;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock};
use crate::util::beload::pack_be32;

const FORBIDDEN_FLAGS: u32 = 0x0fea_fee0;

/// # Safety
/// A passing readiness/flag gate requires a valid context with a target-width
/// handler word at +0x2d0 and an initialized PosixMutex at +0x2d8, plus the
/// runtime prerequisites of packet creation and event scheduling.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_command_32_request(context: *mut u8, flags: u32) -> u32 {
    if active_service_handler_is_ready() == 0 || flags & FORBIDDEN_FLAGS != 0 {
        return 11;
    }
    let mutex = context.add(0x2d8).cast();
    posix_mutex_lock(mutex);
    let mut payload = 0u32;
    pack_be32((&mut payload as *mut u32).cast(), flags);
    let owner = ptr::read(context.cast::<u32>().add(0x2d0 / 4));
    let packet = iap_packet_create(
        owner as usize as *mut u8, ptr::null_mut(), 7, 0x20,
        (&payload as *const u32).cast(), 4,
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
    use super::super::service_handler_availability::{
        replace_service_handler_lifecycle_state, SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK,
    };
    use crate::testing::ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK;

    #[test]
    fn unavailable_service_rejects_even_valid_flags_without_dereferencing_context() {
        let _guard = ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let previous = replace_active_service_handler_context(ptr::null_mut());
            for flags in [0, 0x4000_0010, !FORBIDDEN_FLAGS, u32::MAX] {
                assert_eq!(iap_command_32_request(ptr::null_mut(), flags), 11);
            }
            replace_active_service_handler_context(previous);
        }
    }

    #[test]
    fn ready_service_rejects_every_forbidden_bit_before_touching_request_context() {
        let _guard = ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut active = [0u32; 0x2d8 / 4];
        active[0x2d0 / 4] = 1;
        let mut manager = [0u32; 1];
        unsafe {
            let slot = ptr::addr_of_mut!(super::super::service_manager::SERVICE_MANAGER_INSTANCE);
            let previous_manager = slot.read();
            slot.write(manager.as_mut_ptr().cast());
            let previous = replace_active_service_handler_context(active.as_mut_ptr().cast());
            let previous_state = replace_service_handler_lifecycle_state(0, 4);
            assert_eq!(active_service_handler_is_ready(), 1);
            for bit in 0..32 {
                let flag = 1u32 << bit;
                if flag & FORBIDDEN_FLAGS != 0 {
                    assert_eq!(iap_command_32_request(ptr::null_mut(), flag), 11);
                    assert_eq!(iap_command_32_request(ptr::null_mut(), flag | !FORBIDDEN_FLAGS), 11);
                }
            }
            replace_service_handler_lifecycle_state(0, previous_state);
            replace_active_service_handler_context(previous);
            slot.write(previous_manager);
        }
    }
}
