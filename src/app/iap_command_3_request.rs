//! Request a lingo-8 command-3 index with a four-attempt retry ceiling.
//!
//! Original: FUN_081e2f38 @ 0x081e2f38; true size 168 bytes through
//! 0x081e2fe0 (160 code bytes and two literals). The next entry starts
//! `mov r0,#1; strb r0,[r1]`. Raw decoding finds four plain outbound BLs
//! and no predicated outbound BLs. Two inbound plain BLs, no predicated BLs.
//!
//! Return 11 for a missing owner, retry count above three, or an unready
//! service. Compare the low byte of the index against the global count;
//! return 9 when out of range. Create a one-byte lingo-8 command-3 packet,
//! returning 28 on allocation failure. Save the index at global +2 before
//! completing the packet with state zero and a 3000 ms event delay.
//! Deviations: existing Rust callees replace firmware BLs; host builds use
//! a private fixture for the literal-backed global. The completion callee's
//! unused fourth argument is explicitly zero rather than residual r3.

use core::ptr;
use super::iap_packet::iap_packet_create;
use super::iap_packet_completion_schedule::complete_iap_packet_and_schedule_event;
use super::service_handler_availability::service_handler_state_is_ready;
use super::service_manager::service_manager_instance_veneer;

#[cfg(not(target_os = "none"))]
static mut HOST_INDEX_STATE: [u8; 4] = [0; 4];

#[inline(always)]
unsafe fn index_state() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x089c_ca14usize as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_INDEX_STATE).cast() }
}

/// Original: 0x081e2f38; 168 bytes; four plain outbound BLs.
///
/// # Safety
/// `context` must contain readable target-width fields through +0x2e1.
/// Its selector must identify a valid lifecycle record. Accepted requests
/// require initialized packet allocation and completion/event state.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_command_3_request(context: *mut u8, index: u32) -> u32 {
    let owner = ptr::read_volatile(context.cast::<u32>().add(0x2d4 / 4));
    if owner == 0 || ptr::read_volatile(context.add(0x2e1)) > 3 {
        return 11;
    }
    let manager = service_manager_instance_veneer();
    let selector = ptr::read_volatile(context.cast::<i32>().add(0x2d0 / 4));
    if service_handler_state_is_ready(manager, selector) == 0 {
        return 11;
    }
    let mut payload = index as u8;
    let state = index_state();
    if payload >= ptr::read_volatile(state) {
        return 9;
    }
    let owner = ptr::read_volatile(context.cast::<u32>().add(0x2d4 / 4));
    let packet = iap_packet_create(owner as usize as *mut u8, ptr::null_mut(), 8, 3, &mut payload, 1);
    if packet.is_null() {
        return 28;
    }
    ptr::write_volatile(state.add(2), payload);
    complete_iap_packet_and_schedule_event(packet, 0, 3000, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::service_handler_availability::{replace_service_handler_lifecycle_state, SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK};
    use super::super::service_manager::{SERVICE_MANAGER_INSTANCE, SERVICE_MANAGER_INSTANCE_TEST_LOCK};

    #[test]
    fn rejection_precedence_and_low_byte_boundary() {
        let _manager = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock();
        let _lifecycle = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap();
        unsafe {
            let saved = ptr::read(ptr::addr_of!(HOST_INDEX_STATE));
            let old_manager = SERVICE_MANAGER_INSTANCE;
            let mut manager = [0u32; 25];
            SERVICE_MANAGER_INSTANCE = manager.as_mut_ptr().cast();
            let old = replace_service_handler_lifecycle_state(0, 4);
            let mut context = [0u32; 0x300 / 4];
            let bytes = context.as_mut_ptr().cast::<u8>();
            HOST_INDEX_STATE = [7, 0xa5, 0x5a, 0xff];
            // Missing owner wins even for an invalid selector and index.
            context[0x2d0 / 4] = 99;
            assert_eq!(iap_command_3_request(bytes, 0xff), 11);
            context[0x2d4 / 4] = 1;
            for attempts in 4..=255 {
                bytes.add(0x2e1).write(attempts);
                assert_eq!(iap_command_3_request(bytes, 0xff), 11);
            }
            context[0x2d0 / 4] = 0;
            for attempts in 0..=3 {
                bytes.add(0x2e1).write(attempts);
                for index in [7, 255, 0x107, 0xffff_ffff] {
                    assert_eq!(iap_command_3_request(bytes, index), 9);
                }
            }
            replace_service_handler_lifecycle_state(0, 3);
            assert_eq!(iap_command_3_request(bytes, 0), 11);
            replace_service_handler_lifecycle_state(0, 4);
            HOST_INDEX_STATE[0] = 0;
            assert_eq!(iap_command_3_request(bytes, 0x100), 9);
            assert_eq!(ptr::read(ptr::addr_of!(HOST_INDEX_STATE)), [0, 0xa5, 0x5a, 0xff]);
            replace_service_handler_lifecycle_state(0, old);
            HOST_INDEX_STATE = saved;
            SERVICE_MANAGER_INSTANCE = old_manager;
        }
    }
}
