//! Submit an iAP packet through one of the two service-thread slots.
//!
//! `iap_service_packet_submit` — original: `FUN_08190aa8` @ **0x08190aa8**.
//! Raw `osos.dec` ARM words establish the complete **184-byte** extent:
//! 176 bytes of code through `pop {r1-r7,pc}` at 0x08190b5c, followed by the
//! two literal words 0x089ca8e6 and 0x089ca940; the next function opens at
//! 0x08190b68. The body has **7 plain unconditional `bl` calls** and **zero
//! predicated `bl` calls**. This corrects Ghidra's incomplete four-call count.
//!
//! Algorithm: only service indices zero and one are eligible. An enabled index
//! maps to owner mode one or two, creates a one-byte lingo-0 command-0x27
//! packet whose payload is the low byte of `payload_word`, polls that index in
//! the incoming-process thread, then waits for it after successful polling.
//! Invalid, disabled, or unmapped indices return status 11; allocation failure
//! returns 28.
//!
//! # Deliberate deviations
//!
//! The two literal-backed tables remain raw target-width tables. Host builds
//! mirror them with private fixtures so rejection-path tests never dereference
//! retailOS addresses. Packet completion remains behind the existing
//! `IAP_PACKET_EVENT_SCHEDULE_OPS` seam reached by the ported thread methods.

use core::ptr;

use super::iap_incoming_process_thread::{
    iap_incoming_process_thread_instance, iap_incoming_process_thread_slot_poll,
    iap_incoming_process_thread_slot_wait,
};
use super::iap_packet::{iap_packet_create, iap_packet_owner_mode_from_index};
use super::service_manager::{service_manager_instance_veneer, service_manager_secondary_handler_get};

const INVALID_SERVICE_STATUS: u32 = 11;
const PACKET_CREATE_FAILURE_STATUS: u32 = 28;
const SERVICE_SLOT_COUNT: u32 = 2;
const IAP_PACKET_COMMAND: u16 = 0x27;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn service_slot_enabled(index: usize) -> bool {
    (0x089c_a8e6usize as *const u8).add(index).read_volatile() == 0
}

#[cfg(not(target_os = "none"))]
static mut HOST_SERVICE_SLOT_FLAGS: [u8; SERVICE_SLOT_COUNT as usize] = [0; SERVICE_SLOT_COUNT as usize];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn service_slot_enabled(index: usize) -> bool {
    ptr::read_volatile(ptr::addr_of!(HOST_SERVICE_SLOT_FLAGS[index])) == 0
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn service_thread_slot(index: usize) -> u32 {
    (0x089c_a940usize as *const u32).add(index).read_volatile()
}

#[cfg(not(target_os = "none"))]
static mut HOST_SERVICE_THREAD_SLOTS: [u32; SERVICE_SLOT_COUNT as usize] = [0; SERVICE_SLOT_COUNT as usize];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn service_thread_slot(index: usize) -> u32 {
    ptr::read_volatile(ptr::addr_of!(HOST_SERVICE_THREAD_SLOTS[index]))
}

/// iap_service_packet_submit — original: `FUN_08190aa8` @ 0x08190aa8 (184
/// bytes including two literals; 7 plain `bl` calls and no predicated `bl`
/// calls).
///
/// # Safety
///
/// For enabled service indices, retailOS requires initialized service-manager
/// and incoming-process-thread singletons. `context` is preserved in the ABI
/// but unused by the raw body. The low byte of `payload_word` is copied into
/// the packet's one-byte payload.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iap_service_packet_submit")]
pub unsafe extern "C" fn iap_service_packet_submit(
    _context: *mut u8,
    service_index: u32,
    _unused: u32,
    payload_word: u32,
) -> u32 {
    if service_index >= SERVICE_SLOT_COUNT || !service_slot_enabled(service_index as usize) {
        return if service_index < SERVICE_SLOT_COUNT { 0 } else { INVALID_SERVICE_STATUS };
    }

    let owner_mode = iap_packet_owner_mode_from_index(service_index);
    if owner_mode == 0 {
        return INVALID_SERVICE_STATUS;
    }

    let service_manager = service_manager_instance_veneer();
    let owner = service_manager_secondary_handler_get(service_manager.add(4).cast(), owner_mode as i32);
    let mut payload = payload_word;
    let packet = iap_packet_create(
        owner,
        ptr::null_mut(),
        0,
        IAP_PACKET_COMMAND,
        (&mut payload as *mut u32).cast(),
        1,
    );
    if packet.is_null() {
        return PACKET_CREATE_FAILURE_STATUS;
    }

    let slot = service_thread_slot(service_index as usize);
    let thread = iap_incoming_process_thread_instance();
    let status = iap_incoming_process_thread_slot_poll(thread, slot);
    if status == 0 {
        iap_incoming_process_thread_slot_wait(iap_incoming_process_thread_instance(), slot)
    } else {
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn submit_rejects_indices_outside_the_two_literal_slots() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            assert_eq!(iap_service_packet_submit(ptr::null_mut(), 2, 0, 0xff), 11);
            assert_eq!(iap_service_packet_submit(ptr::null_mut(), u32::MAX, 0, 0xff), 11);
        }
    }

    #[test]
    fn submit_skips_disabled_slots_without_touching_singletons() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            HOST_SERVICE_SLOT_FLAGS = [1, 1];
            assert_eq!(iap_service_packet_submit(ptr::null_mut(), 0, 0, 0x1234), 0);
            assert_eq!(iap_service_packet_submit(ptr::null_mut(), 1, 0, 0x1234), 0);
            HOST_SERVICE_SLOT_FLAGS = [0, 0];
        }
    }
}
