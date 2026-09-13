//! `service_handler_slot_state_reset` — original: `FUN_0818eef8` @
//! **0x0818eef8** (64 bytes: 60 instruction bytes plus the three 4-byte
//! literal-pool words at 0x0818ef38..0x0818ef40; 0x0818ef44 begins the next
//! distinct function). Decoding every ARM `B`/`BL` immediate in `osos.dec`
//! finds **six direct, unconditional `bl` call sites**: 0x0818ed24,
//! 0x0818f204, 0x0818f318, 0x08191254, 0x08192cf0, and 0x08193dc4.
//!
//! Resets the selected service-handler slot's two one-byte flags and its
//! 20-byte state record. The record is initialized with state 15, timeout 100,
//! its selector word, and zeroed event and pending-mask words. `context` is
//! retained in the ABI but the decoded ARM body does not read `r0`.
//!
//! # Deliberate deviations
//!
//! Host builds use isolated backing tables instead of the retail fixed RAM
//! addresses. The retail body performs no selector bounds check; this port
//! retains that precondition and uses wrapping pointer arithmetic accordingly.

use core::ptr;

const SERVICE_HANDLER_SLOT_COUNT: usize = 3;
const SLOT_ACTIVITY_FLAGS_ADDRESS: usize = 0x089c_a8f0;
const SLOT_STATE_TABLE_ADDRESS: usize = 0x08a2_58f8;
const SLOT_PENDING_FLAGS_ADDRESS: usize = 0x089c_a8f3;
const RESET_STATE: u8 = 15;
const RESET_TIMEOUT: u32 = 100;

/// Observed 20-byte entry in the service-handler slot state table.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ServiceHandlerSlotState {
    state: u8,
    _padding_01: [u8; 3],
    timeout: u32,
    selector: u32,
    event_state: u32,
    pending_mask: u32,
}

const EMPTY_SLOT_STATE: ServiceHandlerSlotState = ServiceHandlerSlotState {
    state: 0,
    _padding_01: [0; 3],
    timeout: 0,
    selector: 0,
    event_state: 0,
    pending_mask: 0,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn slot_activity_flags() -> *mut u8 {
    SLOT_ACTIVITY_FLAGS_ADDRESS as *mut u8
}

#[cfg(not(target_os = "none"))]
static mut HOST_SLOT_ACTIVITY_FLAGS: [u8; SERVICE_HANDLER_SLOT_COUNT] = [0; SERVICE_HANDLER_SLOT_COUNT];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn slot_activity_flags() -> *mut u8 {
    ptr::addr_of_mut!(HOST_SLOT_ACTIVITY_FLAGS).cast()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn slot_states() -> *mut ServiceHandlerSlotState {
    SLOT_STATE_TABLE_ADDRESS as *mut ServiceHandlerSlotState
}

#[cfg(not(target_os = "none"))]
static mut HOST_SLOT_STATES: [ServiceHandlerSlotState; SERVICE_HANDLER_SLOT_COUNT] =
    [EMPTY_SLOT_STATE; SERVICE_HANDLER_SLOT_COUNT];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn slot_states() -> *mut ServiceHandlerSlotState {
    ptr::addr_of_mut!(HOST_SLOT_STATES).cast()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn slot_pending_flags() -> *mut u8 {
    SLOT_PENDING_FLAGS_ADDRESS as *mut u8
}

#[cfg(not(target_os = "none"))]
static mut HOST_SLOT_PENDING_FLAGS: [u8; SERVICE_HANDLER_SLOT_COUNT] = [0; SERVICE_HANDLER_SLOT_COUNT];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn slot_pending_flags() -> *mut u8 {
    ptr::addr_of_mut!(HOST_SLOT_PENDING_FLAGS).cast()
}

/// Resets the selected service-handler slot state to its initial values.
///
/// # Safety
///
/// `selector` must name a valid service-handler slot. The retail routine
/// performs no bounds validation before indexing its fixed global tables.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_slot_state_reset(_context: *mut u8, selector: u32) {
    let slot = selector as usize;
    unsafe { ptr::write_volatile(slot_activity_flags().wrapping_add(slot), 0) };

    let state = unsafe { slot_states().wrapping_add(slot) };
    unsafe { ptr::write_volatile(ptr::addr_of_mut!((*state).state), RESET_STATE) };
    unsafe { ptr::write_volatile(ptr::addr_of_mut!((*state).selector), selector) };
    unsafe { ptr::write_volatile(ptr::addr_of_mut!((*state).event_state), 0) };
    unsafe { ptr::write_volatile(ptr::addr_of_mut!((*state).timeout), RESET_TIMEOUT) };
    unsafe { ptr::write_volatile(ptr::addr_of_mut!((*state).pending_mask), 0) };

    unsafe { ptr::write_volatile(slot_pending_flags().wrapping_add(slot), 0) };
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) static SERVICE_HANDLER_SLOT_STATE_RESET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FILLED_SLOT_STATE: ServiceHandlerSlotState = ServiceHandlerSlotState {
        state: 0xa5,
        _padding_01: [0x5a; 3],
        timeout: 0x1122_3344,
        selector: 0x5566_7788,
        event_state: 0x99aa_bbcc,
        pending_mask: 0xddee_ff00,
    };

    unsafe fn fill_host_tables() {
        HOST_SLOT_ACTIVITY_FLAGS = [0xaa; SERVICE_HANDLER_SLOT_COUNT];
        HOST_SLOT_STATES = [FILLED_SLOT_STATE; SERVICE_HANDLER_SLOT_COUNT];
        HOST_SLOT_PENDING_FLAGS = [0x55; SERVICE_HANDLER_SLOT_COUNT];
    }

    #[test]
    fn resets_only_selected_slot_and_preserves_record_layout() {
        let _guard = SERVICE_HANDLER_SLOT_STATE_RESET_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            fill_host_tables();
            service_handler_slot_state_reset(ptr::null_mut(), 1);

            assert_eq!(HOST_SLOT_ACTIVITY_FLAGS, [0xaa, 0, 0xaa]);
            assert_eq!(HOST_SLOT_PENDING_FLAGS, [0x55, 0, 0x55]);
            assert_eq!(HOST_SLOT_STATES[0], FILLED_SLOT_STATE);
            assert_eq!(HOST_SLOT_STATES[1], ServiceHandlerSlotState {
                state: RESET_STATE,
                _padding_01: [0x5a; 3],
                timeout: RESET_TIMEOUT,
                selector: 1,
                event_state: 0,
                pending_mask: 0,
            });
            assert_eq!(HOST_SLOT_STATES[2], FILLED_SLOT_STATE);
        }
    }

    #[test]
    fn resets_each_valid_selector_to_its_own_selector_word() {
        let _guard = SERVICE_HANDLER_SLOT_STATE_RESET_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            fill_host_tables();
            for selector in 0..SERVICE_HANDLER_SLOT_COUNT as u32 {
                service_handler_slot_state_reset(ptr::null_mut(), selector);
            }

            for selector in 0..SERVICE_HANDLER_SLOT_COUNT {
                assert_eq!(HOST_SLOT_STATES[selector].state, RESET_STATE);
                assert_eq!(HOST_SLOT_STATES[selector].timeout, RESET_TIMEOUT);
                assert_eq!(HOST_SLOT_STATES[selector].selector, selector as u32);
                assert_eq!(HOST_SLOT_STATES[selector].event_state, 0);
                assert_eq!(HOST_SLOT_STATES[selector].pending_mask, 0);
            }
            assert_eq!(HOST_SLOT_ACTIVITY_FLAGS, [0; SERVICE_HANDLER_SLOT_COUNT]);
            assert_eq!(HOST_SLOT_PENDING_FLAGS, [0; SERVICE_HANDLER_SLOT_COUNT]);
        }
    }
}
