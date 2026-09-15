//! Global pending-timer cleanup.
//!
//! The state block lives at `0x089d05c4`; raw `osos.dec` identifies its timer
//! handle at `+0x10` and its shutdown-request flag at `+0x14`.

use crate::heap::timer_free_gateway::iram_timer_free_veneer;
use crate::kernel::gateway_service19::gateway_service19_request;
use crate::kernel::task_lock::rom_svc_220041cc;

#[repr(C)]
struct GlobalTimerState {
    _reserved: [u32; 4],
    pending_timer: u32,
    shutdown_requested: u32,
}

#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_TIMER_STATE: GlobalTimerState = GlobalTimerState {
    _reserved: [0; 4],
    pending_timer: 0,
    shutdown_requested: 0,
};

unsafe fn global_timer_state() -> *mut GlobalTimerState {
    #[cfg(target_os = "none")]
    {
        0x089d_05c4 as *mut GlobalTimerState
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_GLOBAL_TIMER_STATE)
    }
}

/// global_timer_cleanup — original: `FUN_082d9634` @ `0x082d9634` (72 bytes,
/// including the `0x089d05c4` literal at `0x082d9678`; Ghidra reports the
/// 68-byte instruction span only).
///
/// Raw ARM words establish the true boundary: `pop {r4, pc}` is at
/// `0x082d9674`, its literal follows at `0x082d9678`, and the next function
/// starts at `0x082d967c`. There are five direct callers: four unconditional
/// `bl` and one predicated `blne`. The routine optionally sets the global
/// shutdown flag, signals kernel object `0x40`, then, when a pending timer
/// handle exists, posts its service-19 request, frees it through the RTXC
/// timer-free veneer, clears the handle, and returns zero.
///
/// Deliberate deviation: the foreign ROM veneers are represented by their
/// existing Rust seams; host builds use private backing storage for the fixed
/// retailOS state address.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_timer_cleanup(request_shutdown: u32) -> u32 {
    let state = global_timer_state();
    if request_shutdown != 0 {
        (*state).shutdown_requested = 1;
    }
    rom_svc_220041cc(0x40);
    let timer = (*state).pending_timer;
    if timer != 0 {
        gateway_service19_request(timer);
        iram_timer_free_veneer(timer as usize as *mut u8);
        (*state).pending_timer = 0;
    }
    0
}
#[cfg(test)]
unsafe fn cleanup_global_timer(
    state: *mut GlobalTimerState,
    request_shutdown: u32,
    signal_object: unsafe extern "C" fn(usize) -> usize,
    request_service19: unsafe extern "C" fn(u32) -> u32,
    free_timer: unsafe extern "C" fn(*mut u8),
) -> u32 {
    if request_shutdown != 0 {
        (*state).shutdown_requested = 1;
    }
    signal_object(0x40);
    let timer = (*state).pending_timer;
    if timer != 0 {
        request_service19(timer);
        free_timer(timer as usize as *mut u8);
        (*state).pending_timer = 0;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut SIGNALS: [usize; 2] = [0; 2];
    static mut SIGNAL_COUNT: usize = 0;
    static mut SERVICE_INPUT: u32 = 0;
    static mut FREE_TIMER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_signal(object: usize) -> usize {
        SIGNALS[SIGNAL_COUNT] = object;
        SIGNAL_COUNT += 1;
        0
    }

    unsafe extern "C" fn record_service19(timer: u32) -> u32 {
        SERVICE_INPUT = timer;
        0
    }

    unsafe extern "C" fn record_free(timer: *mut u8) {
        FREE_TIMER = timer;
    }

    unsafe fn reset() {
        SIGNALS = [0; 2];
        SIGNAL_COUNT = 0;
        SERVICE_INPUT = 0;
        FREE_TIMER = core::ptr::null_mut();
    }

    #[test]
    fn empty_timer_still_signals_and_only_nonzero_request_sets_shutdown() {
        unsafe {
            let mut state = GlobalTimerState {
                _reserved: [0; 4],
                pending_timer: 0,
                shutdown_requested: 0,
            };
            reset();
            assert_eq!(cleanup_global_timer(&mut state, 0, record_signal, record_service19, record_free), 0);
            assert_eq!(state.shutdown_requested, 0);
            assert_eq!(SIGNAL_COUNT, 1);
            assert_eq!(SIGNALS[0], 0x40);
            assert_eq!(SERVICE_INPUT, 0);
            assert!(FREE_TIMER.is_null());

            assert_eq!(cleanup_global_timer(&mut state, 7, record_signal, record_service19, record_free), 0);
            assert_eq!(state.shutdown_requested, 1);
            assert_eq!(SIGNAL_COUNT, 2);
            assert_eq!(SIGNALS[1], 0x40);
        }
    }

    #[test]
    fn pending_timer_is_requested_freed_and_cleared_in_order() {
        unsafe {
            let mut state = GlobalTimerState {
                _reserved: [0; 4],
                pending_timer: 0x1234_5678,
                shutdown_requested: 9,
            };
            reset();
            cleanup_global_timer(&mut state, 0, record_signal, record_service19, record_free);
            assert_eq!(state.shutdown_requested, 9);
            assert_eq!(state.pending_timer, 0);
            assert_eq!(SIGNAL_COUNT, 1);
            assert_eq!(SIGNALS[0], 0x40);
            assert_eq!(SERVICE_INPUT, 0x1234_5678);
            assert_eq!(FREE_TIMER as usize as u32, 0x1234_5678);
        }
    }
}
