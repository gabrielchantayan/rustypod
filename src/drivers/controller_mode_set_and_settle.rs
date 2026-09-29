//! Controller-mode selection with controller-state settling delay.
//!
//! Port: [`controller_mode_set_and_settle`] — original: `FUN_0836e118` @
//! `0x0836e118` (76 bytes, `0x0836e118..0x0836e164`; the next real function
//! starts at `0x0836e164`; **2 plain `bl` instructions and zero predicated
//! `bl` instructions**, verified from `osos.dec`).
//!
//! The function clears controller state and waits 800 microseconds. Mode zero
//! selects timer value `0x400`; modes one and two respectively clear and set
//! bit 2 of the controller control word, then select timer value zero. Other
//! modes leave both words untouched. Every path sets controller state to one
//! and waits 10 microseconds before returning.
//!
//! # Deliberate deviation
//!
//! Device builds use volatile MMIO accesses. Host builds model the two local
//! controller words atomically because their physical addresses are unmapped;
//! the existing deterministic Timer E seam supplies both delays.

use crate::drivers::clear_controller_state_and_delay::{clear_controller_state_and_delay, controller_state_write};
use crate::drivers::timer::usec_delay;

const CONTROLLER_TIMER_CONFIG: *mut u32 = 0x3c40_0018 as *mut u32;
const CONTROLLER_CONTROL: *mut u32 = 0x3c40_0030 as *mut u32;
const CONTROLLER_CONTROL_MODE_BIT: u32 = 4;
const FINAL_SETTLE_USEC: u32 = 10;

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(not(target_os = "none"))]
static HOST_CONTROLLER_TIMER_CONFIG: AtomicU32 = AtomicU32::new(0);
#[cfg(not(target_os = "none"))]
static HOST_CONTROLLER_CONTROL: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
unsafe fn controller_timer_config_write(value: u32) {
    #[cfg(target_os = "none")]
    unsafe {
        core::ptr::write_volatile(CONTROLLER_TIMER_CONFIG, value);
    }

    #[cfg(not(target_os = "none"))]
    {
        HOST_CONTROLLER_TIMER_CONFIG.store(value, Ordering::SeqCst);
    }
}

#[inline(always)]
unsafe fn controller_control_read() -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        return core::ptr::read_volatile(CONTROLLER_CONTROL);
    }

    #[cfg(not(target_os = "none"))]
    {
        HOST_CONTROLLER_CONTROL.load(Ordering::SeqCst)
    }
}

#[inline(always)]
unsafe fn controller_control_write(value: u32) {
    #[cfg(target_os = "none")]
    unsafe {
        core::ptr::write_volatile(CONTROLLER_CONTROL, value);
    }

    #[cfg(not(target_os = "none"))]
    {
        HOST_CONTROLLER_CONTROL.store(value, Ordering::SeqCst);
    }
}

/// controller_mode_set_and_settle — original: `FUN_0836e118` @ 0x0836e118
/// (76 bytes; **2 plain `bl` instructions, zero predicated `bl` instructions**).
///
/// Selects the controller timer mode, applies the matching control-bit change,
/// then leaves controller state asserted after the stock 800- and 10-microsecond
/// settling delays. Modes other than zero, one, and two intentionally skip the
/// timer and control updates.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_mode_set_and_settle(mode: u32) -> u32 {
    unsafe { clear_controller_state_and_delay() };

    match mode {
        0 => unsafe { controller_timer_config_write(0x400) },
        1 => {
            unsafe { controller_control_write(controller_control_read() & !CONTROLLER_CONTROL_MODE_BIT) };
            unsafe { controller_timer_config_write(0) };
        }
        2 => {
            unsafe { controller_control_write(controller_control_read() | CONTROLLER_CONTROL_MODE_BIT) };
            unsafe { controller_timer_config_write(0) };
        }
        _ => {}
    }

    unsafe { controller_state_write(1) };
    unsafe { usec_delay(FINAL_SETTLE_USEC) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::clear_controller_state_and_delay::controller_state_for_test;
    use crate::drivers::timer::{configure_usec_timer_for_test, usec_timer_read};

    fn reset_registers(control: u32, timer_config: u32) {
        HOST_CONTROLLER_CONTROL.store(control, Ordering::SeqCst);
        HOST_CONTROLLER_TIMER_CONFIG.store(timer_config, Ordering::SeqCst);
    }

    #[test]
    fn mode_zero_selects_0x400_without_touching_control() {
        let _timer_guard = configure_usec_timer_for_test(0, 400);
        reset_registers(0xa5a5_0015, u32::MAX);

        assert_eq!(unsafe { controller_mode_set_and_settle(0) }, 0);
        assert_eq!(HOST_CONTROLLER_CONTROL.load(Ordering::SeqCst), 0xa5a5_0015);
        assert_eq!(HOST_CONTROLLER_TIMER_CONFIG.load(Ordering::SeqCst), 0x400);
        assert_eq!(controller_state_for_test(), 1);
        assert_eq!(unsafe { usec_timer_read() }, 2_000);
    }

    #[test]
    fn modes_one_and_two_change_only_controller_control_bit_two() {
        let _timer_guard = configure_usec_timer_for_test(0, 400);
        reset_registers(0xffff_ffff, 0x1234);
        assert_eq!(unsafe { controller_mode_set_and_settle(1) }, 0);
        assert_eq!(HOST_CONTROLLER_CONTROL.load(Ordering::SeqCst), 0xffff_fffb);
        assert_eq!(HOST_CONTROLLER_TIMER_CONFIG.load(Ordering::SeqCst), 0);

        reset_registers(0xffff_fffb, 0x1234);
        assert_eq!(unsafe { controller_mode_set_and_settle(2) }, 0);
        assert_eq!(HOST_CONTROLLER_CONTROL.load(Ordering::SeqCst), 0xffff_ffff);
        assert_eq!(HOST_CONTROLLER_TIMER_CONFIG.load(Ordering::SeqCst), 0);
        assert_eq!(controller_state_for_test(), 1);
    }

    #[test]
    fn unsupported_mode_preserves_timer_and_control_words() {
        let _timer_guard = configure_usec_timer_for_test(0, 400);
        reset_registers(0xfeed_beef, 0xcafe_babe);

        assert_eq!(unsafe { controller_mode_set_and_settle(3) }, 0);
        assert_eq!(HOST_CONTROLLER_CONTROL.load(Ordering::SeqCst), 0xfeed_beef);
        assert_eq!(HOST_CONTROLLER_TIMER_CONFIG.load(Ordering::SeqCst), 0xcafe_babe);
        assert_eq!(controller_state_for_test(), 1);
    }
}
