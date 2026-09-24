//! Controller-state clear with fixed microsecond settling delay.
//!
//! Port: [`clear_controller_state_and_delay`] — original: `FUN_080bb648` @
//! `0x080bb648` (20 bytes, `0x080bb648..0x080bb65c`; the next real function
//! starts at `0x080bb65c`; **3 inbound plain `bl` call sites and zero
//! predicated `bl` call sites**). A separate tail-branch thunk at `0x0836e1e4`
//! also targets this body.
//!
//! Clears the word at the otherwise unidentified controller register
//! `0x38400e00`, then tail-calls the IRAM veneer at `0x08037ef0` with 800.
//! The veneer resolves to [`crate::drivers::timer::usec_delay`], so the fixed
//! settling interval is 800 microseconds.
//!
//! # Deliberate deviation
//!
//! Device builds perform the original volatile MMIO store. Host builds use an
//! atomic register model so the ordering and final value can be tested; the
//! delay still uses the shared deterministic Timer E seam.

use crate::drivers::timer::usec_delay;

const CONTROLLER_STATE_REGISTER: *mut u32 = 0x3840_0e00 as *mut u32;
const CONTROLLER_SETTLE_USEC: u32 = 800;

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(not(target_os = "none"))]
static HOST_CONTROLLER_STATE: AtomicU32 = AtomicU32::new(u32::MAX);

#[inline(always)]
unsafe fn clear_controller_state() {
    #[cfg(target_os = "none")]
    unsafe {
        core::ptr::write_volatile(CONTROLLER_STATE_REGISTER, 0);
    }

    #[cfg(not(target_os = "none"))]
    {
        HOST_CONTROLLER_STATE.store(0, Ordering::SeqCst);
    }
}

/// clear_controller_state_and_delay — original: `FUN_080bb648` @ 0x080bb648
/// (20 bytes; **3 inbound plain `bl` call sites, zero predicated forms**).
///
/// Clears the controller state word and waits exactly 800 microseconds through
/// the IRAM delay veneer. It has no parameters and returns the delay body's
/// zero status.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clear_controller_state_and_delay() -> u32 {
    unsafe { clear_controller_state() };
    unsafe { usec_delay(CONTROLLER_SETTLE_USEC) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{clear_controller_state_and_delay, HOST_CONTROLLER_STATE};
    use crate::drivers::timer::{configure_usec_timer_for_test, usec_timer_read};
    use core::sync::atomic::Ordering;

    #[test]
    fn clears_controller_state_before_the_full_800_usec_delay() {
        let _timer_guard = configure_usec_timer_for_test(u32::MAX - 100, 400);
        HOST_CONTROLLER_STATE.store(u32::MAX, Ordering::SeqCst);

        assert_eq!(unsafe { clear_controller_state_and_delay() }, 0);
        assert_eq!(HOST_CONTROLLER_STATE.load(Ordering::SeqCst), 0);
        // The delay sampled start at 0xffff_ff9b, then tested elapsed time at
        // +400 and +800; the next sample proves the full interval was passed.
        assert_eq!(unsafe { usec_timer_read() }, 1_099);
    }
}
