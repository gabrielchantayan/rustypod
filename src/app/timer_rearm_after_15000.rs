//! Timer re-arm wrapper from one unidentified application object.
//!
//! `timer_rearm_after_15000` — original: `FUN_0814b490` @ `0x0814b490`
//! (32 bytes, `0x0814b490..0x0814b4b0`). Raw A32 decoding establishes three
//! direct callers (3 unconditional `bl`, 0 predicated `bl`), one outgoing
//! unconditional `bl` to `timer_start_after`, and a final tail `b` to
//! `timer_restart`.
//!
//! # Algorithm
//!
//! The object embeds a timer at +0x54. Start that timer after 15,000 ms, then
//! restart it. Rust represents the final tail branch as a normal call; both
//! callees are already ported direct calls, so no new seam is needed.

use crate::drivers::timer::{timer_restart, timer_start_after};

const TIMER_OFFSET: usize = 0x54;
const REARM_DELAY_MS: u32 = 15_000;

type TimerStartAfter = unsafe extern "C" fn(timer: *mut u8, delay: u32);
type TimerRestart = unsafe extern "C" fn(timer: *mut u8);

#[inline(always)]
unsafe fn timer_rearm_after_15000_with(
    object: *mut u8,
    start_after: TimerStartAfter,
    restart: TimerRestart,
) {
    let timer = unsafe { object.add(TIMER_OFFSET) };
    unsafe { start_after(timer, REARM_DELAY_MS) };
    unsafe { restart(timer) };
}

/// Re-arms the embedded +0x54 timer after fifteen seconds.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_rearm_after_15000(object: *mut u8) {
    unsafe { timer_rearm_after_15000_with(object, timer_start_after, timer_restart) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(usize, u32); 2] = [(0, 0); 2];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_start_after(timer: *mut u8, delay: u32) {
        unsafe { CALLS[CALL_COUNT] = (timer as usize, delay); CALL_COUNT += 1 };
    }

    unsafe extern "C" fn record_restart(timer: *mut u8) {
        unsafe { CALLS[CALL_COUNT] = (timer as usize, 0); CALL_COUNT += 1 };
    }

    #[test]
    fn reprograms_and_restarts_the_embedded_timer_in_order() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut object = [0u8; TIMER_OFFSET + 4];
        unsafe {
            CALL_COUNT = 0;
            timer_rearm_after_15000_with(
                object.as_mut_ptr(),
                record_start_after,
                record_restart,
            );
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS[0], (object.as_mut_ptr().add(TIMER_OFFSET) as usize, REARM_DELAY_MS));
            assert_eq!(CALLS[1], (object.as_mut_ptr().add(TIMER_OFFSET) as usize, 0));
        }
    }
}
