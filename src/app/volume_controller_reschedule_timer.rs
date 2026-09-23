//! `volume_controller_reschedule_timer` — original: `FUN_081f7a20` @ **0x081f7a20**.
//!
//! Raw `osos.dec` establishes the true **40-byte** extent
//! `0x081f7a20..0x081f7a48`: ten instructions ending in a tail `b` to
//! `timer_restart`, followed by the `10000` literal at `0x081f7a48`; the next
//! function starts at `0x081f7a4c`. Whole-image A32 decoding finds **0 plain
//! `bl` callers and 3 predicated `bl` callers** (`blne` at `0x081f78d8` and
//! `0x081f7a18`, `bleq` at `0x081f9094`).
//!
//! # Algorithm
//!
//! The volume controller holds its timer as a target-width pointer at `+0xc0`.
//! Stop it, program a 10-second delay, then tail-dispatch to `timer_restart`.
//! The nested timer calls deliberately produce four trace/assert calls before
//! the final arm.
//!
//! # Deliberate deviations
//!
//! Rust expresses the stock tail branch as an ordinary call. The final helper
//! returns `void`, so its residual ARM register value is not observable.

use crate::drivers::timer::{timer_restart, timer_start_after, timer_stop};

const TIMER: usize = 0xc0;
const RESCHEDULE_DELAY_MS: u32 = 10_000;

/// Stops, delays, and restarts the timer embedded by pointer in `controller`.
///
/// # Safety
/// `controller + 0xc0` must hold a valid 32-bit target pointer to a timer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_controller_reschedule_timer(controller: *mut u8) {
    let timer = controller.add(TIMER).cast::<u32>().read_volatile() as usize as *mut u8;
    timer_stop(timer);
    timer_start_after(timer, RESCHEDULE_DELAY_MS);
    timer_restart(timer);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use core::ptr;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static TRACE_CALLS: AtomicU32 = AtomicU32::new(0);
    static ARM_CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST_TIMER: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn trace(timer: *mut u8) {
        LAST_TIMER.store(timer as usize, Ordering::Relaxed);
        TRACE_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    unsafe extern "C" fn arm(timer: *mut u8) {
        LAST_TIMER.store(timer as usize, Ordering::Relaxed);
        ARM_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    struct OpsRestore(TimerOps);
    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }

    #[test]
    fn programs_ten_second_delay_then_restarts_target_width_timer() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = try_map_u32_slab(hints::VOLUME_CONTROLLER_RESCHEDULE_TIMER, 0x300) else {
            assert!(note_missing_u32_fixture("app/volume_controller_reschedule_timer"));
            return;
        };
        unsafe {
            let controller = base;
            let timer = base.add(0x200);
            controller.add(TIMER).cast::<u32>().write_volatile(timer as usize as u32);
            TRACE_CALLS.store(0, Ordering::Relaxed);
            ARM_CALLS.store(0, Ordering::Relaxed);
            LAST_TIMER.store(0, Ordering::Relaxed);
            let saved = ptr::addr_of!(TIMER_OPS).read_volatile();
            let mut operations = saved;
            operations.trace_assert = trace;
            operations.arm_timer = arm;
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(operations);
            let _restore = OpsRestore(saved);

            volume_controller_reschedule_timer(controller);

            assert_eq!(timer.add(4).cast::<u32>().read_volatile(), RESCHEDULE_DELAY_MS);
            assert_eq!(timer.add(0x20).cast::<u32>().read_volatile(), TIMER_STATE_RUNNING);
            assert_eq!(TRACE_CALLS.load(Ordering::Relaxed), 4);
            assert_eq!(ARM_CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(LAST_TIMER.load(Ordering::Relaxed), timer as usize);
        }
    }
}
