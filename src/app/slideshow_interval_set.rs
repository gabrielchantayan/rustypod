//! Set the slideshow interval — `FUN_081ccaf4` @ `0x081ccaf4`.
//! True extent: 132 bytes, ending at `0x081ccb78` (next push {r4,lr}).
//! Raw A32 scan: two inbound plain BL sites (0x0810cb44, 0x0810d2a8),
//! six outbound plain BL instructions, and zero predicated BL instructions.
//!
//! Store the millisecond interval at +0x8cc, lazily allocate/construct a
//! 44-byte timer at +0x8dc (returning on allocation failure), or stop the
//! existing timer. Notify the rounded seconds via slideshow_delay_set using
//! signed truncation of wrapping (interval + 500) / 1000. Positive intervals
//! reprogram the timer to 1000 ms and restart it; zero/negative ones leave it
//! stopped. Ghidra incorrectly absorbs the tail-called timer_restart body.
//!
//! Deliberate deviations: the final tail branch is expressed as a Rust call;
//! existing heap/timer dispatch seams are reused, with no new callee seams.
//! Target pointer fields remain u32 on hosts. ARM's assembly-only notification
//! export is declared here; host builds call its existing Rust implementation.

use crate::drivers::timer::{timer_restart, timer_schedule_shim, timer_start_after, timer_stop};
use crate::heap::veneers::operator_new;
use crate::runtime::rt_div::__rt_sdiv;
#[cfg(not(target_arch = "arm"))]
use crate::app::slideshow_delay_set::slideshow_delay_set;

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn slideshow_delay_set(state: *mut u8, delay: u32);
}

/// # Safety
/// `state` is four-byte aligned and writable through +0x8df; a nonzero timer
/// word points to a valid 44-byte timer. Existing heap/timer dispatch must be
/// installed, and the state must support the delay notification vtable slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slideshow_interval_set(state: *mut u8, interval_ms: i32) {
    unsafe {
        state.add(0x8cc).cast::<i32>().write(interval_ms);
        let timer_slot = state.add(0x8dc).cast::<u32>();
        let timer = timer_slot.read() as usize as *mut u8;
        if timer.is_null() {
            let allocated = operator_new(0x2c);
            timer_slot.write(allocated as usize as u32);
            if allocated.is_null() {
                return;
            }
            timer_schedule_shim(state as usize as u32, allocated, 0, 0);
        } else {
            timer_stop(timer);
        }
        let seconds = __rt_sdiv(interval_ms.wrapping_add(500), 1000);
        slideshow_delay_set(state, seconds as u32);
        if interval_ms > 0 {
            timer_start_after(timer_slot.read() as usize as *mut u8, 1000);
            timer_restart(timer_slot.read() as usize as *mut u8);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::LazyLock;

    static SLAB: LazyLock<usize> = LazyLock::new(|| {
        try_map_u32_slab(hints::SLIDESHOW_INTERVAL_SET, 0x2000)
            .expect("slideshow interval target-width fixture") as usize
    });

    struct Restore(TimerOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }
    unsafe extern "C" fn trace(_: *mut u8) {}
    unsafe extern "C" fn arm(_: *mut u8) {}

    #[test]
    fn signed_rounding_and_enable_boundary_preserve_timer_period_when_disabled() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = addr_of!(TIMER_OPS).read_volatile();
            let _restore = Restore(saved);
            let mut ops = saved;
            let _message_lock = crate::app::slideshow_delay_set::TEST_LOCK
                .lock().unwrap_or_else(|e| e.into_inner());
            ops.trace_assert = trace;
            ops.arm_timer = arm;
            addr_of_mut!(TIMER_OPS).write_volatile(ops);
            let state = *SLAB as *mut u8;
            let timer = state.add(0x1000);
            for (interval, seconds) in [
                (i32::MIN, -2147483), (-1501, -1), (-1500, -1),
                (-1499, 0), (-1, 0), (0, 0), (1, 0), (499, 0),
                (500, 1), (1499, 1), (1500, 2), (i32::MAX, -2147483),
            ] {
                state.write_bytes(0, 0x2000);
                state.add(0x8dc).cast::<u32>().write(timer as usize as u32);
                timer.cast::<u32>().add(1).write(77);
                timer.cast::<u32>().add(8).write(TIMER_STATE_RUNNING);
                slideshow_interval_set(state, interval);
                assert_eq!(state.add(0x8cc).cast::<i32>().read(), interval);
                assert_eq!(state.add(0x8c8).cast::<i32>().read(), seconds);
                assert_eq!(timer.cast::<u32>().add(1).read(), if interval > 0 { 1000 } else { 77 });
                assert_eq!(timer.cast::<u32>().add(8).read(),
                    if interval > 0 { TIMER_STATE_RUNNING } else { TIMER_STATE_STOPPED });
            }
        }
    }
}
