//! Stop a view's embedded timer, reset its halfword, and invalidate its bounds.
//!
//! Original: `FUN_08143000` @ 0x08143000. True extent is 44 bytes
//! [0x08143000,0x0814302c): 40 bytes of code plus the 0x00004d80 literal
//! at +0x28; the next function opens with push {r4,r5,r6,lr} at +0x2c.
//! Whole-image raw ARM branch decoding finds two incoming plain BLs
//! (0x08143080, 0x081430a8), zero predicated BLs. The body has one BL
//! to timer_stop @ 0x0812c6b0 and one tail B to ui_element_invalidate
//! @ 0x0826ec9c; Ghidra incorrectly incorporates the invalidation body.
//!
//! Stop the timer embedded at +0x220, store 0x4d80 as a halfword at
//! +0x250, and invalidate the whole element, returning its pointer.
//! The event caller matches the timer at +0x220 before invoking this;
//! the setup caller initializes that same timer before invoking this.
//! No class identity or meaning for the reset halfword is assumed.
//!
//! Deliberate deviation: express the final tail branch as a return-position
//! call to the existing port. Both callees are ported; no new seams.

use crate::drivers::timer::timer_stop;
use crate::ui::invalidate::ui_element_invalidate;

/// # Safety
/// `view` must be an aligned, writable UI element through +0x251 with a
/// valid embedded timer at +0x220 and valid fields for UI invalidation.
/// The retail function has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_view_stop_invalidate(view: *mut u8) -> *mut u8 {
    timer_stop(view.add(0x220));
    view.add(0x250).cast::<u16>().write(0x4d80);
    ui_element_invalidate(view)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_EXPIRED,
        TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::TIMER_OPS_TEST_LOCK;

    struct Restore(TimerOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }

    unsafe extern "C" fn trace(timer: *mut u8) {
        // The reset must not precede stopping the embedded timer.
        assert_eq!(timer.add(0x30).cast::<u16>().read(), 0xbeef);
    }

    unsafe extern "C" fn cancel(handle: usize, _: usize, timer: *mut u8) -> u32 {
        assert_eq!(handle, 0x1234);
        assert_eq!(timer.add(0x30).cast::<u16>().read(), 0xbeef);
        // Cancellation can mutate the view: the subsequent reset must win.
        timer.add(0x30).cast::<u16>().write(0x1234);
        timer.add(0x2c).cast::<u32>().write(0xcafe_babe);
        1
    }

    #[test]
    fn stops_running_and_expired_timers_before_halfword_reset() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let old = ptr::addr_of!(TIMER_OPS).read_volatile();
            let _restore = Restore(old);
            let mut ops = old;
            ops.trace_assert = trace;
            ops.cancel_callback = cancel;
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(ops);
            for state in [TIMER_STATE_RUNNING, TIMER_STATE_EXPIRED, TIMER_STATE_STOPPED] {
                let mut storage = [0xa5a5_a5a5u32; 0x260 / 4];
                let view = storage.as_mut_ptr().cast::<u8>();
                // A hidden view takes the real invalidation early-return path.
                view.add(0x48).cast::<u32>().write(0);
                view.add(0x240).cast::<u32>().write(state);
                view.add(0x248).cast::<u32>().write(0x1234);
                view.add(0x250).cast::<u16>().write(0xbeef);
                assert_eq!(timed_view_stop_invalidate(view), view);
                assert_eq!(view.add(0x240).cast::<u32>().read(), TIMER_STATE_STOPPED);
                assert_eq!(view.add(0x250).cast::<u16>().read(), 0x4d80);
                assert_eq!(view.add(0x252).cast::<u16>().read(), 0xa5a5);
                assert_eq!(view.add(0x24c).cast::<u32>().read(),
                    if state == TIMER_STATE_EXPIRED { 0xcafe_babe } else { 0xa5a5_a5a5 });
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[0x254 / 4], 0xa5a5_a5a5);
            }
        }
    }
}
