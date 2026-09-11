//! Controller timer-pair cancellation.
//!
//! `stop_controller_timer_pair` — original: `FUN_081d068c` @ 0x081d068c
//! (28 bytes, exact extent 0x081d068c..0x081d06a8; the next function opens
//! with `push {r4,lr}`). A binary scan of every ARM B/BL word in `osos.dec`
//! finds nine direct callers: eight unconditional `bl` and one `blne`; no
//! tail-branch callers. The raw body loads the controller's timer at +0xb4,
//! calls the already-ported `timer_stop`, then reloads the timer at +0xb0
//! after that call and tail-branches to `timer_stop` again. The timer fields
//! are unconditionally dereferenced, as in retailOS. Ghidra incorrectly
//! extends this function into the separately linked sibling at 0x081d06a8.
//!
//! Rust expresses the final tail branch as an ordinary direct call. This is
//! the only deliberate deviation; it preserves the two calls, their order,
//! and their unchecked target-width pointer loads.

use crate::drivers::timer::timer_stop;

const FIRST_TIMER_OFFSET: usize = 0xb4;
const SECOND_TIMER_OFFSET: usize = 0xb0;

#[inline(always)]
unsafe fn timer_at(controller: *const u8, offset: usize) -> *mut u8 {
    unsafe { controller.add(offset).cast::<u32>().read() as usize as *mut u8 }
}

/// stop_controller_timer_pair — original: `FUN_081d068c` @ 0x081d068c
/// (28 bytes; nine direct call sites: eight `bl`, one `blne`).
///
/// Stops the timer pointer at controller +0xb4, then separately loads and
/// stops the pointer at +0xb0. Neither pointer is NULL-checked; the second
/// load remains after the first stop exactly as in the ARM body.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stop_controller_timer_pair(controller: *mut u8) {
    unsafe {
        timer_stop(timer_at(controller, FIRST_TIMER_OFFSET));
        timer_stop(timer_at(controller, SECOND_TIMER_OFFSET));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use core::ptr;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const FIRST_TIMER_IN_SLAB: usize = 0x200;
    const SECOND_TIMER_IN_SLAB: usize = 0x300;
    const REPLACEMENT_TIMER_IN_SLAB: usize = 0x400;
    const UNTOUCHED_TIMER_IN_SLAB: usize = 0x500;
    const THIRD_TIMER_OFFSET: usize = 0xb8;
    const TIMER_STATE_OFFSET: usize = 0x20;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::DUAL_CONTROLLER_TIMER_STOP, SLAB_LEN).map(|pointer| pointer as usize)
    });

    static mut FIRST_TIMER: *mut u8 = core::ptr::null_mut();
    static mut SECOND_TIMER_SLOT: *mut u32 = core::ptr::null_mut();
    static mut REPLACEMENT_TIMER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn reload_second_timer_after_first_stop(timer: *mut u8) {
        unsafe {
            if timer == ptr::addr_of!(FIRST_TIMER).read() {
                ptr::addr_of!(SECOND_TIMER_SLOT)
                    .read()
                    .write(ptr::addr_of!(REPLACEMENT_TIMER).read() as usize as u32);
            }
        }
    }

    unsafe extern "C" fn no_op_cancel(_handle: usize, _callback_id: usize, _timer: *mut u8) -> u32 {
        0
    }
    unsafe extern "C" fn no_op_timer(_timer: *mut u8) {}
    unsafe extern "C" fn no_op_construct(
        _timer: *mut u8,
        _init_arg: u32,
        _config_word: u32,
        _callback_handle: usize,
    ) {
    }
    unsafe extern "C" fn zero_tick() -> u32 {
        0
    }
    unsafe extern "C" fn no_deadline_order(_a: *const u32, _b: *const u32) -> u32 {
        0
    }
    unsafe extern "C" fn no_op_notify(_cell: *const u32) {}

    const RELOAD_SECOND_TIMER_OPS: TimerOps = TimerOps {
        trace_assert: reload_second_timer_after_first_stop,
        cancel_callback: no_op_cancel,
        arm_timer: no_op_timer,
        construct_timer: no_op_construct,
        trace_validate: no_op_timer,
        tick: zero_tick,
        compare_deadlines: no_deadline_order,
        notify_pending: no_op_notify,
    };

    #[test]
    fn reloads_b0_after_stopping_b4_and_leaves_b8_untouched() {
        let _ops_guard = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("app/controller_timer_pair"));
            return;
        };
        let base = base as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, SLAB_LEN);
            let first_timer = base.add(FIRST_TIMER_IN_SLAB);
            let original_second_timer = base.add(SECOND_TIMER_IN_SLAB);
            let replacement_timer = base.add(REPLACEMENT_TIMER_IN_SLAB);
            let untouched_timer = base.add(UNTOUCHED_TIMER_IN_SLAB);

            base.add(FIRST_TIMER_OFFSET)
                .cast::<u32>()
                .write(first_timer as usize as u32);
            base.add(SECOND_TIMER_OFFSET)
                .cast::<u32>()
                .write(original_second_timer as usize as u32);
            base.add(THIRD_TIMER_OFFSET)
                .cast::<u32>()
                .write(untouched_timer as usize as u32);
            for timer in [first_timer, original_second_timer, replacement_timer, untouched_timer] {
                timer.add(TIMER_STATE_OFFSET).cast::<u32>().write(TIMER_STATE_RUNNING);
            }

            ptr::addr_of_mut!(FIRST_TIMER).write(first_timer);
            ptr::addr_of_mut!(SECOND_TIMER_SLOT).write(base.add(SECOND_TIMER_OFFSET).cast::<u32>());
            ptr::addr_of_mut!(REPLACEMENT_TIMER).write(replacement_timer);
            let saved_ops = ptr::addr_of!(TIMER_OPS).read_volatile();
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(RELOAD_SECOND_TIMER_OPS);

            stop_controller_timer_pair(base);

            let states = [
                first_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(),
                original_second_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(),
                replacement_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(),
                untouched_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(),
            ];
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(saved_ops);

            assert_eq!(states[0], TIMER_STATE_STOPPED, "+0xb4 timer is stopped first");
            assert_eq!(states[1], TIMER_STATE_RUNNING, "the stale +0xb0 target is not stopped");
            assert_eq!(states[2], TIMER_STATE_STOPPED, "+0xb0 is reloaded after the first stop");
            assert_eq!(states[3], TIMER_STATE_RUNNING, "+0xb8 is not a target");
        }
    }
}
