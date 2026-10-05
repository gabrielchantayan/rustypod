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

/// stop_volume_down_timers — original: `FUN_081d0670` @ 0x081d0670.
///
/// True extent: 28 bytes, 0x081d0670..0x081d068c, ending in a tail branch;
/// the next real function begins with `push {r4,lr}` at 0x081d068c.
/// Two incoming BL sites, binary-verified: one plain BL at 0x081d05ec
/// and one BLNE at 0x081ce280 (the HandleRemoteVolumeDownUp path).
/// Stops controller +0xb4, then reloads and stops +0xb0, without NULL
/// guards. Both raw branches target the already-ported timer_stop.
/// Deliberate deviation: the final tail branch is expressed as a direct
/// call. A dedicated target section keeps this identical sibling export
/// independently visible to disassembly tools.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stop_volume_down_timers")]
pub unsafe extern "C" fn stop_volume_down_timers(controller: *mut u8) {
    unsafe {
        timer_stop(timer_at(controller, FIRST_TIMER_OFFSET));
        timer_stop(timer_at(controller, SECOND_TIMER_OFFSET));
    }
}

/// stop_volume_up_timers — original: `FUN_081d04e8` @ 0x081d04e8.
///
/// True extent: 28 bytes, 0x081d04e8..0x081d0504; the next function
/// starts with `push {r4,lr}`. Binary-verified incoming calls: one plain
/// BL at 0x081d0248 and one BLNE at 0x081ce25c. The body has one BL
/// and one tail B, both to the ported timer_stop @ 0x0812c6b0.
/// Stops controller +0xb0, then reloads and stops +0xb4, without NULL
/// guards. Ghidra incorrectly incorporates the timer_stop body.
/// Deliberate deviation: Rust expresses the final tail branch as a direct
/// call; target-width aligned pointer loads and their order are preserved.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stop_volume_up_timers(controller: *mut u8) {
    unsafe {
        timer_stop(timer_at(controller, SECOND_TIMER_OFFSET));
        timer_stop(timer_at(controller, FIRST_TIMER_OFFSET));
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
    fn reloads_second_timer_after_first_stop_and_leaves_b8_untouched() {
        let _ops_guard = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("app/controller_timer_pair"));
            return;
        };
        let base = base as *mut u8;
        for (stop, first_offset, second_offset) in [
            (stop_controller_timer_pair as unsafe extern "C" fn(*mut u8), FIRST_TIMER_OFFSET, SECOND_TIMER_OFFSET),
            (stop_volume_down_timers, FIRST_TIMER_OFFSET, SECOND_TIMER_OFFSET),
            (stop_volume_up_timers, SECOND_TIMER_OFFSET, FIRST_TIMER_OFFSET),
        ] {
        unsafe {
            core::ptr::write_bytes(base, 0, SLAB_LEN);
            let first_timer = base.add(FIRST_TIMER_IN_SLAB);
            let original_second_timer = base.add(SECOND_TIMER_IN_SLAB);
            let replacement_timer = base.add(REPLACEMENT_TIMER_IN_SLAB);
            let untouched_timer = base.add(UNTOUCHED_TIMER_IN_SLAB);

            base.add(first_offset)
                .cast::<u32>()
                .write(first_timer as usize as u32);
            base.add(second_offset)
                .cast::<u32>()
                .write(original_second_timer as usize as u32);
            base.add(THIRD_TIMER_OFFSET)
                .cast::<u32>()
                .write(untouched_timer as usize as u32);
            for timer in [first_timer, original_second_timer, replacement_timer, untouched_timer] {
                timer.add(TIMER_STATE_OFFSET).cast::<u32>().write(TIMER_STATE_RUNNING);
            }

            ptr::addr_of_mut!(FIRST_TIMER).write(first_timer);
            ptr::addr_of_mut!(SECOND_TIMER_SLOT).write(base.add(second_offset).cast::<u32>());
            ptr::addr_of_mut!(REPLACEMENT_TIMER).write(replacement_timer);
            let saved_ops = ptr::addr_of!(TIMER_OPS).read_volatile();
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(RELOAD_SECOND_TIMER_OPS);

            stop(base);

            let states = [
                first_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(),
                original_second_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(),
                replacement_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(),
                untouched_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(),
            ];
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(saved_ops);

            assert_eq!(states[0], TIMER_STATE_STOPPED, "first timer is stopped");
            assert_eq!(states[1], TIMER_STATE_RUNNING, "the stale second target is not stopped");
            assert_eq!(states[2], TIMER_STATE_STOPPED, "second pointer is reloaded after the first stop");
            assert_eq!(states[3], TIMER_STATE_RUNNING, "+0xb8 is not a target");

            // Both controller fields may refer to the same timer. Repeated
            // cancellation must leave it stopped and not touch its neighbours.
            first_timer.add(TIMER_STATE_OFFSET).cast::<u32>().write(TIMER_STATE_RUNNING);
            base.add(second_offset).cast::<u32>().write(first_timer as usize as u32);
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(TimerOps {
                trace_assert: no_op_timer,
                ..RELOAD_SECOND_TIMER_OPS
            });
            stop(base);
            let alias_state = first_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read();
            let neighbour_state = untouched_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read();
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(saved_ops);
            assert_eq!(alias_state, TIMER_STATE_STOPPED);
            assert_eq!(neighbour_state, TIMER_STATE_RUNNING);
        }
        }
    }
}
