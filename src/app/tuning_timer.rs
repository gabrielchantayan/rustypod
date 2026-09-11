//! Tuning-controller timer sequencing.
//!
//! `stop_frequency_change_and_start_tuning_timer` — original:
//! `FUN_0811a890` @ 0x0811a890 (36 bytes, exact extent
//! 0x0811a890..0x0811a8b4; the next function opens with `push {r4,lr}`).
//! A binary scan of every ARM B/BL word in `osos.dec` finds ten direct
//! callers: ten unconditional `bl`, with no predicated `bl` or tail `b`
//! callers. The function stops the frequency-change timer at controller
//! `+0xb8`, clears the pending-frequency-change byte at `+0xb4`, then
//! tail-branches to the 40-byte helper at 0x0811ac74. That helper stops the
//! tuning timer at `+0xb0` and sets its delay to 4000 ms. The port calls the
//! already-ported `timer_start_after` directly rather than recreating the
//! unported tail-call wrapper; observable timer state and call order match.
//!
//! The controller's timer fields are target-width `u32` pointers. The word
//! accessors retain the 32-bit firmware layout on the 64-bit host; host
//! fixtures therefore use a low-address slab.

use crate::drivers::timer::{timer_start_after, timer_stop};

const TUNING_TIMER_OFFSET: usize = 0xb0;
const FREQUENCY_CHANGE_PENDING_OFFSET: usize = 0xb4;
const FREQUENCY_CHANGE_TIMER_OFFSET: usize = 0xb8;
const TUNING_DELAY_MS: u32 = 4000;

#[inline(always)]
unsafe fn target_pointer_at(object: *const u8, offset: usize) -> *mut u8 {
    unsafe { object.add(offset).cast::<u32>().read() as usize as *mut u8 }
}

/// stop_frequency_change_and_start_tuning_timer — original: `FUN_0811a890`
/// @ 0x0811a890 (36 bytes; ten direct unconditional `bl` call sites).
///
/// Stops the controller's frequency-change timer, clears its pending byte,
/// then stops and programs its tuning timer for a 4000 ms delay. Neither
/// timer pointer is NULL-checked, exactly as in the firmware. The stock body
/// tail-branches through 0x0811ac74; this port directly calls the ported
/// `timer_start_after`, which is that wrapper's complete behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stop_frequency_change_and_start_tuning_timer(controller: *mut u8) {
    unsafe {
        timer_stop(target_pointer_at(controller, FREQUENCY_CHANGE_TIMER_OFFSET));
        controller.add(FREQUENCY_CHANGE_PENDING_OFFSET).write(0);
        timer_start_after(
            target_pointer_at(controller, TUNING_TIMER_OFFSET),
            TUNING_DELAY_MS,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::timer::TIMER_STATE_STOPPED;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const CONTROLLER_OFFSET: usize = 0;
    const FREQUENCY_TIMER_OFFSET: usize = 0x200;
    const TUNING_TIMER_OFFSET_IN_SLAB: usize = 0x300;
    const TIMER_PERIOD_OFFSET: usize = 0x04;
    const TIMER_STATE_OFFSET: usize = 0x20;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TUNING_TIMER_SEQUENCE, SLAB_LEN).map(|pointer| pointer as usize)
    });

    #[test]
    fn stops_frequency_timer_clears_flag_and_restarts_tuning_delay() {
        let _ops_guard = TIMER_OPS_TEST_LOCK.lock().unwrap();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("app/tuning_timer"));
            return;
        };
        let base = base as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, SLAB_LEN);
            let controller = base.add(CONTROLLER_OFFSET);
            let frequency_timer = base.add(FREQUENCY_TIMER_OFFSET);
            let tuning_timer = base.add(TUNING_TIMER_OFFSET_IN_SLAB);

            controller
                .add(FREQUENCY_CHANGE_TIMER_OFFSET)
                .cast::<u32>()
                .write(frequency_timer as usize as u32);
            controller
                .add(TUNING_TIMER_OFFSET)
                .cast::<u32>()
                .write(tuning_timer as usize as u32);
            controller.add(FREQUENCY_CHANGE_PENDING_OFFSET).write(0xa5);
            frequency_timer.add(TIMER_STATE_OFFSET).cast::<u32>().write(0x1122_3344);
            tuning_timer.add(TIMER_STATE_OFFSET).cast::<u32>().write(0x5566_7788);
            tuning_timer.add(TIMER_PERIOD_OFFSET).cast::<u32>().write(17);

            stop_frequency_change_and_start_tuning_timer(controller);

            assert_eq!(controller.add(FREQUENCY_CHANGE_PENDING_OFFSET).read(), 0);
            assert_eq!(frequency_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(), TIMER_STATE_STOPPED);
            assert_eq!(tuning_timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(), TIMER_STATE_STOPPED);
            assert_eq!(tuning_timer.add(TIMER_PERIOD_OFFSET).cast::<u32>().read(), TUNING_DELAY_MS);
        }
    }
}
