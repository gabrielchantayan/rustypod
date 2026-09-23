//! Showcase timer-slot reset.
//!
/// `showcase_clear_timer_slots_and_stop` — original: `FUN_081b76b0` @
/// **0x081b76b0** (44 bytes exactly, `0x081b76b0..0x081b76dc`; the next
/// function begins `push {r4, lr}` at 0x081b76dc).
///
/// A raw `osos.dec` word decode establishes the four-word clear at object
/// offsets +0x1c4..+0x1d0 and the conditional tail branch to the already
/// ported `timer_stop` at 0x0812c6b0. The function clears the slots first,
/// then stops the non-null timer pointer stored at +0x1c0. Three independently
/// decoded inbound call sites are plain `bl` at 0x081b6d28, 0x081b7760, and
/// 0x081b783c; none is predicated.
///
/// Deliberate deviation: Rust represents the conditional tail branch as a
/// normal call followed by return; callers cannot observe a result from this
/// void function.
use crate::drivers::timer::timer_stop;

const TIMER_OFFSET: usize = 0x1c0;
const FIRST_SLOT_OFFSET: usize = 0x1c4;
const SLOT_COUNT: usize = 4;

/// # Safety
///
/// `showcase` must be valid and writable through +0x1d4. A nonzero target-width
/// timer pointer at +0x1c0 must designate a valid timer object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn showcase_clear_timer_slots_and_stop(showcase: *mut u8) {
    unsafe {
        let slots = showcase.add(FIRST_SLOT_OFFSET).cast::<u32>();
        slots.write(0);
        slots.add(1).write(0);
        slots.add(2).write(0);
        slots.add(3).write(0);

        let timer = showcase.add(TIMER_OFFSET).cast::<u32>().read() as usize as *mut u8;
        if !timer.is_null() {
            timer_stop(timer);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use core::ptr;

    const SLAB_LEN: usize = 0x400;
    const TIMER_IN_SLAB: usize = 0x200;
    const TIMER_STATE_OFFSET: usize = 0x20;

    unsafe extern "C" fn no_op_trace(_timer: *mut u8) {}
    unsafe extern "C" fn no_op_cancel(_handle: usize, _callback_id: usize, _timer: *mut u8) -> u32 { 0 }
    unsafe extern "C" fn no_op_timer(_timer: *mut u8) {}
    unsafe extern "C" fn no_op_construct(_timer: *mut u8, _init_arg: u32, _config_word: u32, _callback_handle: usize) {}
    unsafe extern "C" fn zero_tick() -> u32 { 0 }
    unsafe extern "C" fn no_deadline_order(_a: *const u32, _b: *const u32) -> u32 { 0 }
    unsafe extern "C" fn no_op_notify(_cell: *const u32) {}

    const TEST_TIMER_OPS: TimerOps = TimerOps {
        trace_assert: no_op_trace,
        cancel_callback: no_op_cancel,
        arm_timer: no_op_timer,
        construct_timer: no_op_construct,
        trace_validate: no_op_timer,
        tick: zero_tick,
        compare_deadlines: no_deadline_order,
        notify_pending: no_op_notify,
    };

    #[test]
    fn clears_slots_and_stops_a_nonnull_target_width_timer() {
        let _ops_guard = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(showcase) = try_map_u32_slab(hints::SHOWCASE_CLEAR_TIMER_SLOTS, SLAB_LEN) else {
            assert!(note_missing_u32_fixture("app/showcase_clear_timer_slots"));
            return;
        };
        unsafe {
            showcase.write_bytes(0, SLAB_LEN);
            let timer = showcase.add(TIMER_IN_SLAB);
            showcase.add(TIMER_OFFSET).cast::<u32>().write(timer as usize as u32);
            timer.add(TIMER_STATE_OFFSET).cast::<u32>().write(TIMER_STATE_RUNNING);
            for index in 0..SLOT_COUNT {
                showcase.add(FIRST_SLOT_OFFSET + index * 4).cast::<u32>().write(0xfeed_0000 + index as u32);
            }
            let saved_ops = ptr::addr_of!(TIMER_OPS).read_volatile();
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(TEST_TIMER_OPS);

            showcase_clear_timer_slots_and_stop(showcase);

            ptr::addr_of_mut!(TIMER_OPS).write_volatile(saved_ops);
            assert_eq!(timer.add(TIMER_STATE_OFFSET).cast::<u32>().read(), TIMER_STATE_STOPPED);
            for index in 0..SLOT_COUNT {
                assert_eq!(showcase.add(FIRST_SLOT_OFFSET + index * 4).cast::<u32>().read(), 0);
            }
        }
    }

    #[test]
    fn clears_slots_without_a_timer() {
        let mut showcase = [0u8; FIRST_SLOT_OFFSET + SLOT_COUNT * 4];
        unsafe {
            for index in 0..SLOT_COUNT {
                showcase.as_mut_ptr().add(FIRST_SLOT_OFFSET + index * 4).cast::<u32>().write(u32::MAX);
            }
            showcase_clear_timer_slots_and_stop(showcase.as_mut_ptr());
            for index in 0..SLOT_COUNT {
                assert_eq!(showcase.as_ptr().add(FIRST_SLOT_OFFSET + index * 4).cast::<u32>().read(), 0);
            }
        }
    }
}
