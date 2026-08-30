//! `view_timer_start_after` — lazily constructs and arms a view's timer.
//!
//! Original: `FUN_0810e02c` @ 0x0810e02c (92 bytes exactly,
//! 0x0810e02c..0x0810e088; the `mov r0, #1; bx lr` leaf at 0x0810e088
//! opens immediately afterward). A full ARM branch-word scan finds 41 direct
//! callers: 39 `bl` (38 unconditional `bl`, one `bleq`) and two tail `b`.
//! The lone predicated call is caller-side gating; this function itself has
//! no guard beyond the lazy timer allocation.
//!
//! # Algorithm
//!
//! ```text
//! if view.timer (+0x50) == NULL:
//!     timer = operator_new(0x2c)
//!     view.timer = timer
//!     timer_schedule_shim(view, timer, 0, 0)
//! view.delay (+0x54) = delay
//! stop_view_timer(view)                    // 0x0810dfe8
//! timer_start_after(view.timer, delay)     // reload +0x50
//! timer_restart(view.timer)                // reload +0x50; tail branch
//! ```
//!
//! The sibling at 0x0810e090 loads `view.delay` and tail-branches here,
//! establishing +0x54 as the stored re-arm delay. The timer owner/config word
//! is the view's 32-bit target address; the constructor shim rotates it into
//! the timer constructor's third argument.
//!
//! # Deviations
//!
//! `stop_view_timer` is the still-unported 16-byte wrapper at 0x0810dfe8, so
//! it uses the established `VIEW_EVENT_OPS` firmware-default seam. The other
//! callees (`operator_new`, `timer_schedule_shim`, `timer_start_after`, and
//! `timer_restart`) are already ported and called directly. Rust represents
//! the final tail branch as a normal call. There is deliberately no NULL
//! allocation guard: stock stores the allocator result then reaches the timer
//! helpers unconditionally.

use core::ptr::{addr_of, addr_of_mut};

use crate::app::view_event::VIEW_EVENT_OPS;
use crate::drivers::timer::{timer_restart, timer_schedule_shim, timer_start_after};
use crate::heap::veneers::operator_new;

/// Allocation size passed to tag-2 `operator_new` (`mov r0, #0x2c`).
const TIMER_OBJECT_SIZE: usize = 0x2c;

/// The view fields this method accesses. Target pointers remain `u32` so the
/// 32-bit firmware layout stays valid on both target and host fixtures.
#[repr(C)]
struct ViewTimerFields {
    _prefix: [u8; 0x50],
    timer: u32,
    delay: u32,
}

#[inline(always)]
unsafe fn timer(view: *mut u8) -> *mut u8 {
    unsafe { addr_of!((*view.cast::<ViewTimerFields>()).timer).read_volatile() as usize as *mut u8 }
}

#[inline(always)]
unsafe fn set_timer(view: *mut u8, value: *mut u8) {
    unsafe {
        addr_of_mut!((*view.cast::<ViewTimerFields>()).timer).write_volatile(value as u32);
    }
}

#[inline(always)]
unsafe fn set_delay(view: *mut u8, value: u32) {
    unsafe {
        addr_of_mut!((*view.cast::<ViewTimerFields>()).delay).write_volatile(value);
    }
}

/// view_timer_start_after — original: `FUN_0810e02c` @ 0x0810e02c
/// (92 bytes; 39 `bl` = 38 unconditional + 1 `bleq`, plus 2 tail `b`
/// call sites).
///
/// Lazily allocates the view's 0x2c-byte timer, initializes it with the view
/// as owner, records `delay`, then stops, reprograms, and arms the timer. The
/// timer field is reloaded after the stop wrapper and again before restart,
/// matching the original's two separate `ldr [view, #0x50]` instructions.
///
/// # Safety
///
/// `view` must be writable through +0x57. Its +0x50 field is a 32-bit target
/// pointer; a non-NULL value must name a timer object valid for the ported
/// timer helpers. Allocation failure follows stock's unguarded NULL path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_timer_start_after(view: *mut u8, delay: u32) {
    if unsafe { timer(view) }.is_null() {
        let allocated = unsafe { operator_new(TIMER_OBJECT_SIZE) };
        unsafe { set_timer(view, allocated) };
        unsafe { timer_schedule_shim(view as usize as u32, allocated, 0, 0) };
    }

    unsafe { set_delay(view, delay) };
    let stop = unsafe { addr_of_mut!(VIEW_EVENT_OPS.stop_view_timer).read_volatile() };
    unsafe { stop(view) };
    unsafe { timer_start_after(timer(view), delay) };
    unsafe { timer_restart(timer(view)) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::view_event::{ViewEventOps, VIEW_EVENT_OPS};
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING};
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK,
        VIEW_EVENT_OPS_TEST_LOCK,
    };
    use std::sync::{LazyLock, Mutex};
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    const TIMER_A_OFFSET: usize = 0x100;
    const TIMER_B_OFFSET: usize = 0x200;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Construct(usize, u32, u32, usize),
        Stop(usize),
        Trace(usize),
        Arm(usize),
    }

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
    static mut STOP_REPLACEMENT: usize = 0;

    /// Target-size layout through the 0x2c bytes allocated by the original.
    #[repr(C)]
    struct TimerObject {
        _next: u32,
        period: u32,
        _deadline: u32,
        _opaque_0c: [u8; 0x0c],
        _queued_state: u32,
        _armed: u32,
        state: u32,
        _config_word: u32,
        _callback_handle: u32,
    }

    #[derive(Clone, Copy)]
    struct Fixture {
        base: *mut u8,
        view: *mut ViewTimerFields,
        timer_a: *mut TimerObject,
        timer_b: *mut TimerObject,
    }

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::VIEW_TIMER, SLAB_LEN).map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<Fixture> {
        let base = (*SLAB)? as *mut u8;
        Some(unsafe {
            Fixture {
                base,
                view: base.cast::<ViewTimerFields>(),
                timer_a: base.add(TIMER_A_OFFSET).cast::<TimerObject>(),
                timer_b: base.add(TIMER_B_OFFSET).cast::<TimerObject>(),
            }
        })
    }

    fn record(event: Event) {
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event);
    }

    fn events() -> Vec<Event> {
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    unsafe extern "C" fn recording_construct(
        timer: *mut u8,
        init_arg: u32,
        config_word: u32,
        callback_handle: usize,
    ) {
        record(Event::Construct(
            timer as usize,
            init_arg,
            config_word,
            callback_handle,
        ));
    }

    unsafe extern "C" fn recording_stop(view: *mut u8) {
        record(Event::Stop(view as usize));
        let replacement = unsafe { STOP_REPLACEMENT };
        if replacement != 0 {
            unsafe { set_timer(view, replacement as *mut u8) };
        }
    }

    unsafe extern "C" fn recording_trace(timer: *mut u8) {
        record(Event::Trace(timer as usize));
    }

    unsafe extern "C" fn recording_arm(timer: *mut u8) {
        record(Event::Arm(timer as usize));
    }

    /// Restores both shared seams while their respective test locks are held.
    struct OpsRestore {
        timer_ops: TimerOps,
        view_ops: ViewEventOps,
    }

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(TIMER_OPS).write_volatile(self.timer_ops);
                addr_of_mut!(VIEW_EVENT_OPS).write_volatile(self.view_ops);
            }
        }
    }

    unsafe fn install_recording_ops() -> OpsRestore {
        let timer_ops = unsafe { addr_of!(TIMER_OPS).read_volatile() };
        let view_ops = unsafe { addr_of!(VIEW_EVENT_OPS).read_volatile() };
        let mut recorded_timer_ops = timer_ops;
        recorded_timer_ops.trace_assert = recording_trace;
        recorded_timer_ops.arm_timer = recording_arm;
        recorded_timer_ops.construct_timer = recording_construct;
        unsafe { addr_of_mut!(TIMER_OPS).write_volatile(recorded_timer_ops) };
        unsafe {
            addr_of_mut!(VIEW_EVENT_OPS).write_volatile(ViewEventOps {
                stop_view_timer: recording_stop,
                commit_staged_flags: view_ops.commit_staged_flags,
            })
        };
        OpsRestore { timer_ops, view_ops }
    }

    unsafe fn reset_fixture(fixture: Fixture, replacement: *mut u8) {
        unsafe { fixture.base.write_bytes(0, SLAB_LEN) };
        unsafe { STOP_REPLACEMENT = replacement as usize };
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }

    #[test]
    fn allocation_constructs_then_programs_and_arms_the_view_timer() {
        let _timer_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _view_lock = VIEW_EVENT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _heap_lock = mock_heap();
        let Some(fixture) = fixture() else {
            assert!(note_missing_u32_fixture("app::view_timer"));
            return;
        };
        unsafe {
            reset_fixture(fixture, core::ptr::null_mut());
            set_alloc_ret(fixture.timer_a.cast());
            let _restore = install_recording_ops();

            view_timer_start_after(fixture.view.cast(), 500);

            assert_eq!(
                addr_of!((*fixture.view).timer).read_volatile(),
                fixture.timer_a as u32,
                "the newly allocated timer is installed at view+0x50"
            );
            assert_eq!(
                addr_of!((*fixture.view).delay).read_volatile(),
                500,
                "the re-arm delay is stored at view+0x54"
            );
            assert_eq!(alloc_log(), (1, TIMER_OBJECT_SIZE, 2));
            assert_eq!(
                events(),
                std::vec![
                    Event::Construct(fixture.timer_a as usize, 0, fixture.view as usize as u32, 0),
                    Event::Stop(fixture.view as usize),
                    Event::Trace(fixture.timer_a as usize),
                    Event::Trace(fixture.timer_a as usize),
                    Event::Trace(fixture.timer_a as usize),
                    Event::Arm(fixture.timer_a as usize),
                ],
                "construct, stop wrapper, start-after, then restart"
            );
            assert_eq!(addr_of!((*fixture.timer_a).period).read_volatile(), 500);
            assert_eq!(
                addr_of!((*fixture.timer_a).state).read_volatile(),
                TIMER_STATE_RUNNING,
                "restart leaves the timer in the retailOS 'run ' state"
            );
        }
    }

    #[test]
    fn stop_wrapper_replacement_is_reloaded_without_reallocating() {
        let _timer_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _view_lock = VIEW_EVENT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _heap_lock = mock_heap();
        let Some(fixture) = fixture() else {
            assert!(note_missing_u32_fixture("app::view_timer"));
            return;
        };
        unsafe {
            reset_fixture(fixture, fixture.timer_b.cast());
            addr_of_mut!((*fixture.view).timer).write_volatile(fixture.timer_a as u32);
            addr_of_mut!((*fixture.timer_a).period).write_volatile(0xa5a5_a5a5);
            addr_of_mut!((*fixture.timer_a).state).write_volatile(0x1111_1111);
            let _restore = install_recording_ops();

            view_timer_start_after(fixture.view.cast(), 0);

            assert_eq!(alloc_log().0, 0, "an installed timer bypasses operator_new");
            assert_eq!(
                events(),
                std::vec![
                    Event::Stop(fixture.view as usize),
                    Event::Trace(fixture.timer_b as usize),
                    Event::Trace(fixture.timer_b as usize),
                    Event::Trace(fixture.timer_b as usize),
                    Event::Arm(fixture.timer_b as usize),
                ],
                "both post-stop loads use the wrapper's replacement timer"
            );
            assert_eq!(
                addr_of!((*fixture.view).timer).read_volatile(),
                fixture.timer_b as u32,
                "the wrapper's replacement remains installed"
            );
            assert_eq!(addr_of!((*fixture.view).delay).read_volatile(), 0);
            assert_eq!(addr_of!((*fixture.timer_b).period).read_volatile(), 0);
            assert_eq!(
                addr_of!((*fixture.timer_b).state).read_volatile(),
                TIMER_STATE_RUNNING
            );
            assert_eq!(
                addr_of!((*fixture.timer_a).period).read_volatile(),
                0xa5a5_a5a5,
                "the stale pre-stop timer is not reprogrammed"
            );
            assert_eq!(
                addr_of!((*fixture.timer_a).state).read_volatile(),
                0x1111_1111,
                "the stale pre-stop timer is not restarted"
            );
        }
    }
}
