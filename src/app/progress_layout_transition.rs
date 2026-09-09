//! `stop_progress_layout_transition` — original: `FUN_08216d70` @
//! **0x08216d70** (52 bytes exactly, 0x08216d70..0x08216da4).
//!
//! The preceding bytes are a NUL-terminated string ending at 0x08216d6f;
//! `push {r4,lr}` opens this body and the sibling `push {r4-r6,lr}` opens at
//! 0x08216da4. Decoding every ARM B/BL immediate in `osos.dec` finds 15
//! direct call sites: 3 unconditional `bl` and 12 caller-gated `blne`; no
//! tail `b` sites. The caller-side predicates test this controller's +0xc1
//! byte before the call. This body repeats that guard rather than treating the
//! predicated calls as a NULL guard.
//!
//! ## Algorithm
//!
//! If the controller's activity flag at +0xc1 is zero, return without reading
//! either pointer. Otherwise stop its +0xc4 timer, call 0x081f9248 on the
//! +0xb0 activity with literal `1`, then clear +0xc1. Neither pointer is
//! NULL-checked by retailOS.
//!
//! ## Deliberate deviation
//!
//! Timer stop is already ported as [`crate::drivers::timer::timer_stop`] and
//! is called directly. The 0x081f9248 activity callee is not ported, so the
//! call remains an explicit volatile dispatch seam: target builds invoke its
//! firmware address and host tests install a recording replacement. Its wider
//! identity is deliberately not inferred here.

use core::ptr::{addr_of, addr_of_mut};

use crate::drivers::timer::timer_stop;

/// Firmware address of the unported activity cleanup callee.
pub const PROGRESS_LAYOUT_ACTIVITY_STOP_ADDRESS: usize = 0x081f_9248;

/// The controller fields this routine accesses. Target pointers remain u32 so
/// the layout is identical on host and ARM.
#[repr(C)]
struct ProgressLayoutTransitionFields {
    _prefix: [u8; 0xb0],
    activity: u32,
    _opaque_b4_to_c0: [u8; 0x0d],
    active: u8,
    _padding_c2: [u8; 2],
    timer: u32,
}

const _: () = assert!(core::mem::offset_of!(ProgressLayoutTransitionFields, activity) == 0xb0);
const _: () = assert!(core::mem::offset_of!(ProgressLayoutTransitionFields, active) == 0xc1);
const _: () = assert!(core::mem::offset_of!(ProgressLayoutTransitionFields, timer) == 0xc4);

/// Dispatch table for the one unported callee reached after the timer stops.
#[derive(Clone, Copy)]
pub struct ProgressLayoutTransitionOps {
    /// `FUN_081f9248(activity, 1)`: retailOS activity finalization/cleanup.
    pub stop_activity: unsafe extern "C" fn(activity: *mut u8, finish: u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_stop_activity(activity: *mut u8, finish: u32) {
    let f: unsafe extern "C" fn(*mut u8, u32) =
        unsafe { core::mem::transmute(PROGRESS_LAYOUT_ACTIVITY_STOP_ADDRESS) };
    unsafe { f(activity, finish) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_stop_activity(_activity: *mut u8, _finish: u32) {
    panic!("stop_progress_layout_transition requires firmware callee 0x081f9248")
}

#[cfg(target_os = "none")]
pub static mut PROGRESS_LAYOUT_TRANSITION_OPS: ProgressLayoutTransitionOps =
    ProgressLayoutTransitionOps {
        stop_activity: firmware_stop_activity,
    };

#[cfg(not(target_os = "none"))]
pub static mut PROGRESS_LAYOUT_TRANSITION_OPS: ProgressLayoutTransitionOps =
    ProgressLayoutTransitionOps {
        stop_activity: missing_stop_activity,
    };

#[inline(always)]
fn transition_ops() -> ProgressLayoutTransitionOps {
    unsafe { addr_of!(PROGRESS_LAYOUT_TRANSITION_OPS).read_volatile() }
}

/// `stop_progress_layout_transition` — original: `FUN_08216d70` @ 0x08216d70
/// (52 bytes; 15 direct call sites = 3 `bl` + 12 `blne`).
///
/// Stops the controller's active progress-layout transition. An inactive
/// controller returns without touching its timer or activity. The active path
/// stops +0xc4, finalizes +0xb0 with literal `1`, and clears +0xc1 last.
///
/// # Safety
///
/// `this` must identify writable controller storage through +0xc7. If its
/// activity byte is nonzero, +0xb0 and +0xc4 must be valid target pointers;
/// retailOS performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stop_progress_layout_transition(this: *mut u8) {
    let fields = this.cast::<ProgressLayoutTransitionFields>();
    if unsafe { addr_of!((*fields).active).read_volatile() } == 0 {
        return;
    }

    let timer = unsafe { addr_of!((*fields).timer).read_volatile() };
    unsafe { timer_stop(timer as usize as *mut u8) };

    let activity = unsafe { addr_of!((*fields).activity).read_volatile() };
    let stop_activity = transition_ops().stop_activity;
    unsafe { stop_activity(activity as usize as *mut u8, 1) };

    unsafe { addr_of_mut!((*fields).active).write_volatile(0) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use std::sync::{LazyLock, Mutex};
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    const TIMER_OFFSET: usize = 0x200;
    const ACTIVITY_OFFSET: usize = 0x300;

    #[repr(C)]
    struct TimerObject {
        _prefix: [u8; 0x20],
        state: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        TimerStop(usize),
        ActivityStop(usize, u32),
    }

    #[derive(Clone, Copy)]
    struct Fixture {
        base: *mut u8,
        controller: *mut ProgressLayoutTransitionFields,
        timer: *mut TimerObject,
        activity: *mut u8,
    }

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::PROGRESS_LAYOUT_TRANSITION, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
    static PROGRESS_LAYOUT_TRANSITION_OPS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<Fixture> {
        let base = (*SLAB)? as *mut u8;
        Some(unsafe {
            Fixture {
                base,
                controller: base.cast::<ProgressLayoutTransitionFields>(),
                timer: base.add(TIMER_OFFSET).cast::<TimerObject>(),
                activity: base.add(ACTIVITY_OFFSET),
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

    unsafe extern "C" fn recording_trace(timer: *mut u8) {
        record(Event::TimerStop(timer as usize));
    }

    unsafe extern "C" fn recording_stop_activity(activity: *mut u8, finish: u32) {
        record(Event::ActivityStop(activity as usize, finish));
    }

    struct TimerOpsRestore(TimerOps);

    impl Drop for TimerOpsRestore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }

    struct TransitionOpsRestore(ProgressLayoutTransitionOps);

    impl Drop for TransitionOpsRestore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(PROGRESS_LAYOUT_TRANSITION_OPS).write_volatile(self.0) };
        }
    }

    unsafe fn install_recording_ops() -> (TimerOpsRestore, TransitionOpsRestore) {
        let timer_ops = unsafe { addr_of!(TIMER_OPS).read_volatile() };
        let mut recorded_timer_ops = timer_ops;
        recorded_timer_ops.trace_assert = recording_trace;
        unsafe { addr_of_mut!(TIMER_OPS).write_volatile(recorded_timer_ops) };

        let transition_ops = unsafe { addr_of!(PROGRESS_LAYOUT_TRANSITION_OPS).read_volatile() };
        unsafe {
            addr_of_mut!(PROGRESS_LAYOUT_TRANSITION_OPS).write_volatile(ProgressLayoutTransitionOps {
                stop_activity: recording_stop_activity,
            })
        };

        (TimerOpsRestore(timer_ops), TransitionOpsRestore(transition_ops))
    }

    unsafe fn reset_fixture(fixture: Fixture) {
        unsafe { fixture.base.write_bytes(0, SLAB_LEN) };
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }

    #[test]
    fn inactive_transition_does_not_read_or_stop_either_pointer() {
        let _timer_ops_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _transition_ops_lock = PROGRESS_LAYOUT_TRANSITION_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(fixture) = fixture() else {
            assert!(note_missing_u32_fixture("app::progress_layout_transition"));
            return;
        };

        unsafe {
            reset_fixture(fixture);
            addr_of_mut!((*fixture.controller).activity).write_volatile(fixture.activity as u32);
            addr_of_mut!((*fixture.controller).timer).write_volatile(fixture.timer as u32);
            addr_of_mut!((*fixture.timer).state).write_volatile(TIMER_STATE_RUNNING);
            let _restore = install_recording_ops();

            stop_progress_layout_transition(fixture.controller.cast());

            assert_eq!(events(), std::vec![], "zero +0xc1 suppresses both calls");
            assert_eq!(
                addr_of!((*fixture.timer).state).read_volatile(),
                TIMER_STATE_RUNNING,
                "the timer remains untouched when the transition is inactive"
            );
            assert_eq!(
                addr_of!((*fixture.controller).active).read_volatile(),
                0,
                "the inactive marker remains zero"
            );
        }
    }

    #[test]
    fn active_transition_stops_timer_then_activity_and_clears_flag() {
        let _timer_ops_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _transition_ops_lock = PROGRESS_LAYOUT_TRANSITION_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(fixture) = fixture() else {
            assert!(note_missing_u32_fixture("app::progress_layout_transition"));
            return;
        };

        unsafe {
            reset_fixture(fixture);
            addr_of_mut!((*fixture.controller).activity).write_volatile(fixture.activity as u32);
            addr_of_mut!((*fixture.controller).timer).write_volatile(fixture.timer as u32);
            addr_of_mut!((*fixture.controller).active).write_volatile(1);
            addr_of_mut!((*fixture.timer).state).write_volatile(TIMER_STATE_RUNNING);
            let _restore = install_recording_ops();

            stop_progress_layout_transition(fixture.controller.cast());

            assert_eq!(
                events(),
                std::vec![
                    Event::TimerStop(fixture.timer as usize),
                    Event::ActivityStop(fixture.activity as usize, 1),
                ],
                "retailOS stops the timer before the literal-one activity call"
            );
            assert_eq!(
                addr_of!((*fixture.timer).state).read_volatile(),
                TIMER_STATE_STOPPED,
                "the direct timer_stop call reaches the supplied timer"
            );
            assert_eq!(
                addr_of!((*fixture.controller).active).read_volatile(),
                0,
                "the transition flag clears only after both calls"
            );
        }
    }
}
