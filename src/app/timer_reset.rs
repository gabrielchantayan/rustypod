//! `timer_reset_4000` — stop, reprogram to 4000 ms, and re-arm a
//! controller's timer.
//!
//! Original: `FUN_08217318` @ 0x08217318 (40 bytes exactly,
//! 0x08217318..0x08217340; the `mov r0, #0; bx lr` leaf at 0x08217340
//! opens immediately afterward, confirming Ghidra's 40-byte extent).
//! A full ARM branch-word scan of osos.dec finds 24 call sites: 22
//! unconditional `bl` plus 2 `blne`. The predicated pair are caller-side
//! mode gates (the event handlers' `global.mode != MODE_X` checks), not a
//! NULL guard — this routine dereferences this+0xb8 unconditionally.
//!
//! # Algorithm
//!
//! ```text
//! timer = this.timer (+0xb8)
//! timer_stop(timer)                  // 0x0812c6b0
//! timer = this.timer (+0xb8)         // reload
//! timer_start_after(timer, 4000)     // 0x0812c63c
//! timer = this.timer (+0xb8)         // reload
//! timer_restart(timer)               // 0x0812bf4c; tail branch
//! ```
//!
//! A method on an unidentified controller class: every caller clusters in
//! 0x08216xxx-0x0821fxxx and is an event handler returning 1 ("handled")
//! that resets the object's +0xb8 timer to a fresh 4000 ms unless a global
//! mode word (`FUN_0817ee04()`+0x28) equals that handler's mode constant.
//!
//! # Deviations
//!
//! All three callees are already ported (`timer_stop`, `timer_start_after`,
//! `timer_restart`), so the port calls them directly and needs no dispatch
//! seam. Rust represents the original's tail branch to `timer_restart` as a
//! normal call. The three separate `ldr [this, #0xb8]` loads are preserved
//! as volatile reads, so a stop path that swapped the field would be honored
//! by the later helpers exactly as in stock.

use core::ptr::addr_of;

use crate::drivers::timer::{timer_restart, timer_start_after, timer_stop};

/// Fixed re-arm delay (`mov r1, #0xfa0`).
const RESET_DELAY_MS: u32 = 4000;

/// The controller fields this method accesses. Target pointers remain `u32`
/// so the 32-bit firmware layout stays valid on both target and host
/// fixtures.
#[repr(C)]
struct ResetTimerFields {
    _prefix: [u8; 0xb8],
    timer: u32,
}

#[inline(always)]
unsafe fn timer(this: *mut u8) -> *mut u8 {
    unsafe { addr_of!((*this.cast::<ResetTimerFields>()).timer).read_volatile() as usize as *mut u8 }
}

/// timer_reset_4000 — original: `FUN_08217318` @ 0x08217318
/// (40 bytes; 24 call sites = 22 unconditional `bl` + 2 `blne`).
///
/// Stops the controller's +0xb8 timer, reprograms its delay to 4000 ms, and
/// re-arms it, reloading the timer field before each helper just as the
/// original's three `ldr r0, [r4, #0xb8]` instructions do.
///
/// # Safety
///
/// `this` must be readable through +0xbb. Its +0xb8 field is a 32-bit target
/// pointer that must be non-NULL and name a timer object valid for the
/// ported timer helpers; stock has no NULL guard and neither does the port.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_reset_4000(this: *mut u8) {
    unsafe { timer_stop(timer(this)) };
    unsafe { timer_start_after(timer(this), RESET_DELAY_MS) };
    unsafe { timer_restart(timer(this)) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use crate::drivers::timer::{
        TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use std::sync::{LazyLock, Mutex};
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    const TIMER_A_OFFSET: usize = 0x100;
    const TIMER_B_OFFSET: usize = 0x200;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Trace(usize),
        Arm(usize),
    }

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
    static mut SWAP_THIS: usize = 0;
    static mut SWAP_TARGET: usize = 0;

    /// Target-size layout through the 0x2c bytes the timer helpers touch.
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
        this: *mut ResetTimerFields,
        timer_a: *mut TimerObject,
        timer_b: *mut TimerObject,
    }

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TIMER_RESET_4000, SLAB_LEN).map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<Fixture> {
        let base = (*SLAB)? as *mut u8;
        Some(unsafe {
            Fixture {
                base,
                this: base.cast::<ResetTimerFields>(),
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

    unsafe extern "C" fn recording_trace(timer: *mut u8) {
        record(Event::Trace(timer as usize));
        let this = unsafe { SWAP_THIS } as *mut u8;
        let target = unsafe { SWAP_TARGET };
        if !this.is_null() && target != 0 {
            // First trace only: swap the controller's timer field mid-stop,
            // then consume the swap so later reloads see a stable field.
            unsafe { SWAP_THIS = 0 };
            unsafe {
                addr_of_mut!((*this.cast::<ResetTimerFields>()).timer).write(target as u32)
            };
        }
    }

    unsafe extern "C" fn recording_arm(timer: *mut u8) {
        record(Event::Arm(timer as usize));
    }

    /// Restores the shared timer ops seam while the test lock is held.
    struct OpsRestore(TimerOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }

    unsafe fn install_recording_ops() -> OpsRestore {
        let timer_ops = unsafe { core::ptr::addr_of!(TIMER_OPS).read_volatile() };
        let mut recorded = timer_ops;
        recorded.trace_assert = recording_trace;
        recorded.arm_timer = recording_arm;
        unsafe { core::ptr::addr_of_mut!(TIMER_OPS).write_volatile(recorded) };
        OpsRestore(timer_ops)
    }

    unsafe fn reset_fixture(fixture: Fixture) {
        unsafe { fixture.base.write_bytes(0, SLAB_LEN) };
        unsafe { SWAP_THIS = 0 };
        unsafe { SWAP_TARGET = 0 };
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }

    #[test]
    fn reprograms_the_timer_to_4000ms_and_rearms_it() {
        let _timer_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(fixture) = fixture() else {
            assert!(note_missing_u32_fixture("app::timer_reset"));
            return;
        };
        unsafe {
            reset_fixture(fixture);
            addr_of_mut!((*fixture.this).timer).write(fixture.timer_a as u32);
            let _restore = install_recording_ops();

            timer_reset_4000(fixture.this.cast());

            assert_eq!(
                addr_of!((*fixture.timer_a).period).read_volatile(),
                RESET_DELAY_MS,
                "start_after stores the fixed 4000 ms delay"
            );
            assert_eq!(
                addr_of!((*fixture.timer_a).state).read_volatile(),
                TIMER_STATE_RUNNING,
                "restart leaves the timer in the retailOS 'run ' state"
            );
            assert_eq!(
                events(),
                std::vec![
                    Event::Trace(fixture.timer_a as usize),
                    Event::Trace(fixture.timer_a as usize),
                    Event::Trace(fixture.timer_a as usize),
                    Event::Trace(fixture.timer_a as usize),
                    Event::Arm(fixture.timer_a as usize),
                ],
                "stop, start-after, then restart's stop+arm path all trace the same timer"
            );
        }
    }

    #[test]
    fn reloads_the_timer_field_before_each_helper() {
        let _timer_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(fixture) = fixture() else {
            assert!(note_missing_u32_fixture("app::timer_reset"));
            return;
        };
        unsafe {
            reset_fixture(fixture);
            addr_of_mut!((*fixture.this).timer).write(fixture.timer_a as u32);
            let _restore = install_recording_ops();
            // The stop's trace swaps +0xb8 to timer_b; the later helpers must
            // observe the replacement because the field is reloaded.
            SWAP_THIS = fixture.this as usize;
            SWAP_TARGET = fixture.timer_b as usize;

            timer_reset_4000(fixture.this.cast());

            assert_eq!(
                addr_of!((*fixture.timer_a).state).read_volatile(),
                TIMER_STATE_STOPPED,
                "the original timer is the one the stop ran on"
            );
            assert_eq!(
                addr_of!((*fixture.timer_b).period).read_volatile(),
                RESET_DELAY_MS,
                "the replacement timer received the 4000 ms delay"
            );
            assert_eq!(
                addr_of!((*fixture.timer_b).state).read_volatile(),
                TIMER_STATE_RUNNING,
                "the replacement timer is the one restart armed"
            );
            assert_eq!(
                events(),
                std::vec![
                    Event::Trace(fixture.timer_a as usize),
                    Event::Trace(fixture.timer_b as usize),
                    Event::Trace(fixture.timer_b as usize),
                    Event::Trace(fixture.timer_b as usize),
                    Event::Arm(fixture.timer_b as usize),
                ],
                "only the stop saw timer_a; both reloads observed the swap"
            );
        }
    }
}
