//! `view_event_complete` — the shared event-handler epilogue of the
//! retailOS view/controller base class.
//!
//! Original: `FUN_0810dfc0` @ 0x0810dfc0 (40 bytes exactly,
//! 0x0810dfc0..0x0810dfe8 — ten instructions, no literal pool; the
//! view-timer-stop wrapper opens immediately after. 98 call sites
//! binary-scanned: 52 `bl` + 46 `b`).
//!
//! # Algorithm
//!
//! ```text
//! if *(u32 *)(this + 0x50) != 0:      ; the view owns a timer
//!     FUN_0810dfe8(this)              ; stop it
//! FUN_0810e170(this)                  ; commit the staged flag writes
//! return 1                            ; "event handled"
//! ```
//!
//! r1 is never touched: the argument the tail-calling handlers leave in
//! r1 flows through dead (both callees overwrite or ignore it), so the
//! recovered ABI is one argument.
//!
//! # What it is (call-site evidence)
//!
//! All 98 sites are UI view/controller event handlers across
//! 0x080fxxxx..0x0827xxxx that finish with `mov r1, <arg>; mov r0,
//! this; b 0x0810dfc0` (or `bl` and forward the result): each handler
//! runs its specific work, then tails into this shared epilogue. The
//! two callees:
//!
//! - `FUN_0810dfe8` (the very next function, 12 bytes) is the view's
//!   timer stop: `ldr r0, [r0, #0x50]; cmp r0, #0; bne 0x0812c6b0` —
//!   fetch the view's timer at +0x50 and tail-branch to the ported
//!   `timer_stop` (drivers/timer) when one exists. (Ghidra's decompile
//!   inlines timer_stop's body, which makes the wrapper look bigger
//!   than it is; the ARM is three instructions.)
//! - `FUN_0810e170` @ 0x0810e170 walks the view's collection at +0x60
//!   with the ported util/cursor family (cursor_init 0x081ee17c /
//!   cursor_advance 0x081ee138 / cursor_invalidate 0x081ee18c) and, per
//!   item, stores `item.byte2` into the global byte table @ 0x08a77a8f
//!   at index `item.byte0` (`bl 0x0819c9d0`, the table's byte setter —
//!   indices 0x71..0x77 are special-cased in its sibling @ 0x0819c77c):
//!   the commit of the flag bytes the handler staged during the event.
//!
//! The `1` return is the framework's "handled" verdict — consuming
//! sites forward it verbatim (e.g. `mov r6, r0; ...; mov r0, r6` @
//! 0x0839f6d0, `mov r4, r0; ...; mov r0, r4` @ 0x08125678).
//!
//! The stop helper is ported and wired into the default [`VIEW_EVENT_OPS`]
//! slot; the staged-flag commit helper still rides the seam (the
//! `event_list.rs` pattern: transmuted firmware defaults on target,
//! panicking defaults on host, recording mocks in tests), so this port
//! is hook-ready on target. Note the original tests +0x50 here AND the
//! wrapper re-tests it — the double test is reproduced, not folded.

use core::ptr::addr_of_mut;

use crate::drivers::timer::timer_stop;

/// Byte offset of the view's optional timer pointer (`ldr r0, [r0,
/// #0x50]`).
pub const VIEW_TIMER: usize = 0x50;
/// Byte offset of the staged-flag collection the epilogue commits
/// (`add r1, r0, #0x60` in FUN_0810e170).
pub const VIEW_STAGED_FLAGS: usize = 0x60;

/// The framework's "event handled" verdict (`mov r0, #1`).
pub const EVENT_HANDLED: u32 = 1;

/// Helper slots below the epilogue (see the module header).
#[derive(Clone, Copy)]
pub struct ViewEventOps {
    /// `FUN_0810dfe8` @ 0x0810dfe8: stop the view's +0x50 timer if one
    /// is installed.
    pub stop_view_timer: unsafe extern "C" fn(this: *mut u8),
    /// `FUN_0810e170` @ 0x0810e170: commit the staged flag bytes from
    /// the +0x60 collection into the global byte table.
    pub commit_staged_flags: unsafe extern "C" fn(this: *mut u8),
    /// `FUN_0810e1c4` @ 0x0810e1c4: map each staged flag's selector into
    /// byte 2, then commit its byte 1 value to the global flag table.
    pub apply_mapped_staged_flags: unsafe extern "C" fn(this: *mut u8),
}

/// `stop_view_timer` — original: `FUN_0810dfe8` @ 0x0810dfe8 (12
/// bytes; 21 `bl` call sites).
///
/// Loads the view's optional timer pointer at +0x50 and, when it is
/// non-NULL, calls the ported `timer_stop` on that timer. Otherwise it
/// returns immediately. The original body is just `ldr r0, [r0, #0x50];
/// cmp r0, #0; bne 0x0812c6b0; bx lr`; the only deliberate deviation is
/// that Rust spells the tail branch as an indirect call through a
/// volatile function-pointer load so LLVM keeps the body separate.
///
/// # Safety
///
/// `this` must point to readable storage through +0x50; the timer
/// pointer is loaded unchecked, exactly as in the original.
static STOP_VIEW_TIMER: unsafe extern "C" fn(*mut u8) = timer_stop;

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stop_view_timer(this: *mut u8) {
    let timer = (this.add(VIEW_TIMER) as *const u32).read_volatile();
    if timer != 0 {
        let stop = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STOP_VIEW_TIMER)) };
        unsafe { stop(timer as usize as *mut u8) };
    }
}

/// `FUN_0810e170` @ 0x0810e170: commit the staged flag bytes from the
/// +0x60 collection into the global byte table.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_commit_staged_flags(this: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x0810_e170usize) };
    unsafe { f(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_commit_staged_flags(_this: *mut u8) {
    panic!("view_event_complete requires staged-flag commit 0x0810e170")
}

/// `FUN_0810e1c4` @ 0x0810e1c4: map staged flag selectors, then commit
/// their byte 1 values to the global flag table.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_apply_mapped_staged_flags(this: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x0810_e1c4usize) };
    unsafe { f(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_apply_mapped_staged_flags(_this: *mut u8) {
    panic!("view_event_apply_mapped_staged_flags requires flag apply 0x0810e1c4")
}

/// Active helpers. retailOS defaults invoke the ported stop helper and the
/// two unported staged-flag helpers directly; host tests replace the table
/// with recording mocks.
#[cfg(target_os = "none")]
pub static mut VIEW_EVENT_OPS: ViewEventOps = ViewEventOps {
    stop_view_timer,
    commit_staged_flags: firmware_commit_staged_flags,
    apply_mapped_staged_flags: firmware_apply_mapped_staged_flags,
};

#[cfg(not(target_os = "none"))]
pub static mut VIEW_EVENT_OPS: ViewEventOps = ViewEventOps {
    stop_view_timer,
    commit_staged_flags: missing_commit_staged_flags,
    apply_mapped_staged_flags: missing_apply_mapped_staged_flags,
};

/// view_event_complete — original: `FUN_0810dfc0` @ 0x0810dfc0
/// (40 bytes; 52 `bl` + 46 `b` call sites).
///
/// If the view's timer word at +0x50 is non-NULL, stops the timer
/// through the +0x50 re-testing wrapper; then commits the staged flag
/// writes unconditionally; returns 1 ("handled"). See the module
/// header for the call-site evidence and the seam contract.
///
/// # Safety
///
/// `this` must point into a readable allocation covering the word at
/// +0x50; it is dereferenced unchecked, as in the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_event_complete(this: *mut u8) -> u32 {
    if (this.add(VIEW_TIMER) as *const u32).read_volatile() != 0 {
        // The slot read stays on the cold path, where the original's
        // conditional `blne` sits.
        let stop = unsafe { addr_of_mut!(VIEW_EVENT_OPS.stop_view_timer).read_volatile() };
        unsafe { stop(this) };
    }
    let commit = unsafe { addr_of_mut!(VIEW_EVENT_OPS.commit_staged_flags).read_volatile() };
    unsafe { commit(this) };
    EVENT_HANDLED
}

/// view_event_apply_mapped_staged_flags — original: `FUN_0810de48` @
/// 0x0810de48 (16 bytes exactly; 19 plain `bl` and 75 plain tail `b`
/// call sites, binary-scanned by decoding every ARM B/BL word in
/// `osos.dec`).
///
/// Calls `FUN_0810e1c4(this)`, which walks the staged flag collection at
/// `this+0x60`: it maps each item byte 0 through the table accessor at
/// 0x0819c7a4 into byte 2, then stores byte 1 in the global flag-byte
/// table at the original byte-0 index. Returns 1, the framework's handled
/// verdict. The 19 `bl` call sites are all unconditional; caller-side
/// predicates do not gate this handler. `r1` passes through the 16-byte
/// wrapper but the callee saves without reading it, so the recovered ABI
/// takes only `this`.
///
/// Deliberate deviation: the not-yet-ported 0x0810e1c4 body remains an
/// explicit ops-table seam. Target builds dispatch to its firmware address;
/// host tests install a recording replacement.
///
/// # Safety

///
/// `this` must be valid for the callee's staged-flag collection accesses,
/// exactly as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_event_apply_mapped_staged_flags(this: *mut u8) -> u32 {
    let apply = unsafe { addr_of_mut!(VIEW_EVENT_OPS.apply_mapped_staged_flags).read_volatile() };
    unsafe { apply(this) };
    EVENT_HANDLED
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK,
        VIEW_EVENT_OPS_TEST_LOCK as VIEW_LOCK,
    };
    use std::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, MutexGuard};
    use std::vec::Vec;

    /// Calls into the mock helpers, in order.
    static mut CALLS: Vec<&'static str> = Vec::new();

    /// The `this` pointer each mock observed, in order.
    static mut SEEN: Vec<*mut u8> = Vec::new();

    #[repr(align(4))]
    struct View([u8; 0x54]);

    static mut VIEW: View = View([0; 0x54]);

    unsafe extern "C" fn recording_stop(this: *mut u8) {
        unsafe {
            (*addr_of_mut!(CALLS)).push("stop");
            (*addr_of_mut!(SEEN)).push(this);
        }
    }

    unsafe extern "C" fn recording_commit(this: *mut u8) {
        unsafe {
            (*addr_of_mut!(CALLS)).push("commit");
            (*addr_of_mut!(SEEN)).push(this);
        }
    }

    unsafe extern "C" fn recording_mapped_apply(this: *mut u8) {
        unsafe {
            (*addr_of_mut!(CALLS)).push("mapped apply");
            (*addr_of_mut!(SEEN)).push(this);
        }
    }

    /// Installs the recording mocks and sets the view's timer word.
    fn mock(timer: u32) -> MutexGuard<'static, ()> {
        let guard = VIEW_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            VIEW_EVENT_OPS = ViewEventOps {
                stop_view_timer: recording_stop,
                commit_staged_flags: recording_commit,
                apply_mapped_staged_flags: recording_mapped_apply,
            };
            (*addr_of_mut!(CALLS)).clear();
            (*addr_of_mut!(SEEN)).clear();
            (*addr_of_mut!(VIEW)).0.fill(0);
            (addr_of_mut!(VIEW) as *mut u32)
                .add(VIEW_TIMER / 4)
                .write_volatile(timer);
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            VIEW_EVENT_OPS = ViewEventOps {
                stop_view_timer,
                commit_staged_flags: missing_commit_staged_flags,
                apply_mapped_staged_flags: missing_apply_mapped_staged_flags,
            };
        }
        drop(guard);
    }

    fn view() -> *mut u8 {
        unsafe { addr_of_mut!(VIEW) as *mut u8 }
    }

    const STOP_SLAB_LEN: usize = 0x1000;
    const STOP_TIMER_OFFSET: usize = 0x100;

    #[repr(C)]
    struct StopViewFields {
        _prefix: [u8; 0x50],
        timer: u32,
    }

    #[repr(C)]
    struct StopTimerObject {
        _next: u32,
        period: u32,
        _deadline: u32,
        _opaque_0c: [u8; 0x0c],
        _queued_state: u32,
        _armed: u32,
        state: u32,
        _callback_handle: u32,
    }

    #[derive(Clone, Copy)]
    struct StopFixture {
        base: *mut u8,
        view: *mut StopViewFields,
        timer: *mut StopTimerObject,
    }

    static STOP_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::VIEW_EVENT_TIMER_STOP, STOP_SLAB_LEN).map(|pointer| pointer as usize)
    });

    unsafe extern "C" fn recording_trace(timer: *mut u8) {
        unsafe {
            (*addr_of_mut!(STOP_CALLS)).push("trace");
            (*addr_of_mut!(STOP_SEEN)).push(timer as usize);
        }
    }

    static mut STOP_CALLS: Vec<&'static str> = Vec::new();
    static mut STOP_SEEN: Vec<usize> = Vec::new();

    struct TimerOpsRestore {
        timer_ops: TimerOps,
    }

    impl Drop for TimerOpsRestore {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(TIMER_OPS).write_volatile(self.timer_ops);
            }
        }
    }

    unsafe fn install_timer_trace_mock() -> TimerOpsRestore {
        let timer_ops = addr_of!(TIMER_OPS).read_volatile();
        let mut recorded = timer_ops;
        recorded.trace_assert = recording_trace;
        addr_of_mut!(TIMER_OPS).write_volatile(recorded);
        TimerOpsRestore { timer_ops }
    }

    fn stop_fixture() -> Option<StopFixture> {
        let base = (*STOP_SLAB)? as *mut u8;
        Some(unsafe {
            StopFixture {
                base,
                view: base.cast::<StopViewFields>(),
                timer: base.add(STOP_TIMER_OFFSET).cast::<StopTimerObject>(),
            }
        })
    }

    unsafe fn reset_stop_fixture(fixture: StopFixture, timer_word: u32, timer_state: u32) {
        fixture.base.write_bytes(0, STOP_SLAB_LEN);
        (*addr_of_mut!(STOP_CALLS)).clear();
        (*addr_of_mut!(STOP_SEEN)).clear();
        addr_of_mut!((*fixture.view).timer).write_volatile(timer_word);
        addr_of_mut!((*fixture.timer).state).write_volatile(timer_state);
    }

    #[test]
    fn stop_view_timer_stops_the_installed_timer() {
        let _timer_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(fixture) = stop_fixture() else {
            assert!(note_missing_u32_fixture("app::view_event::stop_view_timer"));
            return;
        };
        unsafe {
            reset_stop_fixture(fixture, fixture.timer as u32, TIMER_STATE_RUNNING);
            let _restore = install_timer_trace_mock();

            stop_view_timer(fixture.view.cast());

            assert_eq!(
                *addr_of!(STOP_CALLS),
                std::vec!["trace"],
                "timer_stop was reached exactly once"
            );
            assert_eq!(
                *addr_of!(STOP_SEEN),
                std::vec![fixture.timer as usize],
                "the view's timer pointer is passed through unchanged"
            );
            assert_eq!(
                addr_of!((*fixture.timer).state).read_volatile(),
                TIMER_STATE_STOPPED,
                "timer_stop writes the stopped state"
            );
        }
    }

    #[test]
    fn stop_view_timer_leaves_a_null_timer_alone() {
        let _timer_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(fixture) = stop_fixture() else {
            assert!(note_missing_u32_fixture("app::view_event::stop_view_timer"));
            return;
        };
        unsafe {
            reset_stop_fixture(fixture, 0, TIMER_STATE_RUNNING);
            let _restore = install_timer_trace_mock();

            stop_view_timer(fixture.view.cast());

            assert!(
                (*addr_of!(STOP_CALLS)).is_empty(),
                "null timers do not reach timer_stop"
            );
            assert!(
                (*addr_of!(STOP_SEEN)).is_empty(),
                "no timer pointer is recorded when the slot is empty"
            );
            assert_eq!(
                addr_of!((*fixture.timer).state).read_volatile(),
                TIMER_STATE_RUNNING,
                "the timer object is untouched when the slot is empty"
            );
        }
    }

    #[test]
    fn a_view_with_a_timer_stops_it_then_commits_and_reports_handled() {
        let guard = mock(0x0855_1234);
        unsafe {
            assert_eq!(view_event_complete(view()), 1, "the handled verdict");
            assert_eq!(
                *addr_of!(CALLS),
                std::vec!["stop", "commit"],
                "timer stop strictly before the flag commit"
            );
            assert_eq!(
                *addr_of!(SEEN),
                std::vec![view(), view()],
                "both callees receive the view itself"
            );
        }
        restore(guard);
    }

    #[test]
    fn a_view_without_a_timer_only_commits() {
        let guard = mock(0);
        unsafe {
            assert_eq!(view_event_complete(view()), 1, "handled either way");
            assert_eq!(
                *addr_of!(CALLS),
                std::vec!["commit"],
                "no timer, no stop — the commit is unconditional"
            );
            assert_eq!(*addr_of!(SEEN), std::vec![view()]);
        }
        restore(guard);
    }

    #[test]
    fn mapped_flag_handler_delegates_then_reports_handled() {
        let guard = mock(0);
        unsafe {
            assert_eq!(
                view_event_apply_mapped_staged_flags(view()),
                EVENT_HANDLED,
                "the wrapper reports handled after applying flags"
            );
            assert_eq!(
                *addr_of!(CALLS),
                std::vec!["mapped apply"],
                "the mapped-flag helper runs exactly once"
            );
            assert_eq!(
                *addr_of!(SEEN),
                std::vec![view()],
                "the original view pointer reaches the helper"
            );
        }
        restore(guard);
    }
}
