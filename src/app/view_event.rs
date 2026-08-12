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
//! Both callees are unported and ride the [`VIEW_EVENT_OPS`] seam (the
//! event_list.rs pattern: transmuted firmware defaults on target,
//! panicking defaults on host, recording mocks in tests), so this port
//! is hook-ready on target. Note the original tests +0x50 here AND the
//! wrapper re-tests it — the double test is reproduced, not folded.

use core::ptr::{addr_of, addr_of_mut};

/// Byte offset of the view's optional timer pointer (`ldr r0, [r0,
/// #0x50]`).
pub const VIEW_TIMER: usize = 0x50;
/// Byte offset of the staged-flag collection the epilogue commits
/// (`add r1, r0, #0x60` in FUN_0810e170).
pub const VIEW_STAGED_FLAGS: usize = 0x60;

/// The framework's "event handled" verdict (`mov r0, #1`).
pub const EVENT_HANDLED: u32 = 1;

/// Unported firmware helpers below the epilogue (see the module header).
#[derive(Clone, Copy)]
pub struct ViewEventOps {
    /// `FUN_0810dfe8` @ 0x0810dfe8: stop the view's +0x50 timer if one
    /// is installed (tail-branch into the ported `timer_stop`).
    pub stop_view_timer: unsafe extern "C" fn(this: *mut u8),
    /// `FUN_0810e170` @ 0x0810e170: commit the staged flag bytes from
    /// the +0x60 collection into the global byte table.
    pub commit_staged_flags: unsafe extern "C" fn(this: *mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_stop_view_timer(this: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x0810_dfe8usize) };
    unsafe { f(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_stop_view_timer(_this: *mut u8) {
    panic!("view_event_complete requires view-timer stop 0x0810dfe8")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_commit_staged_flags(this: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x0810_e170usize) };
    unsafe { f(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_commit_staged_flags(_this: *mut u8) {
    panic!("view_event_complete requires staged-flag commit 0x0810e170")
}

/// Active helpers. retailOS defaults invoke the firmware functions
/// directly; host tests replace the table with recording mocks.
#[cfg(target_os = "none")]
pub static mut VIEW_EVENT_OPS: ViewEventOps = ViewEventOps {
    stop_view_timer: firmware_stop_view_timer,
    commit_staged_flags: firmware_commit_staged_flags,
};

#[cfg(not(target_os = "none"))]
pub static mut VIEW_EVENT_OPS: ViewEventOps = ViewEventOps {
    stop_view_timer: missing_stop_view_timer,
    commit_staged_flags: missing_commit_staged_flags,
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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the tests that swap the ops table.
    static VIEW_LOCK: Mutex<()> = Mutex::new(());

    /// Calls into the mock helpers, in order.
    static mut CALLS: Vec<&'static str> = Vec::new();

    /// The `this` pointer each mock observed, in order.
    static mut SEEN: Vec<*mut u8> = Vec::new();

    /// A stand-in view record (timer word at +0x50).
    static mut VIEW: [u8; 0x54] = [0; 0x54];

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

    /// Installs the recording mocks and sets the view's timer word.
    fn mock(timer: u32) -> MutexGuard<'static, ()> {
        let guard = VIEW_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            VIEW_EVENT_OPS = ViewEventOps {
                stop_view_timer: recording_stop,
                commit_staged_flags: recording_commit,
            };
            (*addr_of_mut!(CALLS)).clear();
            (*addr_of_mut!(SEEN)).clear();
            (*addr_of_mut!(VIEW)).fill(0);
            (addr_of_mut!(VIEW) as *mut u32)
                .add(VIEW_TIMER / 4)
                .write_volatile(timer);
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            VIEW_EVENT_OPS = ViewEventOps {
                stop_view_timer: missing_stop_view_timer,
                commit_staged_flags: missing_commit_staged_flags,
            };
        }
        drop(guard);
    }

    fn view() -> *mut u8 {
        unsafe { addr_of_mut!(VIEW) as *mut u8 }
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
}
