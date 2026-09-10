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

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};
use crate::app::string_table::string_table_has_string;
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

/// Byte offsets of the two localized integer flags written by
/// [`view_event_apply_localized_flags`].
const VIEW_LOCALIZED_FLAG_A: usize = 0xb0;
const VIEW_LOCALIZED_FLAG_B: usize = 0xb1;

/// Resolves retailOS global inputs needed by
/// [`view_event_apply_localized_flags`].
#[derive(Clone, Copy)]
pub struct ViewLocalizedFlagOps {
    /// Loads a NUL-terminated key from the configuration object at word 3
    /// (`+0x0c`) or word 4 (`+0x10`).
    pub configuration_key: unsafe extern "C" fn(word_index: usize) -> *const u8,
    /// Loads the localized string-table singleton.
    pub string_table: unsafe extern "C" fn() -> *mut u8,
    /// `FUN_08102168`: resolves `key` in `table` then parses its value as
    /// signed decimal (`"%d"`), returning the resulting 32-bit bit pattern.
    pub string_table_parse_i32: unsafe extern "C" fn(table: *mut u8, key: *const u32) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_configuration_key(word_index: usize) -> *const u8 {
    // `DAT_08219380` appears in the body as literal 0x089cfe4c. Its
    // pointer fields are target words, so index rather than host byte
    // offsets preserves the retail 32-bit layout.
    let configuration = unsafe { (0x089c_fe4c as *const u32).read_volatile() as *const u32 };
    unsafe { configuration.add(word_index).read() as usize as *const u8 }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_configuration_key(_word_index: usize) -> *const u8 {
    panic!("view_event_apply_localized_flags requires configuration 0x089cfe4c")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_localized_string_table() -> *mut u8 {
    // Literal 0x08a79c10 at 0x08219384 is the string-table singleton word.
    unsafe { (0x08a7_9c10 as *const u32).read_volatile() as usize as *mut u8 }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_localized_string_table() -> *mut u8 {
    panic!("view_event_apply_localized_flags requires string table 0x08a79c10")
}


#[cfg(target_os = "none")]
pub const DEFAULT_VIEW_LOCALIZED_FLAG_OPS: ViewLocalizedFlagOps = ViewLocalizedFlagOps {
    configuration_key: firmware_configuration_key,
    string_table: firmware_localized_string_table,
    string_table_parse_i32: crate::app::string_table::string_table_parse_i32,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_VIEW_LOCALIZED_FLAG_OPS: ViewLocalizedFlagOps = ViewLocalizedFlagOps {
    configuration_key: missing_configuration_key,
    string_table: missing_localized_string_table,
    string_table_parse_i32: crate::app::string_table::string_table_parse_i32,
};

/// Active dependencies of [`view_event_apply_localized_flags`]. Target
/// defaults read the real globals and call the ported integer parser; host
/// tests install fixtures.
pub static mut VIEW_LOCALIZED_FLAG_OPS: ViewLocalizedFlagOps = DEFAULT_VIEW_LOCALIZED_FLAG_OPS;

/// view_event_apply_localized_flags — original: `FUN_0826087c` @
/// **0x0826087c** (a 4-byte `b 0x082192a0` entry veneer; its 224-byte
/// reached body is 0x082192a0..0x0821937c, followed by two literal words).
///
/// Decoding every aligned ARM B/BL word in `osos.dec` finds **11 direct
/// `bl` call sites**, all unconditional, no predicated forms, and one
/// data-word reference at 0x089b06cc (a virtual-method table entry).
///
/// When `event` is non-NULL, builds temporary COW strings from configuration
/// keys at `DAT_08219380 + 0x0c` and `+0x10`; for each key present in the
/// `DAT_08219384` localization table, resolves/parses its `"%d"` value and
/// stores its low byte at `this + 0xb0` or `+0xb1`, then releases the
/// temporary. It finally delegates to
/// [`view_event_apply_mapped_staged_flags`] and returns that handled verdict.
///
/// Deliberate deviations: host-safe key/global access uses an ops table
/// because retail pointers are 32-bit words. The COW constructors/releases,
/// membership test, and integer parser are direct Rust ports. Rust represents
/// the final tail branch as a call.
///
/// # Safety
///
/// `this` must be valid through `+0xb1`; when `event` is non-NULL, every
/// configured key and the string table must satisfy the called helpers'
/// unchecked-pointer contracts, exactly as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_event_apply_localized_flags(
    this: *mut u8,
    event: *mut u8,
) -> u32 {
    if !event.is_null() {
        let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VIEW_LOCALIZED_FLAG_OPS)) };
        let table = unsafe { (ops.string_table)() };

        let mut first_key = core::ptr::null_mut();
        unsafe { cxx_string_from_cstr(&mut first_key, (ops.configuration_key)(3)) };
        if unsafe { string_table_has_string(table, (&first_key as *const *mut u8).cast()) } != 0 {
            unsafe {
                this.add(VIEW_LOCALIZED_FLAG_A)
                    .write((ops.string_table_parse_i32)(table, (&first_key as *const *mut u8).cast()) as u8);
            }
        }
        unsafe { cxx_string_release(&mut first_key) };

        let mut second_key = core::ptr::null_mut();
        unsafe { cxx_string_from_cstr(&mut second_key, (ops.configuration_key)(4)) };
        if unsafe { string_table_has_string(table, (&second_key as *const *mut u8).cast()) } != 0 {
            unsafe {
                this.add(VIEW_LOCALIZED_FLAG_B)
                    .write((ops.string_table_parse_i32)(table, (&second_key as *const *mut u8).cast()) as u8);
            }
        }
        unsafe { cxx_string_release(&mut second_key) };
    }
    unsafe { view_event_apply_mapped_staged_flags(this) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::string_table::{StringTableOps, STRING_TABLE_OPS};
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, STRING_TABLE_OPS_TEST_LOCK,
        TIMER_OPS_TEST_LOCK, VIEW_EVENT_OPS_TEST_LOCK as VIEW_LOCK,
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

    const LOCALIZED_SLAB_LEN: usize = 0x1000;
    const LOCALIZED_HEADER_CURRENT: usize = 0x100;
    const LOCALIZED_HEADER_FALLBACK: usize = 0x120;
    const LOCALIZED_NODE: usize = 0x200;
    const LOCALIZED_REP_SIZE: usize = 0x300;

    static LOCALIZED_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::VIEW_EVENT_LOCALIZED_FLAGS, LOCALIZED_SLAB_LEN)
            .map(|pointer| pointer as usize)
    });
    static mut LOCALIZED_TABLE: usize = 0;
    static mut LOCALIZED_FIND_INDEX: usize = 0;
    static mut LOCALIZED_FIND_RESULTS: [u32; 3] = [0; 3];
    static mut LOCALIZED_PARSE_CALLS: u32 = 0;

    static FIRST_LOCALIZED_KEY: &[u8] = b"\0";
    static SECOND_LOCALIZED_KEY: &[u8] = b"\0";

    #[repr(align(4))]
    struct LocalizedView([u8; VIEW_LOCALIZED_FLAG_B + 1]);

    unsafe extern "C" fn localized_configuration_key(word_index: usize) -> *const u8 {
        match word_index {
            3 => FIRST_LOCALIZED_KEY.as_ptr(),
            4 => SECOND_LOCALIZED_KEY.as_ptr(),
            _ => core::ptr::null(),
        }
    }

    unsafe extern "C" fn localized_string_table() -> *mut u8 {
        unsafe { *addr_of!(LOCALIZED_TABLE) as *mut u8 }
    }

    unsafe extern "C" fn localized_find(out: *mut u32, _map: *mut u8, _key: *const u32) {
        unsafe {
            out.write((*addr_of!(LOCALIZED_FIND_RESULTS))[*addr_of!(LOCALIZED_FIND_INDEX)]);
            *addr_of_mut!(LOCALIZED_FIND_INDEX) += 1;
        }
    }

    unsafe extern "C" fn localized_string_empty(string: *const u32) -> u32 {
        unsafe {
            (((string.read() as usize - 4) as *const u32).read() == 0) as u32
        }
    }

    unsafe extern "C" fn localized_parse_i32(_table: *mut u8, _key: *const u32) -> u32 {
        unsafe {
            *addr_of_mut!(LOCALIZED_PARSE_CALLS) += 1;
        }
        0x1234
    }

    struct LocalizedSeamRestore {
        localized_flags: ViewLocalizedFlagOps,
        string_table: StringTableOps,
        view_event: ViewEventOps,
    }

    impl Drop for LocalizedSeamRestore {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(VIEW_LOCALIZED_FLAG_OPS).write_volatile(self.localized_flags);
                addr_of_mut!(STRING_TABLE_OPS).write_volatile(self.string_table);
                addr_of_mut!(VIEW_EVENT_OPS).write_volatile(self.view_event);
            }
        }
    }

    unsafe fn install_localized_seams(table: *mut u8) -> LocalizedSeamRestore {
        let restore = LocalizedSeamRestore {
            localized_flags: addr_of!(VIEW_LOCALIZED_FLAG_OPS).read_volatile(),
            string_table: addr_of!(STRING_TABLE_OPS).read_volatile(),
            view_event: addr_of!(VIEW_EVENT_OPS).read_volatile(),
        };
        *addr_of_mut!(LOCALIZED_TABLE) = table as usize;
        *addr_of_mut!(LOCALIZED_FIND_INDEX) = 0;
        *addr_of_mut!(LOCALIZED_PARSE_CALLS) = 0;
        addr_of_mut!(VIEW_LOCALIZED_FLAG_OPS).write_volatile(ViewLocalizedFlagOps {
            configuration_key: localized_configuration_key,
            string_table: localized_string_table,
            string_table_parse_i32: localized_parse_i32,
        });
        addr_of_mut!(STRING_TABLE_OPS).write_volatile(StringTableOps {
            find: localized_find,
            iter_eq: crate::cxx::templates::iterator_equal,
            string_empty: localized_string_empty,
        });
        let mut event_ops = restore.view_event;
        event_ops.apply_mapped_staged_flags = recording_mapped_apply;
        addr_of_mut!(VIEW_EVENT_OPS).write_volatile(event_ops);
        restore
    }

    fn localized_table_fixture() -> Option<*mut u8> {
        let table = (*LOCALIZED_SLAB)? as *mut u8;
        unsafe {
            table.write_bytes(0, LOCALIZED_SLAB_LEN);
            let word = |offset: usize| table.add(offset).cast::<u32>();
            word(0x10).write(table.add(LOCALIZED_HEADER_CURRENT) as usize as u32);
            word(0x48).write(table.add(LOCALIZED_HEADER_FALLBACK) as usize as u32);
            word(LOCALIZED_NODE + 0x14).write(table.add(LOCALIZED_REP_SIZE + 4) as usize as u32);
            word(LOCALIZED_REP_SIZE).write(1);
            *addr_of_mut!(LOCALIZED_FIND_RESULTS) = [
                table.add(LOCALIZED_NODE) as usize as u32,
                table.add(LOCALIZED_HEADER_CURRENT) as usize as u32,
                table.add(LOCALIZED_HEADER_FALLBACK) as usize as u32,
            ];
        }
        Some(table)
    }

    #[test]
    fn localized_flags_only_parse_present_keys_then_apply_mapped_flags() {
        let _view_lock = VIEW_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _string_table_lock = STRING_TABLE_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(table) = localized_table_fixture() else {
            assert!(note_missing_u32_fixture("app::view_event::localized_flags"));
            return;
        };
        let _restore = unsafe { install_localized_seams(table) };
        let mut view = LocalizedView([0; VIEW_LOCALIZED_FLAG_B + 1]);
        view.0[VIEW_LOCALIZED_FLAG_B] = 0xa5;
        unsafe {
            (*addr_of_mut!(CALLS)).clear();
            (*addr_of_mut!(SEEN)).clear();
            assert_eq!(
                view_event_apply_localized_flags(view.0.as_mut_ptr(), 1usize as *mut u8),
                EVENT_HANDLED
            );
            assert_eq!(view.0[VIEW_LOCALIZED_FLAG_A], 0x34, "low byte of parsed value");
            assert_eq!(
                view.0[VIEW_LOCALIZED_FLAG_B], 0xa5,
                "the missing second key leaves its flag unchanged"
            );
            assert_eq!(*addr_of!(LOCALIZED_PARSE_CALLS), 1);
            assert_eq!(*addr_of!(LOCALIZED_FIND_INDEX), 3, "hit then miss/fallback");
            assert_eq!(*addr_of!(CALLS), std::vec!["mapped apply"]);
            assert_eq!(*addr_of!(SEEN), std::vec![view.0.as_mut_ptr()]);
        }
    }

    #[test]
    fn localized_flags_skip_configuration_for_a_null_event() {
        let guard = mock(0);
        let mut view = LocalizedView([0; VIEW_LOCALIZED_FLAG_B + 1]);
        view.0[VIEW_LOCALIZED_FLAG_A] = 0x5a;
        view.0[VIEW_LOCALIZED_FLAG_B] = 0xa5;
        unsafe {
            assert_eq!(
                view_event_apply_localized_flags(view.0.as_mut_ptr(), core::ptr::null_mut()),
                EVENT_HANDLED
            );
            assert_eq!(view.0[VIEW_LOCALIZED_FLAG_A], 0x5a);
            assert_eq!(view.0[VIEW_LOCALIZED_FLAG_B], 0xa5);
            assert_eq!(*addr_of!(CALLS), std::vec!["mapped apply"]);
            assert_eq!(*addr_of!(SEEN), std::vec![view.0.as_mut_ptr()]);
        }
        restore(guard);
    }
}
