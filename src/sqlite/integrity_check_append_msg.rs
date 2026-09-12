//! Append one formatted integrity-check diagnostic to its accumulated text.
//!
//! - `integrity_check_append_msg` — original: `FUN_082c2438` @
//!   0x082c2438 (176 bytes; next function starts at 0x082c24f0, after the
//!   two-word literal pool at 0x082c24e8).
//! - Binary decoding finds 14 direct `bl` callers: 11 unconditional and
//!   three `blne` (0x082c2bec, 0x08371a74, 0x08371abc). The conditional
//!   callers gate diagnostic production on their mismatch predicate; this
//!   callee only gates its work on `mx_err`, not on its context pointer.
//!
//! Algorithm: while `mx_err` is nonzero, decrement it, increment `n_err`,
//! format the supplied varargs with SQLite's NULL-db formatter, and replace
//! `z_err_msg`. A NULL prefix becomes `""`. For an existing message, detach
//! the old pointer, concatenate `old + "\n" + prefix + formatted`, then free
//! the old and formatted temporary strings in that order. A fresh accumulator
//! receives `prefix + formatted`. A formatter NULL simply terminates the
//! list passed to `sqlite3SetString`, preserving the non-NULL earlier pieces.
//!
//! Deliberate deviations: C varargs are the explicit [`VaList`] pointer used
//! throughout this crate, and the unported formatter runs through the shared
//! `SQLITE_VM_PRINTF` dispatch seam. `sqlite3SetString` and `sqlite3_free`
//! are already ported and are called directly.

use crate::heap::tracked::tracked_free;
use super::error_msg::{vm_printf_op, VaList};
use super::set_string::sqlite3_set_string;

const EMPTY_PREFIX: &[u8; 1] = b"\0";
const NEWLINE: &[u8; 2] = b"\n\0";

/// The integrity-check state fields touched by `checkAppendMsg`.
#[repr(C)]
pub struct IntegrityCheck {
    /// +0x00: shared b-tree whose pointer map this check validates.
    pub p_bt: *mut u8,
    /// +0x04: owning pager; not touched by the ported routines here.
    pub _p_pager: *mut u8,
    /// +0x08: page count recorded when the check began.
    pub _n_page: i32,
    /// +0x0c: per-page reference counts.
    pub _an_ref: *mut i32,
    /// +0x10: remaining diagnostics allowed.
    pub mx_err: i32,
    /// +0x14: accumulated heap-owned diagnostic text.
    pub z_err_msg: *mut u8,
    /// +0x18: emitted diagnostic count.
    pub n_err: i32,
}

// Pointer width makes host offsets differ; the target layout is exact.
#[cfg(target_pointer_width = "32")]
const _INTEGRITY_CHECK_MX_ERR_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(IntegrityCheck, mx_err)];
#[cfg(target_pointer_width = "32")]
const _INTEGRITY_CHECK_Z_ERR_MSG_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(IntegrityCheck, z_err_msg)];
#[cfg(target_pointer_width = "32")]
const _INTEGRITY_CHECK_N_ERR_OFFSET: [u8; 0x18] = [0; core::mem::offset_of!(IntegrityCheck, n_err)];

// `sqlite3_set_string` consumes target-width pointer words. ARM literals are
// naturally target-width; tests substitute low mapped copies so host pointer
// truncation cannot hide a broken list.
#[cfg(test)]
static mut HOST_EMPTY_PREFIX: *const u8 = core::ptr::null();
#[cfg(test)]
static mut HOST_NEWLINE: *const u8 = core::ptr::null();

#[inline(always)]
fn empty_prefix() -> *const u8 {
    #[cfg(test)]
    unsafe {
        return core::ptr::read(core::ptr::addr_of!(HOST_EMPTY_PREFIX));
    }
    #[cfg(not(test))]
    EMPTY_PREFIX.as_ptr()
}

#[inline(always)]
fn newline() -> *const u8 {
    #[cfg(test)]
    unsafe {
        return core::ptr::read(core::ptr::addr_of!(HOST_NEWLINE));
    }
    #[cfg(not(test))]
    NEWLINE.as_ptr()
}

/// `checkAppendMsg` — original: `FUN_082c2438` @ 0x082c2438 (176 bytes;
/// 14 direct `bl` call sites, 11 plain and three `blne`).
///
/// Appends a formatted message if `check->mx_err` permits it. `check` is
/// unguarded, `prefix` alone accepts NULL, and `args` points at the first
/// word after `format`, matching the spilled ARM varargs home area.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn integrity_check_append_msg(
    check: *mut IntegrityCheck,
    prefix: *const u8,
    format: *const u8,
    args: VaList,
) {
    let check = &mut *check;
    if check.mx_err == 0 {
        return;
    }

    check.mx_err = check.mx_err.wrapping_sub(1);
    check.n_err = check.n_err.wrapping_add(1);
    let formatted = (vm_printf_op())(core::ptr::null_mut(), format, args);
    let prefix = if prefix.is_null() { empty_prefix() } else { prefix };
    let old = check.z_err_msg;
    check.z_err_msg = core::ptr::null_mut();

    if old.is_null() {
        let strings = [prefix as usize as u32, formatted as usize as u32, 0];
        sqlite3_set_string(&mut check.z_err_msg, strings.as_ptr());
    } else {
        let strings = [
            old as usize as u32,
            newline() as usize as u32,
            prefix as usize as u32,
            formatted as usize as u32,
            0,
        ];
        sqlite3_set_string(&mut check.z_err_msg, strings.as_ptr());
        tracked_free(old);
    }
    tracked_free(formatted);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::sqlite::error_msg::{missing_vm_printf, SQLITE_VM_PRINTF};
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Once;

    static mut FORMAT_CALLS: usize = 0;
    static mut FORMATTED: *mut u8 = core::ptr::null_mut();
    static mut RECORDED: Option<(*mut u8, *const u8, VaList)> = None;

    unsafe extern "C" fn recording_vm_printf(
        db: *mut u8,
        format: *const u8,
        args: VaList,
    ) -> *mut u8 {
        FORMAT_CALLS += 1;
        RECORDED = Some((db, format, args));
        FORMATTED
    }

    unsafe fn with_formatter(message: *mut u8, body: impl FnOnce()) {
        FORMAT_CALLS = 0;
        RECORDED = None;
        FORMATTED = message;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VM_PRINTF),
            recording_vm_printf,
        );
        body();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VM_PRINTF),
            missing_vm_printf,
        );
    }

    fn slab() -> Option<*mut u8> {
        static ONCE: Once = Once::new();
        static mut BASE: *mut u8 = core::ptr::null_mut();
        ONCE.call_once(|| unsafe {
            BASE = try_map_u32_slab(hints::SQLITE_INTEGRITY_CHECK_APPEND_MSG, 0x1000)
                .unwrap_or(core::ptr::null_mut());
        });
        unsafe {
            let base = core::ptr::read(core::ptr::addr_of!(BASE));
            if base.is_null() { None } else { Some(base) }
        }
    }

    /// Build a tag-57 payload at `base + offset`: raw header at +0, payload
    /// at +0x20, and pad word at payload-4. The mock heap records the frees.
    unsafe fn tracked_string(base: *mut u8, offset: usize, text: &[u8]) -> *mut u8 {
        let raw = base.add(offset);
        core::ptr::write_bytes(raw, 0, 0x80);
        (raw as *mut i32).write((text.len() - 1) as i32);
        (raw.add(28) as *mut u32).write(24);
        core::ptr::copy_nonoverlapping(text.as_ptr(), raw.add(32), text.len());
        raw.add(32)
    }

    unsafe fn configure_literals(base: *mut u8) {
        core::ptr::copy_nonoverlapping(b"prefix: \0".as_ptr(), base.add(0x200), 9);
        core::ptr::copy_nonoverlapping(b"\n\0".as_ptr(), base.add(0x220), 2);
        base.add(0x230).write(0);
        HOST_NEWLINE = base.add(0x220);
        HOST_EMPTY_PREFIX = base.add(0x230);
    }

    fn check(mx_err: i32, z_err_msg: *mut u8, n_err: i32) -> IntegrityCheck {
        IntegrityCheck {
            p_bt: core::ptr::null_mut(),
            _p_pager: core::ptr::null_mut(),
            _n_page: 0,
            _an_ref: core::ptr::null_mut(),
            mx_err,
            z_err_msg,
            n_err,
        }
    }

    #[test]
    fn exhausted_budget_leaves_all_state_and_seams_untouched() {
        let _heap = mock_heap();
        let mut state = check(0, core::ptr::null_mut(), -9);
        let format = b"ignored %d\0".as_ptr();
        let args = [17u32];

        unsafe {
            with_formatter(core::ptr::null_mut(), || {
                integrity_check_append_msg(&mut state, core::ptr::null(), format, args.as_ptr());
            });
            assert_eq!((state.mx_err, state.n_err, state.z_err_msg), (0, -9, core::ptr::null_mut()));
            assert_eq!(FORMAT_CALLS, 0, "zero mxErr bypasses the formatter");
            assert_eq!(free_log().0, 0, "zero mxErr reaches neither free path");
        }
    }

    #[test]
    fn null_prefix_uses_empty_default_and_counter_wraps() {
        let Some(base) = slab() else {
            assert!(note_missing_u32_fixture("sqlite::integrity_check_append_msg"));
            return;
        };
        let mut arena = [0xa5u8; 16];
        let _mem = install_recorder(arena.as_mut_ptr());
        let _heap = mock_heap();
        let format = b"formatted\0".as_ptr();
        let args = [0xfeed_beefu32];

        unsafe {
            configure_literals(base);
            let formatted = tracked_string(base, 0x100, b"fresh\0");
            let mut state = check(1, core::ptr::null_mut(), i32::MAX);
            with_formatter(formatted, || {
                integrity_check_append_msg(&mut state, core::ptr::null(), format, args.as_ptr());
            });
            assert_eq!((state.mx_err, state.n_err), (0, i32::MIN), "ARM add/sub wrap");
            assert_eq!(state.z_err_msg, arena.as_mut_ptr());
            assert_eq!(&arena[..6], b"fresh\0", "NULL prefix is the empty literal");
            assert_eq!(realloc_log(), std::vec![(0, 6)], "one exact replacement allocation");
            assert_eq!(
                RECORDED,
                Some((core::ptr::null_mut(), format, args.as_ptr())),
                "formatter receives the NULL db and spilled varargs",
            );
            assert_eq!(free_log(), (1, base.add(0x100), 57), "formatted temporary is released");
        }
    }

    #[test]
    fn existing_message_is_detached_before_full_append_then_both_temporaries_free() {
        let Some(base) = slab() else {
            assert!(note_missing_u32_fixture("sqlite::integrity_check_append_msg"));
            return;
        };
        let mut arena = [0xa5u8; 32];
        let _mem = install_recorder(arena.as_mut_ptr());
        let _heap = mock_heap();
        let format = b"message %d\0".as_ptr();
        let args = [7u32];

        unsafe {
            configure_literals(base);
            let old = tracked_string(base, 0x000, b"old\0");
            let formatted = tracked_string(base, 0x100, b"fresh\0");
            let mut state = check(2, old, 9);
            with_formatter(formatted, || {
                integrity_check_append_msg(&mut state, base.add(0x200), format, args.as_ptr());
            });
            assert_eq!((state.mx_err, state.n_err), (1, 10));
            assert_eq!(state.z_err_msg, arena.as_mut_ptr());
            assert_eq!(&arena[..18], b"old\nprefix: fresh\0");
            assert_eq!(realloc_log(), std::vec![(0, 18)], "old text stays live until copied");
            assert_eq!(free_log(), (2, base.add(0x100), 57), "old frees first; formatted frees last");
        }
    }
}
