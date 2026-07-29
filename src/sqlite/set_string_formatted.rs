//! Format-a-string into fresh heap memory, discarding nothing but the
//! caller's patience — the variadic front end of the SQLite printf
//! chain.
//!
//! - `sqlite_set_string_formatted` — original: `FUN_0837d358` @
//!   0x0837d358 (28 bytes; 37 `bl` call sites, binary-scanned).
//!   SQLite's `sqlite3MPrintf` (`char *sqlite3MPrintf(sqlite3 *db,
//!   const char *zFormat, ...)` in util.c of the 3.5.x line).
//!
//! Algorithm: spill all four argument registers into a varargs home
//! area (`stmdb sp!, {r0-r3}`), reload the format pointer (the spilled
//! r1), build `ap` as the address of the spilled r2 — the first
//! variadic word — and call `sqlite3VMPrintf` @ 0x08386454 with
//! `(db, format, ap)`. The epilogue restores r4/lr and unwinds the home
//! area *without touching r0*, so the formatter's result — a heap-owned
//! NUL-terminated string, or NULL when its allocation fails — is
//! returned verbatim. Call sites confirm the pass-through: e.g.
//! 0x0836f26c feeds the returned `SELECT idx, stat FROM %Q.sqlite_stat1`
//! string straight into the statement executor.
//!
//! Deviations:
//! - The original is C-variadic; the Rust signature replaces the `...`
//!   with an explicit `args: VaList` — exactly the pointer the original
//!   builds on its stack (house convention, see `printf/printf_api.rs`
//!   for the rationale and the trampoline note for calling from
//!   firmware code).
//! - `sqlite3VMPrintf` @ 0x08386454 is not ported: it is a wrapper
//!   around the whole SQLite printf chain (see `sqlite/error_msg.rs`).
//!   The call goes through the shared [`SQLITE_VM_PRINTF`] dispatch
//!   static whose default slot is a documented always-NULL stub — the
//!   same end state the original reaches when the formatter's
//!   allocation fails.
//!
//! [`SQLITE_VM_PRINTF`]: super::error_msg::SQLITE_VM_PRINTF

use super::error_msg::{vm_printf_op, VaList};

/// sqlite_set_string_formatted — original: `FUN_0837d358` @ 0x0837d358
/// (28 bytes; 37 `bl` call sites).
///
/// Format `format` with the variadic words at `args` on behalf of
/// connection `db` and return the heap-owned result (NULL when the
/// formatter's allocation fails — or, with the default dispatch stub,
/// always).
///
/// Register usage: r0 = db, r1 = format, r2/r3/stack = varargs
/// (original builds `ap` = &spilled-r2; here `args` IS that pointer).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_set_string_formatted(
    db: *mut u8,
    format: *const u8,
    args: VaList,
) -> *mut u8 {
    (vm_printf_op())(db, format, args)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::error_msg::{missing_vm_printf, SQLITE_VM_PRINTF};
    use super::*;

    /// (db, format, ap) of the last formatter invocation.
    static mut RECORDED: Option<(*mut u8, *const u8, VaList)> = None;
    /// String the recording formatter hands back.
    static mut NEXT_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_vm_printf(db: *mut u8, format: *const u8, ap: VaList) -> *mut u8 {
        RECORDED = Some((db, format, ap));
        NEXT_RESULT
    }

    /// Swaps in the recording formatter for `body`, then restores the
    /// documented default so a failed assertion cannot leak the mock
    /// into the next test.
    unsafe fn with_formatter(result: *mut u8, body: impl FnOnce()) {
        NEXT_RESULT = result;
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), recording_vm_printf);
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), missing_vm_printf);
    }

    #[test]
    fn forwards_db_format_and_ap_and_returns_the_result_verbatim() {
        let mut db = [0u8; 8];
        let mut canned = b"SELECT idx, stat FROM 'main'.sqlite_stat1\0".to_vec();
        let result = canned.as_mut_ptr();
        let format = b"SELECT idx, stat FROM %Q.sqlite_stat1\0".as_ptr();
        let args: [u32; 2] = [0xdead_beef, 0xc0ff_ee00];
        unsafe {
            let mut returned = core::ptr::null_mut();
            with_formatter(result, || {
                returned = sqlite_set_string_formatted(db.as_mut_ptr(), format, args.as_ptr());
            });
            assert_eq!(returned, result, "formatter result passes through untouched");
            let recorded = core::ptr::read(core::ptr::addr_of!(RECORDED));
            assert_eq!(
                recorded,
                Some((db.as_mut_ptr(), format, args.as_ptr())),
                "formatter saw (db, format, ap)"
            );
        }
    }

    #[test]
    fn a_null_formatter_result_is_returned_as_null() {
        let mut db = [0u8; 8];
        unsafe {
            let mut returned = 1usize as *mut u8;
            with_formatter(core::ptr::null_mut(), || {
                returned =
                    sqlite_set_string_formatted(db.as_mut_ptr(), b"x %d\0".as_ptr(), core::ptr::null());
            });
            assert!(returned.is_null(), "allocation failure inside the formatter surfaces as NULL");
        }
    }

    #[test]
    fn the_default_formatter_stub_yields_null() {
        // No mock installed: the documented default slot is the
        // always-NULL stub (see `sqlite/error_msg.rs`).
        let mut db = [0u8; 8];
        unsafe {
            let returned =
                sqlite_set_string_formatted(db.as_mut_ptr(), b"x\0".as_ptr(), core::ptr::null());
            assert!(returned.is_null(), "default dispatch: no formatter, no string");
        }
    }

    #[test]
    fn null_db_and_null_ap_are_forwarded_verbatim() {
        // The wrapper performs no validation of its own — the original
        // forwards r0 and the built ap to 0x08386454 as-is, and so do
        // we.
        let format = b"%s\0".as_ptr();
        unsafe {
            let mut returned = core::ptr::null_mut();
            with_formatter(core::ptr::null_mut(), || {
                returned = sqlite_set_string_formatted(core::ptr::null_mut(), format, core::ptr::null());
            });
            let recorded = core::ptr::read(core::ptr::addr_of!(RECORDED));
            assert_eq!(recorded, Some((core::ptr::null_mut(), format, core::ptr::null())));
            assert!(returned.is_null());
        }
    }
}
