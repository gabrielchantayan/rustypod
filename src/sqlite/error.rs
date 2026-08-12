//! The connection error reporter — SQLite's runtime (rather than parser)
//! diagnostic funnel.
//!
//! - `sqlite_error` — original: `FUN_083766f4` @ 0x083766f4 (136
//!   bytes; 27 unconditional `bl` call sites plus `blne` at 0x082c443c
//!   and `bleq` at 0x082dc074). Upstream SQLite 3.5.9's `sqlite3Error`
//!   from `src/util.c`.
//!
//! Algorithm: a NULL database handle is ignored. Otherwise, create the
//! connection's cached error `Mem` (`pErr` at +0xc8) with
//! `sqlite3ValueNew` when necessary; if that allocation fails, leave the
//! connection untouched. Store `err_code` into `errCode` (+0x14). A NULL
//! format clears the `Mem` to a UTF-8, statically owned NULL string;
//! otherwise format the variadic words with `sqlite3VMPrintf` and install
//! the resulting owned string with length -1. As in the ARM, the `pErr`
//! slot is reloaded after formatting before `sqlite3ValueSetStr` is
//! called.
//!
//! Connection fields pinned by the `ldr/str [r4, #off]` sequence:
//!
//! ```text
//! +0x14 errCode  i32
//! +0xc8 pErr     *mut Mem
//! ```
//!
//! Deviations:
//! - `sqlite3ValueNew` @ 0x083866c0 and `sqlite3ValueSetStr` @
//!   0x083866ec are unported and cross [`SQLITE_VALUE_NEW`] and
//!   [`SQLITE_VALUE_SET_STR`] dispatch seams. The value-new default
//!   reports allocation failure; the value-set-string default is a no-op.
//! - `sqlite3VMPrintf` @ 0x08386454 uses the shared
//!   [`super::error_msg::SQLITE_VM_PRINTF`] seam. The C varargs home area
//!   becomes explicit [`VaList`], the pointer to the first variadic word.
//! - For a formatted error, the firmware passes literal 0x0838581c as
//!   the `Mem.xDel` destructor. It occupies the xDel position at 16
//!   literal-pool references across the binary; upstream 3.5.9 passes
//!   `sqlite3_free`. The port forwards the observed literal verbatim.

use super::error_msg::{vm_printf_op, VaList};

/// Byte offset of `sqlite3.errCode` (original: `str r5,[r4,#0x14]`).
pub const DB_ERR_CODE_OFFSET: usize = 0x14;
/// Byte offset of `sqlite3.pErr` (original: `ldr/str [r4,#0xc8]`).
pub const DB_P_ERR_OFFSET: usize = 0xc8;

/// The original's UTF-8 encoding argument (`mov r3,#1`).
pub const SQLITE_UTF8: u8 = 1;

/// The destructor literal supplied for a formatted error string.
///
/// The 0x083766f4 literal pool contains 0x0838581c. It fills the fifth
/// (`xDel`) argument to `sqlite3ValueSetStr`; upstream SQLite 3.5.9
/// supplies `sqlite3_free` in this position.
pub const SQLITE_FREE_X_DEL: *mut u8 = 0x0838_581cusize as *mut u8;

/// `sqlite3ValueNew(db)` @ 0x083866c0: allocate and initialize a NULL
/// `Mem` value for the connection's `pErr` slot.
pub type ValueNewFn = unsafe extern "C" fn(db: *mut u8) -> *mut u8;

/// The OOM-shaped default for an unported `sqlite3ValueNew`.
pub(crate) unsafe extern "C" fn missing_value_new(_db: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Active `sqlite3ValueNew` dispatch slot. Host tests install a recording
/// replacement; the real port should replace this default when it lands.
pub static mut SQLITE_VALUE_NEW: ValueNewFn = missing_value_new;

/// Read the value-new slot volatile so its default remains replaceable.
#[inline(always)]
pub(crate) unsafe fn value_new_op() -> ValueNewFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VALUE_NEW))
}

/// `sqlite3ValueSetStr(value, n, z, enc, x_del)` @ 0x083866ec.
///
/// This preserves the wrapper's argument order. Its unported body swaps
/// `n` and `z` while forwarding to `sqlite3VdbeMemSetStr`.
pub type ValueSetStrFn = unsafe extern "C" fn(
    value: *mut u8,
    n: i32,
    z: *mut u8,
    enc: u8,
    x_del: *mut u8,
);

/// The no-op default for an unported `sqlite3ValueSetStr`.
pub(crate) unsafe extern "C" fn missing_value_set_str(
    _value: *mut u8,
    _n: i32,
    _z: *mut u8,
    _enc: u8,
    _x_del: *mut u8,
) {
}

/// Active `sqlite3ValueSetStr` dispatch slot. Host tests install a
/// recording replacement; the real port should replace this default when
/// it lands.
pub static mut SQLITE_VALUE_SET_STR: ValueSetStrFn = missing_value_set_str;

/// Read the value-set-string slot volatile so its default remains
/// replaceable.
#[inline(always)]
pub(crate) unsafe fn value_set_str_op() -> ValueSetStrFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VALUE_SET_STR))
}

/// sqlite_error — original: `FUN_083766f4` @ 0x083766f4 (136 bytes).
///
/// `sqlite3Error`: record `err_code` on `db` and replace its cached error
/// value. A NULL `format` clears the value; a non-NULL format is rendered
/// from `args` and installed as a dynamically owned UTF-8 string. If
/// creating `pErr` fails, no field — including `errCode` — is changed.
///
/// Register usage: r0 = db, r1 = err_code, r2 = format, r3/stack =
/// varargs (the original passes `&spilled-r3` to `sqlite3VMPrintf`; here
/// `args` is that explicit va_list pointer).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_error(
    db: *mut u8,
    err_code: i32,
    format: *const u8,
    args: VaList,
) {
    if db.is_null() {
        return;
    }

    let error_value_slot = db.add(DB_P_ERR_OFFSET) as *mut *mut u8;
    if error_value_slot.read().is_null() {
        let error_value = (value_new_op())(db);
        error_value_slot.write(error_value);
        if error_value.is_null() {
            return;
        }
    }

    (db.add(DB_ERR_CODE_OFFSET) as *mut i32).write(err_code);

    if format.is_null() {
        // Original: pErr, 0, NULL, SQLITE_UTF8, SQLITE_STATIC.
        // It reloads pErr from +0xc8 instead of retaining the local value.
        (value_set_str_op())(
            error_value_slot.read(),
            0,
            core::ptr::null_mut(),
            SQLITE_UTF8,
            core::ptr::null_mut(),
        );
    } else {
        let formatted = (vm_printf_op())(db, format, args);
        // Original: pErr, -1, formatted, SQLITE_UTF8, sqlite3_free.
        (value_set_str_op())(
            error_value_slot.read(),
            -1,
            formatted,
            SQLITE_UTF8,
            SQLITE_FREE_X_DEL,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::error_msg::{missing_vm_printf, SQLITE_VM_PRINTF};
    use super::*;

    /// Aligned opaque storage for the two connection fields the routine
    /// touches. On the host a pointer occupies eight bytes, so reserve its
    /// host width after the firmware's +0xc8 field offset.
    #[repr(align(8))]
    struct DbStorage([u8; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);

    static mut VALUE_NEW_RESULT: *mut u8 = core::ptr::null_mut();
    static mut VALUE_NEW_DB: Option<*mut u8> = None;
    static mut VALUE_SET_CALL: Option<(*mut u8, i32, *mut u8, u8, *mut u8)> = None;
    static mut FORMAT_CALL: Option<(*mut u8, *const u8, VaList)> = None;
    static mut FORMAT_RESULT: *mut u8 = core::ptr::null_mut();
    static mut FORMAT_REPLACED_ERROR_VALUE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_value_new(db: *mut u8) -> *mut u8 {
        VALUE_NEW_DB = Some(db);
        VALUE_NEW_RESULT
    }

    unsafe extern "C" fn recording_value_set_str(
        value: *mut u8,
        n: i32,
        z: *mut u8,
        enc: u8,
        x_del: *mut u8,
    ) {
        VALUE_SET_CALL = Some((value, n, z, enc, x_del));
    }

    unsafe extern "C" fn recording_vm_printf(
        db: *mut u8,
        format: *const u8,
        args: VaList,
    ) -> *mut u8 {
        FORMAT_CALL = Some((db, format, args));
        if !FORMAT_REPLACED_ERROR_VALUE.is_null() {
            error_value_slot(db).write(FORMAT_REPLACED_ERROR_VALUE);
        }
        FORMAT_RESULT
    }

    unsafe fn error_value_slot(db: *mut u8) -> *mut *mut u8 {
        db.add(DB_P_ERR_OFFSET) as *mut *mut u8
    }

    unsafe fn err_code_slot(db: *mut u8) -> *mut i32 {
        db.add(DB_ERR_CODE_OFFSET) as *mut i32
    }

    /// Reset all recording state and install every recording seam. The
    /// defaults are restored after `body`, matching the other SQLite seam
    /// tests' convention.
    unsafe fn with_recorders(body: impl FnOnce()) {
        VALUE_NEW_RESULT = core::ptr::null_mut();
        VALUE_NEW_DB = None;
        VALUE_SET_CALL = None;
        FORMAT_CALL = None;
        FORMAT_RESULT = core::ptr::null_mut();
        FORMAT_REPLACED_ERROR_VALUE = core::ptr::null_mut();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VALUE_NEW), recording_value_new);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VALUE_SET_STR),
            recording_value_set_str,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), recording_vm_printf);
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VALUE_NEW), missing_value_new);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VALUE_SET_STR),
            missing_value_set_str,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), missing_vm_printf);
    }

    #[test]
    fn a_null_connection_does_not_call_any_seam() {
        unsafe {
            with_recorders(|| {
                sqlite_error(core::ptr::null_mut(), 19, b"x\0".as_ptr(), core::ptr::null());
                assert_eq!(VALUE_NEW_DB, None);
                assert_eq!(VALUE_SET_CALL, None);
                assert_eq!(FORMAT_CALL, None);
            });
        }
    }

    #[test]
    fn an_existing_error_value_is_cleared_for_a_null_format() {
        let mut db = DbStorage([0xa5; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);
        let db_ptr = db.0.as_mut_ptr();
        let error_value = 0xfeed_cafeusize as *mut u8;
        unsafe {
            error_value_slot(db_ptr).write(error_value);
            err_code_slot(db_ptr).write(-123);
            with_recorders(|| {
                sqlite_error(db_ptr, 7, core::ptr::null(), core::ptr::null());
                assert_eq!(VALUE_NEW_DB, None, "existing pErr is reused");
                assert_eq!(err_code_slot(db_ptr).read(), 7);
                assert_eq!(
                    VALUE_SET_CALL,
                    Some((error_value, 0, core::ptr::null_mut(), SQLITE_UTF8, core::ptr::null_mut())),
                    "NULL format uses n=0, z=NULL, SQLITE_STATIC",
                );
                assert_eq!(FORMAT_CALL, None);
            });
        }
    }

    #[test]
    fn a_missing_error_value_is_created_before_recording_the_error() {
        let mut db = DbStorage([0; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);
        let db_ptr = db.0.as_mut_ptr();
        let error_value = 0x1234_5678usize as *mut u8;
        unsafe {
            with_recorders(|| {
                VALUE_NEW_RESULT = error_value;
                sqlite_error(db_ptr, 12, core::ptr::null(), core::ptr::null());
                assert_eq!(VALUE_NEW_DB, Some(db_ptr));
                assert_eq!(error_value_slot(db_ptr).read(), error_value, "pErr cached on db");
                assert_eq!(err_code_slot(db_ptr).read(), 12);
                assert_eq!(VALUE_SET_CALL.map(|call| call.0), Some(error_value));
            });
        }
    }

    #[test]
    fn an_error_value_allocation_failure_leaves_the_error_code_unchanged() {
        let mut db = DbStorage([0; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);
        let db_ptr = db.0.as_mut_ptr();
        unsafe {
            err_code_slot(db_ptr).write(0x2468);
            with_recorders(|| {
                // VALUE_NEW_RESULT remains NULL: exact sqlite3ValueNew OOM path.
                sqlite_error(db_ptr, 9, b"unused\0".as_ptr(), core::ptr::null());
                assert_eq!(VALUE_NEW_DB, Some(db_ptr));
                assert!(error_value_slot(db_ptr).read().is_null());
                assert_eq!(err_code_slot(db_ptr).read(), 0x2468, "errCode store follows successful pErr creation");
                assert_eq!(VALUE_SET_CALL, None);
                assert_eq!(FORMAT_CALL, None);
            });
        }
    }

    #[test]
    fn a_format_is_rendered_and_installed_with_the_firmware_free_destructor() {
        let mut db = DbStorage([0; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);
        let db_ptr = db.0.as_mut_ptr();
        let error_value = 0x4000usize as *mut u8;
        let mut rendered = b"disk I/O error\0".to_vec();
        let format = b"disk %s error\0".as_ptr();
        let args = [0xc0ff_ee00u32];
        unsafe {
            error_value_slot(db_ptr).write(error_value);
            with_recorders(|| {
                FORMAT_RESULT = rendered.as_mut_ptr();
                sqlite_error(db_ptr, 10, format, args.as_ptr());
                assert_eq!(err_code_slot(db_ptr).read(), 10);
                assert_eq!(FORMAT_CALL, Some((db_ptr, format, args.as_ptr())));
                assert_eq!(
                    VALUE_SET_CALL,
                    Some((error_value, -1, rendered.as_mut_ptr(), SQLITE_UTF8, SQLITE_FREE_X_DEL)),
                    "formatted result is NUL-scanned and dynamically owned",
                );
            });
        }
    }

    #[test]
    fn the_error_value_slot_is_reloaded_after_formatting() {
        let mut db = DbStorage([0; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);
        let db_ptr = db.0.as_mut_ptr();
        let original_value = 0x4100usize as *mut u8;
        let replacement_value = 0x4200usize as *mut u8;
        unsafe {
            error_value_slot(db_ptr).write(original_value);
            with_recorders(|| {
                FORMAT_REPLACED_ERROR_VALUE = replacement_value;
                sqlite_error(db_ptr, 1, b"x\0".as_ptr(), core::ptr::null());
                assert_eq!(error_value_slot(db_ptr).read(), replacement_value);
                assert_eq!(VALUE_SET_CALL.map(|call| call.0), Some(replacement_value));
            });
        }
    }

    #[test]
    fn the_default_value_new_stub_has_the_original_oom_effect() {
        let mut db = DbStorage([0; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);
        let db_ptr = db.0.as_mut_ptr();
        unsafe {
            err_code_slot(db_ptr).write(22);
            sqlite_error(db_ptr, 23, b"x\0".as_ptr(), core::ptr::null());
            assert!(error_value_slot(db_ptr).read().is_null());
            assert_eq!(err_code_slot(db_ptr).read(), 22);
        }
    }
}
