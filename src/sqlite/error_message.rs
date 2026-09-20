//! `sqlite3_errmsg` — original: `FUN_0839024c` @ `0x0839024c`.
//!
//! True extent: 72 bytes (`0x0839024c..0x08390294`), ending in a tail branch
//! to `sqlite3ErrStr` at `0x083762d8`. Raw `osos.dec` decoding finds three
//! inbound plain `bl` calls (`0x0838f44c`, `0x0839059c`, and `0x083905c4`) and
//! no predicated inbound `bl` calls. The body has two plain outgoing `bl`
//! calls: the ported type-tag validator at `0x08382c18` and
//! `sqlite3_value_text` at `0x0839179c`.
//!
//! Algorithm: NULL and invalid database handles map to SQLite's NOMEM and
//! MISUSE messages respectively. A valid handle returns its cached `pErr`
//! text when available; otherwise its `errCode` is passed to `sqlite3ErrStr`.
//! Deliberate deviation: the original final `b` becomes a call through an
//! absolute retail veneer, because the relocated patch payload cannot encode
//! that PC-relative transfer. On hosts the veneer is a replaceable callback.

use super::error::{DB_ERR_CODE_OFFSET, DB_P_ERR_OFFSET};
use super::value_text::sqlite3_value_text;

const SQLITE_NOMEM: u32 = 7;
const SQLITE_MISUSE: u32 = 21;

#[cfg(target_arch = "arm")]
extern "C" {
    fn sqlite_error_string(error_code: u32) -> *const u8;
}

#[cfg(not(target_arch = "arm"))]
pub type SqliteErrorStringFn = unsafe extern "C" fn(u32) -> *const u8;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_sqlite_error_string(_error_code: u32) -> *const u8 {
    core::ptr::null()
}

/// Host-only replacement for retail `sqlite3ErrStr` at `0x083762d8`.
#[cfg(not(target_arch = "arm"))]
pub static mut SQLITE_ERROR_STRING: SqliteErrorStringFn = missing_sqlite_error_string;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn sqlite_error_string(error_code: u32) -> *const u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_ERROR_STRING))(error_code)
}

/// Returns SQLite's current error text for `db`.
///
/// # Safety
///
/// A non-null `db` must be valid for aligned reads of its `errCode` word at
/// `+0x14`, its `pErr` word at `+0xc8`, and the complete `sqlite3_value_text`
/// contract when that field is non-null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_errmsg(db: *mut u8) -> *const u8 {
    if db.is_null() {
        return sqlite_error_string(SQLITE_NOMEM);
    }

    if crate::util::object_type_tag_is_recognized::object_type_tag_is_recognized(db) == 0 {
        return sqlite_error_string(SQLITE_MISUSE);
    }

    let error_code = (db.add(DB_ERR_CODE_OFFSET) as *const u32).read();
    if error_code == SQLITE_MISUSE {
        return sqlite_error_string(SQLITE_MISUSE);
    }

    let error_value = (db.add(DB_P_ERR_OFFSET) as *const *mut u8).read();
    let error_text = sqlite3_value_text(error_value);
    if !error_text.is_null() {
        return error_text;
    }

    sqlite_error_string(error_code)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl sqlite_error_string
    .type sqlite_error_string, %function
sqlite_error_string:
    ldr     pc, 1f
1:  .word   0x083762d8
    .size sqlite_error_string, . - sqlite_error_string
"#
);

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Mutex;

    const TYPE_TAG: u32 = 0x4b77_1290;
    const TYPE_TAG_WORD: usize = 0x40 / 4;
    const ERR_CODE_WORD: usize = DB_ERR_CODE_OFFSET / 4;
    const P_ERR_WORD: usize = DB_P_ERR_OFFSET / 4;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut LAST_CODE: u32 = 0;
    static MESSAGE: [u8; 8] = *b"message\0";

    unsafe extern "C" fn recording_error_string(error_code: u32) -> *const u8 {
        unsafe { LAST_CODE = error_code };
        MESSAGE.as_ptr()
    }

    struct ErrorStringRestore(SqliteErrorStringFn);

    impl Drop for ErrorStringRestore {
        fn drop(&mut self) {
            unsafe { SQLITE_ERROR_STRING = self.0 };
        }
    }

    fn install_error_string() -> ErrorStringRestore {
        unsafe {
            let previous = SQLITE_ERROR_STRING;
            SQLITE_ERROR_STRING = recording_error_string;
            LAST_CODE = 0;
            ErrorStringRestore(previous)
        }
    }

    #[test]
    fn null_handle_reports_nomem() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_error_string();
        unsafe {
            assert_eq!(sqlite3_errmsg(core::ptr::null_mut()), MESSAGE.as_ptr());
            assert_eq!(LAST_CODE, SQLITE_NOMEM);
        }
    }

    #[test]
    fn rejected_handle_reports_misuse_without_reading_database_fields() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_error_string();
        let db = [0u32; P_ERR_WORD + 1];
        unsafe {
            assert_eq!(sqlite3_errmsg(db.as_ptr().cast_mut().cast()), MESSAGE.as_ptr());
            assert_eq!(LAST_CODE, SQLITE_MISUSE);
        }
    }

    #[test]
    fn valid_misuse_handle_does_not_consult_error_value() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_error_string();
        let mut db = [0u32; P_ERR_WORD + 1];
        db[TYPE_TAG_WORD] = TYPE_TAG;
        db[ERR_CODE_WORD] = SQLITE_MISUSE;
        db[P_ERR_WORD] = 1;
        unsafe {
            assert_eq!(sqlite3_errmsg(db.as_mut_ptr().cast()), MESSAGE.as_ptr());
            assert_eq!(LAST_CODE, SQLITE_MISUSE);
        }
    }

    #[test]
    fn valid_handle_with_no_error_text_maps_its_error_code() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_error_string();
        let mut db = [0u32; P_ERR_WORD + 1];
        db[TYPE_TAG_WORD] = TYPE_TAG;
        db[ERR_CODE_WORD] = 11;
        unsafe {
            assert_eq!(sqlite3_errmsg(db.as_mut_ptr().cast()), MESSAGE.as_ptr());
            assert_eq!(LAST_CODE, 11);
        }
    }
}
