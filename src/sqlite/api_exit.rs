//! `sqlite_api_exit` — original: `FUN_0836f468` @ `0x0836f468` (68 bytes;
//! 9 verified direct `bl` call sites, all unconditional).
//!
//! Raw `osos.dec` extent is exactly 68 bytes (`0x0836f468..0x0836f4ac`):
//! `push {r4,lr}` begins this entry and the next separately linked function
//! begins at `0x0836f4ac`. Decoding every ARM B/BL-immediate word in the image
//! finds nine inbound `bl` instructions — `0x082b795c`, `0x082c43e4`,
//! `0x08381604`, `0x083816c4`, `0x08384c90`, `0x0838f668`, `0x083901f0`,
//! `0x08390334`, and `0x08390570` — none predicated. It also has 13 direct
//! tail-`b` entries, all unconditional.
//!
//! # Algorithm
//!
//! SQLite's `sqlite3ApiExit`: a NULL connection uses the default `errMask`
//! `0xff`. A non-NULL connection with `mallocFailed` at `+0x1e` set reports
//! `SQLITE_NOMEM` through [`super::error::sqlite_error`], clears that sticky
//! byte, and replaces the supplied result code with 7. It returns the selected
//! code masked by `db->errMask` at `+0x18`.
//!
//! Deliberate deviation: `sqlite_error`'s variadic home pointer is explicit in
//! Rust. This entry passes NULL because its NULL format never consumes it.

use super::error::sqlite_error;
use super::mem::MALLOC_FAILED_OFFSET;
use super::value_set_str::SQLITE_NOMEM;

/// Byte offset of `sqlite3.errMask` (original: `ldr r0,[r4,#0x18]`).
pub const DB_ERR_MASK_OFFSET: usize = 0x18;

/// SQLite's API-boundary result-code filter (`sqlite3ApiExit`).
///
/// # Safety
///
/// When non-NULL, `db` must reference writable SQLite connection storage
/// through `+0x1e` and readable storage through `+0x1b`; when its allocation
/// latch is set, it must also satisfy [`sqlite_error`]'s connection contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_api_exit(db: *mut u8, result_code: i32) -> i32 {
    if db.is_null() {
        return result_code & 0xff;
    }

    let result_code = if db.add(MALLOC_FAILED_OFFSET).read() != 0 {
        sqlite_error(db, SQLITE_NOMEM, core::ptr::null(), core::ptr::null());
        db.add(MALLOC_FAILED_OFFSET).write(0);
        SQLITE_NOMEM
    } else {
        result_code
    };

    result_code & (db.add(DB_ERR_MASK_OFFSET) as *const i32).read()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::error::{DB_ERR_CODE_OFFSET, DB_P_ERR_OFFSET};
    use crate::sqlite::value_new::{MEM_NULL, SQLITE_NULL};
    use crate::sqlite::vdbe::Mem;

    #[repr(align(8))]
    struct DbStorage([u8; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);

    unsafe fn error_code_slot(db: *mut u8) -> *mut i32 {
        db.add(DB_ERR_CODE_OFFSET).cast()
    }

    unsafe fn error_value_slot(db: *mut u8) -> *mut *mut u8 {
        db.add(DB_P_ERR_OFFSET).cast()
    }

    fn null_mem(db: *mut u8) -> Mem {
        Mem {
            u: 0,
            r: 0.0,
            db,
            z: core::ptr::null_mut(),
            n: 0,
            flags: 0,
            value_type: 0,
            enc: 0,
            x_del: core::ptr::null_mut(),
            z_malloc: core::ptr::null_mut(),
        }
    }

    #[test]
    fn null_connection_uses_the_default_low_byte_mask() {
        unsafe {
            assert_eq!(sqlite_api_exit(core::ptr::null_mut(), -1), 255);
            assert_eq!(sqlite_api_exit(core::ptr::null_mut(), 0x1234_56ff), 255);
        }
    }

    #[test]
    fn healthy_connection_masks_the_original_result_without_writing() {
        let mut db = DbStorage([0xa5; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);
        let db_ptr = db.0.as_mut_ptr();
        unsafe {
            (db_ptr.add(DB_ERR_MASK_OFFSET) as *mut i32).write(0xf0f0_00ffu32 as i32);
            db_ptr.add(MALLOC_FAILED_OFFSET).write(0);
            error_code_slot(db_ptr).write(0x1357_9bdf);

            assert_eq!(sqlite_api_exit(db_ptr, 0x0f0f_0f3c), 0x0000_003c);
            assert_eq!(error_code_slot(db_ptr).read(), 0x1357_9bdf);
            assert_eq!(db_ptr.add(MALLOC_FAILED_OFFSET).read(), 0);
        }
    }

    #[test]
    fn allocation_failure_is_reported_cleared_and_then_masked() {
        let mut db = DbStorage([0; DB_P_ERR_OFFSET + core::mem::size_of::<*mut u8>()]);
        let db_ptr = db.0.as_mut_ptr();
        let mut error_value = null_mem(db_ptr);
        unsafe {
            (db_ptr.add(DB_ERR_MASK_OFFSET) as *mut i32).write(3);
            db_ptr.add(MALLOC_FAILED_OFFSET).write(0xa5);
            error_code_slot(db_ptr).write(-123);
            error_value_slot(db_ptr).write((&mut error_value as *mut Mem).cast());

            assert_eq!(sqlite_api_exit(db_ptr, 0x70), 3);
            assert_eq!(error_code_slot(db_ptr).read(), SQLITE_NOMEM);
            assert_eq!(db_ptr.add(MALLOC_FAILED_OFFSET).read(), 0);
            assert_eq!(error_value.flags, MEM_NULL);
            assert_eq!(error_value.value_type, SQLITE_NULL);
        }
    }
}
