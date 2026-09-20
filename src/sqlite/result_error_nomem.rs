//! Scalar-function out-of-memory result.
//!
//! - `sqlite3_result_error_nomem` — original: `FUN_083911a8` @
//!   **0x083911a8** (40 bytes, 0x083911a8..0x083911d0; **3 plain `bl`
//!   call sites, no predicated `bl`**). The raw words decode to one call,
//!   `sqlite3VdbeMemSetNull(context + 8)`, followed by stores of
//!   `SQLITE_NOMEM` to `context + 0x34` and one to
//!   `context->s.db + 0x1e`.
//!
//! The helper invalidates the embedded scalar result, records the callback's
//! `SQLITE_NOMEM` error, and latches the connection's `mallocFailed` byte.
//!
//! ### Deliberate deviations
//!
//! Named `repr(C)` fields model the target offsets. This avoids treating host
//! pointers as four-byte fields; the target's `context + 8` result cell is
//! represented by `context.s` on both targets.

use super::aggregate_context::SqliteContext;
use super::mem::MALLOC_FAILED_OFFSET;
use super::value_set_str::SQLITE_NOMEM;
use super::vdbe_mem_set_null::vdbe_mem_set_null;

/// sqlite3_result_error_nomem — original: `FUN_083911a8` @ 0x083911a8 (40
/// bytes; 3 plain `bl` call sites, no predicated `bl`).
///
/// Mark a scalar-function context as out of memory: NULL its embedded result
/// cell, store `SQLITE_NOMEM` in `is_error`, and set `db->mallocFailed`.
/// The original has no NULL checks for either pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_result_error_nomem(context: *mut SqliteContext) {
    vdbe_mem_set_null(core::ptr::addr_of_mut!((*context).s));
    (*context).is_error = SQLITE_NOMEM;
    (*context).s.db.add(MALLOC_FAILED_OFFSET).write(1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::Mem;
    use crate::sqlite::vdbe_mem_set_null::MEM_TYPE_BITS;

    fn mem(db: *mut u8, flags: u16, value_type: u8) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db,
            z: 0x0bad_2000usize as *mut u8,
            n: -123_456_789,
            flags,
            value_type,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    #[test]
    fn nulls_result_records_nomem_and_latches_connection() {
        let mut db = [0xa5u8; MALLOC_FAILED_OFFSET + 2];
        db[MALLOC_FAILED_OFFSET] = 0;
        let before_db = db;
        let db_ptr = db.as_mut_ptr();
        let original = mem(db_ptr, 0xffe0 | MEM_TYPE_BITS, 0xa5);
        let mut context = SqliteContext {
            p_func: core::ptr::null_mut(),
            _gap_04: [0; 4],
            s: original,
            p_mem: core::ptr::null_mut(),
            is_error: -123,
        };

        unsafe { sqlite3_result_error_nomem(&mut context) };

        assert_eq!(context.s.flags, 0xffe0 | 1);
        assert_eq!(context.s.value_type, 5);
        assert_eq!(context.is_error, SQLITE_NOMEM);
        let mut expected_db = before_db;
        expected_db[MALLOC_FAILED_OFFSET] = 1;
        assert_eq!(db, expected_db);
        assert_eq!(context.s.u, 0x0bad_cafe_dead_beef);
        assert_eq!(context.s.r.to_bits(), 0x7ff8_0000_5a5a_5a5a);
        assert_eq!(context.s.db, db_ptr);
        assert_eq!(context.s.z, 0x0bad_2000usize as *mut u8);
        assert_eq!(context.s.n, -123_456_789);
        assert_eq!(context.s.enc, 0xa7);
        assert_eq!(context.s.x_del, 0x0bad_3000usize as *mut u8);
        assert_eq!(context.s.z_malloc, 0x0bad_4000usize as *mut u8);
    }

    #[test]
    fn overwrites_a_preexisting_malloc_failure_latch() {
        let mut db = [0u8; MALLOC_FAILED_OFFSET + 1];
        db[MALLOC_FAILED_OFFSET] = 0x7f;
        let mut context = SqliteContext {
            p_func: core::ptr::null_mut(),
            _gap_04: [0; 4],
            s: mem(db.as_mut_ptr(), 0, 0),
            p_mem: core::ptr::null_mut(),
            is_error: 0,
        };

        unsafe { sqlite3_result_error_nomem(&mut context) };

        assert_eq!(db[MALLOC_FAILED_OFFSET], 1);
        assert_eq!(context.s.flags, 1);
        assert_eq!(context.s.value_type, 5);
        assert_eq!(context.is_error, SQLITE_NOMEM);
    }
}
