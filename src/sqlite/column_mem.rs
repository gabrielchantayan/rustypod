//! SQLite's result-column value accessor.
//!
//! - `column_mem` — original: `FUN_082c43f0` @ `0x082c43f0` (88 bytes;
//!   **10 `bl` call sites**, decoded from every ARM `B`/`BL` word in
//!   `osos.dec`: `0x0838f9b8`, `0x0838f9dc`, `0x0838fa00`, `0x0838fa50`,
//!   `0x0838fa7c`, `0x0838faa0`, `0x0838faec`, `0x0838fb10`, `0x0838fb34`,
//!   and `0x0838fb54`; all are unconditional).
//!
//! The helper behind SQLite's `sqlite3_column_*` APIs returns the `column`th
//! [`Mem`] in a statement's current result set. It accepts only a non-NULL
//! result-set pointer, a non-negative index, and `column < nResColumn`.
//! Otherwise it reports `SQLITE_RANGE` (25) through `sqlite3Error` and returns
//! the shared static SQL-NULL [`Mem`] named by the literal at `0x082c4448`
//! (`0x088fce20` at runtime).
//!
//! Deliberate deviation: the successful ARM path makes an otherwise unused
//! call to `FUN_083900c4`, a 24-byte leaf that only reloads this same
//! statement's `pResultSet` and `nResColumn` before returning the latter. It
//! has no ported ledger entry and its ignored result has no observable effect,
//! so this port omits that pure call rather than introducing a dispatch seam.

use super::error::sqlite_error;
use super::value_new::{MEM_NULL, SQLITE_NULL};
use super::vdbe::{Mem, Vdbe};

/// SQLite's `SQLITE_RANGE` error code (original: `mov r1, #25`).
const SQLITE_RANGE: i32 = 25;

/// The byte pointed to by the stock fallback `Mem.z`: `0x089c4850` is an
/// empty C string in the runtime image.
static EMPTY_RESULT_TEXT: [u8; 1] = [0];

/// Stock's shared fallback value at runtime address `0x088fce20`.
///
/// Its `z` points to [`EMPTY_RESULT_TEXT`], while its flags/type spell SQL
/// NULL (`MEM_Null`, `SQLITE_NULL`), matching the 40 bytes at
/// `0x088fce20 + 0xaed8` in `osos.dec`.
static mut EMPTY_RESULT: Mem = Mem {
    u: 0,
    r: 0.0,
    db: core::ptr::null_mut(),
    z: EMPTY_RESULT_TEXT.as_ptr() as *mut u8,
    n: 0,
    flags: MEM_NULL,
    value_type: SQLITE_NULL,
    enc: 0,
    x_del: core::ptr::null_mut(),
    z_malloc: core::ptr::null_mut(),
};

/// `column_mem` — original: `FUN_082c43f0` @ `0x082c43f0` (88 bytes).
///
/// Return the selected current-row [`Mem`], or the shared SQL-NULL value after
/// reporting [`SQLITE_RANGE`]. Like the ARM, a NULL `statement` reaches the
/// error path's unguarded `statement->db` load and is not a valid input.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn column_mem(statement: *mut Vdbe, column: i32) -> *mut Mem {
    if !statement.is_null() {
        let result_set = (*statement).p_result_set;
        if !result_set.is_null() && (*statement).n_res_column > column && column >= 0 {
            return result_set.add(column as usize);
        }
    }

    sqlite_error(
        (*statement).db,
        SQLITE_RANGE,
        core::ptr::null(),
        core::ptr::null(),
    );
    core::ptr::addr_of_mut!(EMPTY_RESULT)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::MaybeUninit;

    unsafe fn statement(result_set: *mut Mem, n_res_column: i32) -> Vdbe {
        let mut statement = MaybeUninit::<Vdbe>::zeroed().assume_init();
        statement.p_result_set = result_set;
        statement.n_res_column = n_res_column;
        statement
    }

    #[test]
    fn returns_each_in_range_result_cell() {
        let mut results = unsafe { MaybeUninit::<[Mem; 3]>::zeroed().assume_init() };
        let mut statement = unsafe { statement(results.as_mut_ptr(), 3) };

        unsafe {
            assert_eq!(column_mem(&mut statement, 0), results.as_mut_ptr());
            assert_eq!(column_mem(&mut statement, 1), results.as_mut_ptr().add(1));
            assert_eq!(column_mem(&mut statement, 2), results.as_mut_ptr().add(2));
        }
    }

    #[test]
    fn rejects_negative_and_out_of_range_columns() {
        let mut results = unsafe { MaybeUninit::<[Mem; 2]>::zeroed().assume_init() };
        let mut statement = unsafe { statement(results.as_mut_ptr(), 2) };

        unsafe {
            assert_eq!(column_mem(&mut statement, -1), core::ptr::addr_of_mut!(EMPTY_RESULT));
            assert_eq!(column_mem(&mut statement, 2), core::ptr::addr_of_mut!(EMPTY_RESULT));
            assert_eq!(column_mem(&mut statement, i32::MAX), core::ptr::addr_of_mut!(EMPTY_RESULT));
        }
    }

    #[test]
    fn rejects_an_unallocated_result_set_without_reading_a_cell() {
        let mut statement = unsafe { statement(core::ptr::null_mut(), 7) };

        assert_eq!(
            unsafe { column_mem(&mut statement, 0) },
            core::ptr::addr_of_mut!(EMPTY_RESULT),
        );
    }
}
