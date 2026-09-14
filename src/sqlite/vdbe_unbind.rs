//! Prepared-statement parameter clearing — SQLite's common bind preamble.
//!
//! - `vdbe_unbind` — original: `FUN_083974e4` @ 0x083974e4 (160 bytes,
//!   0x083974e4..0x08397584; **5 `bl` call sites plus one tail-`b`**,
//!   decoded from osos.dec). Upstream SQLite 3.5's `vdbeUnbind`, shared by
//!   `sqlite3_bind_null` and the typed parameter binders.
//!
//! ### Algorithm
//!
//! A NULL statement, a statement whose `magic` is not `VDBE_MAGIC_RUN`, or
//! one whose program counter is non-negative reports `SQLITE_MISUSE` (21).
//! A one-based parameter index outside `1..=n_var` reports `SQLITE_RANGE`
//! (25). Otherwise the selected 40-byte `Mem` is released, its flags are
//! assigned `MEM_Null` (1), and `SQLITE_OK` is reported. Every non-NULL
//! statement path calls `sqlite_error(db, rc, NULL, 0)` before returning.
//!
//! ### Extent and call sites
//!
//! The next function begins with `push {r3,lr}` at 0x08397588; 0x08397584 is
//! the preceding routine's literal `VDBE_MAGIC_RUN` word, not an instruction.
//! Scanning every aligned ARM B/BL-immediate in osos.dec finds plain `bl` at
//! 0x082b78dc, 0x0838ef4c, 0x0838ef98, 0x0838f0f0, and 0x0838f134, plus the
//! tail `b` at 0x0838efc8. There are no predicated call sites. The tail is
//! `sqlite3_bind_null`; the five `bl` callers are typed bind wrappers and the
//! code generator's parameter binding path.
//!
//! ### Deviations
//!
//! The target uses the direct `bl mem_release`. The port invokes the existing
//! `MEM_SET_OPS` release slot, whose target default is that exact routine;
//! host tests replace it because `mem_release` intentionally uses target byte
//! offsets and must not run against a widened host-layout `Mem`.

use super::error::sqlite_error;
use super::vdbe::{Mem, Vdbe};
use super::vdbe_mem_set_int64::release_op;

/// `VDBE_MAGIC_RUN`, loaded from the literal at 0x08397584.
pub const VDBE_MAGIC_RUN: u32 = 0xbdf2_0da3;
/// SQLite's "library routine called out of sequence" result.
pub const SQLITE_MISUSE: i32 = 21;
/// SQLite's "column index out of range" result.
pub const SQLITE_RANGE: i32 = 25;

/// vdbe_unbind — original: `FUN_083974e4` @ 0x083974e4 (160 bytes; 5 `bl`
/// call sites plus one tail-`b`).
///
/// SQLite's `vdbeUnbind`: validate that `statement` is an unexecuted prepared
/// statement and that `parameter_index` selects one of its one-based host
/// parameters. Release and NULL the selected binding, report the result on
/// the owning database, and return that result code.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_unbind(statement: *mut Vdbe, parameter_index: i32) -> i32 {
    if statement.is_null() {
        return SQLITE_MISUSE;
    }

    let statement = &mut *statement;
    let result = if statement.magic != VDBE_MAGIC_RUN || statement.pc >= 0 {
        SQLITE_MISUSE
    } else if parameter_index < 1 || parameter_index > statement.n_var {
        SQLITE_RANGE
    } else {
        let value: *mut Mem = statement.a_var.add((parameter_index - 1) as usize);
        (release_op())(value.cast());
        (*value).flags = 1;
        0
    };

    sqlite_error(statement.db, result, core::ptr::null(), core::ptr::null());
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::error::{DB_ERR_CODE_OFFSET, DB_P_ERR_OFFSET};
    use super::super::vdbe_mem_set_int64::{
        tests::ops_lock, MemSetOps, DEFAULT_MEM_SET_OPS, MEM_SET_OPS,
    };
    use core::mem::MaybeUninit;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::MutexGuard;

    static RELEASE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recording_mem_release(value: *mut u8) {
        RELEASE_CALLS.fetch_add(1, Ordering::Relaxed);
        RELEASE_ARG.store(value as usize, Ordering::Relaxed);
    }

    struct ReleaseGuard;

    impl Drop for ReleaseGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(MEM_SET_OPS).write(DEFAULT_MEM_SET_OPS);
            }
        }
    }

    fn record_releases() -> (MutexGuard<'static, ()>, ReleaseGuard) {
        let lock = ops_lock().lock().unwrap_or_else(|error| error.into_inner());
        RELEASE_CALLS.store(0, Ordering::Relaxed);
        RELEASE_ARG.store(0, Ordering::Relaxed);
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_SET_OPS),
                MemSetOps {
                    mem_release: recording_mem_release,
                },
            );
        }
        (lock, ReleaseGuard)
    }

    fn empty_mem() -> Mem {
        unsafe { MaybeUninit::<Mem>::zeroed().assume_init() }
    }

    fn statement(db: *mut u8, values: &mut [Mem]) -> Vdbe {
        let mut statement = unsafe { MaybeUninit::<Vdbe>::zeroed().assume_init() };
        statement.db = db;
        statement.magic = VDBE_MAGIC_RUN;
        statement.pc = -1;
        statement.n_var = values.len() as i32;
        statement.a_var = values.as_mut_ptr();
        statement
    }

    fn install_error_value(db: &mut [usize; 32], error_value: &mut Mem) {
        unsafe {
            (db.as_mut_ptr().cast::<u8>().add(DB_P_ERR_OFFSET) as *mut *mut u8)
                .write((error_value as *mut Mem).cast());
        }
    }

    fn error_code(db: &[usize; 32]) -> i32 {
        unsafe { (db.as_ptr().cast::<u8>().add(DB_ERR_CODE_OFFSET) as *const i32).read() }
    }

    #[test]
    fn null_statement_returns_misuse_without_dereference() {
        assert_eq!(unsafe { vdbe_unbind(core::ptr::null_mut(), 1) }, SQLITE_MISUSE);
    }

    #[test]
    fn invalid_execution_state_reports_misuse_without_releasing_a_binding() {
        let mut db = [0usize; 32];
        let mut error_value = empty_mem();
        install_error_value(&mut db, &mut error_value);
        let mut values = [empty_mem()];
        values[0].z = 0x1234usize as *mut u8;
        let mut statement = statement(db.as_mut_ptr().cast(), &mut values);

        statement.magic = 0;
        assert_eq!(unsafe { vdbe_unbind(&mut statement, 1) }, SQLITE_MISUSE);
        assert_eq!(error_code(&db), SQLITE_MISUSE);
        assert_eq!(values[0].z, 0x1234usize as *mut u8);

        statement.magic = VDBE_MAGIC_RUN;
        statement.pc = 0;
        assert_eq!(unsafe { vdbe_unbind(&mut statement, 1) }, SQLITE_MISUSE);
        assert_eq!(error_code(&db), SQLITE_MISUSE);
        assert_eq!(values[0].z, 0x1234usize as *mut u8);
    }

    #[test]
    fn out_of_range_indices_report_range_without_releasing_a_binding() {
        let mut db = [0usize; 32];
        let mut error_value = empty_mem();
        install_error_value(&mut db, &mut error_value);
        let mut values = [empty_mem(), empty_mem()];
        values[1].z = 0x5678usize as *mut u8;
        let mut statement = statement(db.as_mut_ptr().cast(), &mut values);

        for parameter_index in [i32::MIN, -1, 0, 3, i32::MAX] {
            assert_eq!(unsafe { vdbe_unbind(&mut statement, parameter_index) }, SQLITE_RANGE);
            assert_eq!(error_code(&db), SQLITE_RANGE);
            assert_eq!(values[1].z, 0x5678usize as *mut u8);
        }
    }

    #[test]
    fn valid_one_based_indices_release_exactly_the_selected_binding() {
        let _release_guard = record_releases();
        let mut db = [0usize; 32];
        let mut error_value = empty_mem();
        install_error_value(&mut db, &mut error_value);
        let mut values = [empty_mem(), empty_mem()];
        values[0].z = 0x1111usize as *mut u8;
        values[0].value_type = 0xa1;
        values[1].z = 0x2222usize as *mut u8;
        values[1].value_type = 0xb2;
        let mut statement = statement(db.as_mut_ptr().cast(), &mut values);

        assert_eq!(unsafe { vdbe_unbind(&mut statement, 2) }, 0);
        assert_eq!(error_code(&db), 0);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(RELEASE_ARG.load(Ordering::Relaxed), core::ptr::addr_of!(values[1]) as usize);
        assert_eq!(values[0].z, 0x1111usize as *mut u8);
        assert_eq!(values[0].flags, 0);
        assert_eq!(values[1].z, 0x2222usize as *mut u8);
        assert_eq!(values[1].flags, 1);
        assert_eq!(values[1].value_type, 0xb2);

        assert_eq!(unsafe { vdbe_unbind(&mut statement, 1) }, 0);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(RELEASE_ARG.load(Ordering::Relaxed), core::ptr::addr_of!(values[0]) as usize);
        assert_eq!(values[0].z, 0x1111usize as *mut u8);
        assert_eq!(values[0].flags, 1);
        assert_eq!(values[0].value_type, 0xa1);
    }
}
