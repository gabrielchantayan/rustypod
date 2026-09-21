//! Text parameter binding — SQLite's shared typed-binder implementation.
//!
//! - `sqlite_bind_text` — original: `FUN_082b78b0` @ 0x082b78b0 (180 bytes,
//!   0x082b78b0..0x082b7964; five internal plain `bl`, zero predicated `bl`).
//!
//! ### Algorithm
//!
//! `sqlite3_bind_text` first delegates statement and one-based parameter
//! validation to `vdbeUnbind`. On success and a non-NULL payload it installs
//! the text in `aVar[index - 1]`; a nonzero destructor marker then recodes the
//! value to the connection's configured encoding. It reports every result to
//! the connection and returns `sqlite3ApiExit`'s masked result.
//!
//! ### Deliberate deviations
//!
//! `sqlite3VdbeChangeEncoding` remains unported. This function reuses the
//! existing `VDBE_REAL_VALUE_OPS.change_encoding` seam: target builds branch
//! to retailOS 0x083869f4 and host tests install a recorder.

use super::api_exit::sqlite_api_exit;
use super::error::sqlite_error;
use super::value_set_str::vdbe_mem_set_str_op;
use super::vdbe::Vdbe;
use super::vdbe_real_value::VDBE_REAL_VALUE_OPS;
use super::vdbe_unbind::vdbe_unbind;

const DB_ENCODING_CONFIG_OFFSET: usize = 8;
const CONFIG_ENCODING_OFFSET: usize = 0x59;

#[inline(always)]
unsafe fn connection_encoding(db: *mut u8) -> u8 {
    let config = (db.add(DB_ENCODING_CONFIG_OFFSET) as *const u32).read() as *const u8;
    config.add(CONFIG_ENCODING_OFFSET).read()
}

/// sqlite_bind_text — original: `FUN_082b78b0` @ 0x082b78b0 (180 bytes;
/// five internal plain `bl`, zero predicated `bl`).
///
/// SQLite's internal `bindText`: validate `statement` and `parameter_index`,
/// install `text` as `length` bytes of encoding `encoding`, optionally recode
/// it to the owning connection's encoding, report the result, and return the
/// API-exit result. A NULL statement returns `SQLITE_MISUSE` directly; a NULL
/// text after successful validation leaves the NULL binding made by
/// `vdbe_unbind` intact.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_bind_text(
    statement: *mut Vdbe,
    parameter_index: i32,
    text: *mut u8,
    length: i32,
    encoding: u8,
    destructor: *mut u8,
) -> i32 {
    if statement.is_null() {
        return 21;
    }

    let result = vdbe_unbind(statement, parameter_index);
    if result != 0 || text.is_null() {
        return result;
    }

    let statement = &mut *statement;
    let value = statement.a_var.add((parameter_index - 1) as usize).cast();
    let mut result = (vdbe_mem_set_str_op())(value, text, length, encoding, destructor);
    if result == 0 && !destructor.is_null() {
        let change_encoding = core::ptr::read_volatile(core::ptr::addr_of!(VDBE_REAL_VALUE_OPS.change_encoding));
        result = change_encoding(value, connection_encoding(statement.db));
    }
    sqlite_error(statement.db, result, core::ptr::null(), core::ptr::null());
    sqlite_api_exit(statement.db, result)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::error::{DB_ERR_CODE_OFFSET, DB_P_ERR_OFFSET};
    use super::super::value_set_str::{VdbeMemSetStrFn, SQLITE_VDBE_MEM_SET_STR};
    use super::super::vdbe::{Mem, Vdbe};
    use super::super::vdbe_unbind::VDBE_MAGIC_RUN;
    use core::mem::MaybeUninit;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SET_CALLS: AtomicUsize = AtomicUsize::new(0);
    static EXPECTED_MEM: AtomicUsize = AtomicUsize::new(0);
    static SELECTED_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recording_set_str(mem: *mut u8, _text: *mut u8, _length: i32, _encoding: u8, _destructor: *mut u8) -> i32 {
        SET_CALLS.fetch_add(1, Ordering::Relaxed);
        if mem as usize == EXPECTED_MEM.load(Ordering::Relaxed) {
            SELECTED_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        0
    }

    struct SetStrGuard;
    impl Drop for SetStrGuard {
        fn drop(&mut self) {
            unsafe { SQLITE_VDBE_MEM_SET_STR = super::super::vdbe_mem_set_str::vdbe_mem_set_str; }
        }
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
        unsafe { (db.as_mut_ptr().cast::<u8>().add(DB_P_ERR_OFFSET) as *mut *mut u8).write((error_value as *mut Mem).cast()); }
    }

    #[test]
    fn null_statement_returns_misuse_without_calling_a_seam() {
        assert_eq!(unsafe { sqlite_bind_text(core::ptr::null_mut(), 1, core::ptr::null_mut(), 0, 1, core::ptr::null_mut()) }, 21);
    }

    #[test]
    fn invalid_or_out_of_range_binding_reports_the_unbind_error() {
        let mut db = [0usize; 32];
        let mut error_value = unsafe { MaybeUninit::<Mem>::zeroed().assume_init() };
        install_error_value(&mut db, &mut error_value);
        let mut values = [unsafe { MaybeUninit::<Mem>::zeroed().assume_init() }];
        let mut statement = statement(db.as_mut_ptr().cast(), &mut values);
        statement.pc = 0;
        assert_eq!(unsafe { sqlite_bind_text(&mut statement, 1, 1usize as *mut u8, 1, 1, core::ptr::null_mut()) }, 21);
        statement.pc = -1;
        assert_eq!(unsafe { sqlite_bind_text(&mut statement, 2, 1usize as *mut u8, 1, 1, core::ptr::null_mut()) }, 25);
        assert_eq!(unsafe { (db.as_ptr().cast::<u8>().add(DB_ERR_CODE_OFFSET) as *const i32).read() }, 25);
    }

    #[test]
    fn null_text_preserves_the_unbound_null_value() {
        let mut db = [0usize; 32];
        let mut error_value = unsafe { MaybeUninit::<Mem>::zeroed().assume_init() };
        install_error_value(&mut db, &mut error_value);
        let mut values = [unsafe { MaybeUninit::<Mem>::zeroed().assume_init() }];
        let mut statement = statement(db.as_mut_ptr().cast(), &mut values);
        assert_eq!(unsafe { sqlite_bind_text(&mut statement, 1, core::ptr::null_mut(), -1, 1, core::ptr::null_mut()) }, 0);
        assert_eq!(values[0].flags, 1);
    }

    #[test]
    fn valid_text_installs_the_selected_one_based_binding() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _restore = SetStrGuard;
        let mut db = [0usize; 32];
        let mut error_value = unsafe { MaybeUninit::<Mem>::zeroed().assume_init() };
        install_error_value(&mut db, &mut error_value);
        let mut values = [unsafe { MaybeUninit::<Mem>::zeroed().assume_init() }, unsafe { MaybeUninit::<Mem>::zeroed().assume_init() }];
        SET_CALLS.store(0, Ordering::Relaxed);
        SELECTED_CALLS.store(0, Ordering::Relaxed);
        EXPECTED_MEM.store(core::ptr::addr_of_mut!(values[1]) as usize, Ordering::Relaxed);
        unsafe { SQLITE_VDBE_MEM_SET_STR = recording_set_str as VdbeMemSetStrFn; }
        let mut statement = statement(db.as_mut_ptr().cast(), &mut values);
        let mut text = *b"ipod";
        assert_eq!(unsafe { sqlite_bind_text(&mut statement, 2, text.as_mut_ptr(), 4, 1, core::ptr::null_mut()) }, 0);
        assert_eq!(SET_CALLS.load(Ordering::Relaxed), 3);
        assert_eq!(SELECTED_CALLS.load(Ordering::Relaxed), 1);
    }
}
