//! Execute one SQL string — `FUN_082ccf38` @ `0x082ccf38` (92 bytes; five
//! verified inbound direct `bl` call sites, all unconditional: `0x082ccf00`,
//! `0x083828f4`, `0x08382988`, `0x083829b8`, and `0x08382a44`).
//!
//! Raw `osos.dec` establishes the exact extent `0x082ccf38..0x082ccf94`; the
//! next real function begins with `push {r0-r2,r4-r11,lr}` at `0x082ccf94`.
//! It prepares `query` with length -1 and NULL tail, returns the connection
//! error code if preparation fails, otherwise steps until a result other than
//! `SQLITE_ROW` and returns `sqlite3_finalize`'s result.
//!
//! Deliberate deviation: `sqlite3_prepare_v2` and `sqlite3_errcode` remain
//! volatile seams because their bodies are not ported; `sqlite3_step` and
//! `sqlite3_finalize` are existing Rust ports.

use core::ptr::null_mut;

const SQLITE_ROW: i32 = 100;

/// `sqlite3_prepare_v2` @ `0x08390dcc`.
pub type PrepareV2Fn = unsafe extern "C" fn(
    db: *mut u8, query: *const u8, byte_count: i32, statement_out: *mut *mut u8,
    tail_out: *mut *const u8,
) -> i32;
/// `sqlite3_errcode` @ `0x0839020c`.
pub type ErrorCodeFn = unsafe extern "C" fn(db: *mut u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_prepare_v2(db: *mut u8, query: *const u8, byte_count: i32, statement_out: *mut *mut u8, tail_out: *mut *const u8) -> i32 {
    let prepare: PrepareV2Fn = core::mem::transmute(0x0839_0dccusize);
    prepare(db, query, byte_count, statement_out, tail_out)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_error_code(db: *mut u8) -> i32 {
    let error_code: ErrorCodeFn = core::mem::transmute(0x0839_020cusize);
    error_code(db)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare_v2(_db: *mut u8, _query: *const u8, _byte_count: i32, _statement_out: *mut *mut u8, _tail_out: *mut *const u8) -> i32 {
    panic!("sqlite3_execute_sql requires sqlite3_prepare_v2 @ 0x08390dcc")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_error_code(_db: *mut u8) -> i32 {
    panic!("sqlite3_execute_sql requires sqlite3_errcode @ 0x0839020c")
}

/// The unported direct calls made by [`sqlite3_execute_sql`].
#[derive(Clone, Copy)]
pub struct ExecuteSqlOps { pub prepare_v2: PrepareV2Fn, pub error_code: ErrorCodeFn }
#[cfg(target_os = "none")]
pub const DEFAULT_EXECUTE_SQL_OPS: ExecuteSqlOps = ExecuteSqlOps { prepare_v2: retail_prepare_v2, error_code: retail_error_code };
#[cfg(not(target_os = "none"))]
pub const DEFAULT_EXECUTE_SQL_OPS: ExecuteSqlOps = ExecuteSqlOps { prepare_v2: missing_prepare_v2, error_code: missing_error_code };
/// Active unported-call targets, replaceable by host tests and future ports.
pub static mut EXECUTE_SQL_OPS: ExecuteSqlOps = DEFAULT_EXECUTE_SQL_OPS;

#[inline(always)]
unsafe fn execute_sql_ops() -> ExecuteSqlOps {
    core::ptr::read_volatile(core::ptr::addr_of!(EXECUTE_SQL_OPS))
}

/// Prepare `query`, discard rows, and return its finalization status.
///
/// # Safety
/// `db` and `query` must meet SQLite's `sqlite3_prepare_v2` contract. The
/// configured prepare operation must initialize `statement_out` on success.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_execute_sql(db: *mut u8, query: *const u8) -> i32 {
    let ops = execute_sql_ops();
    let mut statement = null_mut();
    if (ops.prepare_v2)(db, query, -1, &mut statement, null_mut()) != 0 {
        return (ops.error_code)(db);
    }
    while crate::sqlite::step::sqlite3_step(statement) == SQLITE_ROW {}
    crate::sqlite::finalize::sqlite3_finalize(statement.cast())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicI32, Ordering};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static PREPARE_RESULT: AtomicI32 = AtomicI32::new(0);
    static ERROR_CODE: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn prepare(_db: *mut u8, _query: *const u8, count: i32, out: *mut *mut u8, tail: *mut *const u8) -> i32 {
        assert_eq!(count, -1);
        assert!(tail.is_null());
        *out = null_mut();
        PREPARE_RESULT.load(Ordering::SeqCst)
    }
    unsafe extern "C" fn error_code(_db: *mut u8) -> i32 { ERROR_CODE.load(Ordering::SeqCst) }

    unsafe fn with_ops(body: impl FnOnce()) {
        let _guard = OPS_LOCK.lock();
        let saved = core::ptr::read_volatile(core::ptr::addr_of!(EXECUTE_SQL_OPS));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(EXECUTE_SQL_OPS), ExecuteSqlOps { prepare_v2: prepare, error_code });
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(EXECUTE_SQL_OPS), saved);
    }

    #[test]
    fn preparation_failure_returns_connection_error_code() { unsafe {
        PREPARE_RESULT.store(7, Ordering::SeqCst);
        ERROR_CODE.store(19, Ordering::SeqCst);
        with_ops(|| assert_eq!(sqlite3_execute_sql(null_mut(), b"bad\0".as_ptr()), 19));
    }}

    #[test]
    fn empty_query_finalizes_the_null_statement_after_the_terminal_step() { unsafe {
        PREPARE_RESULT.store(0, Ordering::SeqCst);
        with_ops(|| assert_eq!(sqlite3_execute_sql(null_mut(), b"-- comment\0".as_ptr()), 0));
    }}
}
