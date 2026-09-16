//! Legacy SQLite prepare wrapper — `FUN_08390dcc` @ `0x08390dcc` (36 bytes;
//! four verified inbound direct `bl` call sites, all unconditional: `0x082159fc`,
//! `0x082ccedc`, `0x082ccf60`, and `0x08390394`).
//!
//! Raw `osos.dec` establishes the exact extent `0x08390dcc..0x08390df0`: ten
//! ARM words from `stmdb sp!,{r2,r3,r4,lr}` through `ldmia sp!,{r2,r3,r4,pc}`.
//! It forwards its five arguments to `0x0837d2fc`, inserting a zero fourth
//! argument and moving the final two arguments to the callee stack.
//!
//! Deliberate deviation: `0x0837d2fc` (now ported as
//! `sqlite::lock_and_prepare::sqlite3_lock_and_prepare`) remains a volatile
//! seam on host builds and a retailOS call on firmware builds, so host tests
//! can substitute the whole preparation operation.

/// Internal six-argument SQLite preparation operation at `0x0837d2fc`.
pub type LockAndPrepareFn = unsafe extern "C" fn(
    db: *mut u8,
    sql: *const u8,
    byte_count: i32,
    save_sql: i32,
    statement_out: *mut *mut u8,
    tail_out: *mut *const u8,
) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_lock_and_prepare(
    db: *mut u8, sql: *const u8, byte_count: i32, save_sql: i32,
    statement_out: *mut *mut u8, tail_out: *mut *const u8,
) -> i32 {
    let lock_and_prepare: LockAndPrepareFn = core::mem::transmute(0x0837_d2fcusize);
    lock_and_prepare(db, sql, byte_count, save_sql, statement_out, tail_out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lock_and_prepare(
    _db: *mut u8, _sql: *const u8, _byte_count: i32, _save_sql: i32,
    _statement_out: *mut *mut u8, _tail_out: *mut *const u8,
) -> i32 {
    panic!("sqlite3_prepare requires SQLite preparation operation @ 0x0837d2fc")
}

#[cfg(target_os = "none")]
pub const DEFAULT_PREPARE_OP: LockAndPrepareFn = retail_lock_and_prepare;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_PREPARE_OP: LockAndPrepareFn = missing_lock_and_prepare;

/// Active unported-call target, replaceable by host tests and a future port.
pub static mut PREPARE_OP: LockAndPrepareFn = DEFAULT_PREPARE_OP;

#[inline(always)]
unsafe fn prepare_op() -> LockAndPrepareFn {
    core::ptr::read_volatile(core::ptr::addr_of!(PREPARE_OP))
}

/// Prepare SQL without retaining its source text for automatic re-preparation.
///
/// # Safety
/// All pointers must satisfy the retail SQLite preparation operation's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_prepare(
    db: *mut u8,
    sql: *const u8,
    byte_count: i32,
    statement_out: *mut *mut u8,
    tail_out: *mut *const u8,
) -> i32 {
    prepare_op()(db, sql, byte_count, 0, statement_out, tail_out)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static RETURN_VALUE: AtomicI32 = AtomicI32::new(0);
    static DB: AtomicUsize = AtomicUsize::new(0);
    static SQL: AtomicUsize = AtomicUsize::new(0);
    static BYTE_COUNT: AtomicI32 = AtomicI32::new(0);
    static STATEMENT_OUT: AtomicUsize = AtomicUsize::new(0);
    static TAIL_OUT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recording_lock_and_prepare(
        db: *mut u8, sql: *const u8, byte_count: i32, save_sql: i32,
        statement_out: *mut *mut u8, tail_out: *mut *const u8,
    ) -> i32 {
        assert_eq!(save_sql, 0);
        DB.store(db as usize, Ordering::SeqCst);
        SQL.store(sql as usize, Ordering::SeqCst);
        BYTE_COUNT.store(byte_count, Ordering::SeqCst);
        STATEMENT_OUT.store(statement_out as usize, Ordering::SeqCst);
        TAIL_OUT.store(tail_out as usize, Ordering::SeqCst);
        RETURN_VALUE.load(Ordering::SeqCst)
    }

    unsafe fn with_prepare_op(body: impl FnOnce()) {
        let _guard = OPS_LOCK.lock();
        let saved = core::ptr::read_volatile(core::ptr::addr_of!(PREPARE_OP));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PREPARE_OP), recording_lock_and_prepare);
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PREPARE_OP), saved);
    }

    #[test]
    fn forwards_all_pointer_arguments_and_byte_count() { unsafe {
        let mut statement = core::ptr::null_mut();
        let mut tail = core::ptr::null();
        let db = 0x1000usize as *mut u8;
        let sql = b"select 1\0".as_ptr();
        RETURN_VALUE.store(17, Ordering::SeqCst);
        with_prepare_op(|| assert_eq!(sqlite3_prepare(db, sql, -1, &mut statement, &mut tail), 17));
        assert_eq!(DB.load(Ordering::SeqCst), db as usize);
        assert_eq!(SQL.load(Ordering::SeqCst), sql as usize);
        assert_eq!(BYTE_COUNT.load(Ordering::SeqCst), -1);
        assert_eq!(STATEMENT_OUT.load(Ordering::SeqCst), core::ptr::addr_of_mut!(statement) as usize);
        assert_eq!(TAIL_OUT.load(Ordering::SeqCst), core::ptr::addr_of_mut!(tail) as usize);
    }}

    #[test]
    fn preserves_error_results_with_null_optional_outputs() { unsafe {
        RETURN_VALUE.store(-7, Ordering::SeqCst);
        with_prepare_op(|| assert_eq!(sqlite3_prepare(core::ptr::null_mut(), core::ptr::null(), 0, core::ptr::null_mut(), core::ptr::null_mut()), -7));
        assert_eq!(DB.load(Ordering::SeqCst), 0);
        assert_eq!(SQL.load(Ordering::SeqCst), 0);
        assert_eq!(BYTE_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(STATEMENT_OUT.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_OUT.load(Ordering::SeqCst), 0);
    }}
}
