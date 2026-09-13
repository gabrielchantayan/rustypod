//! Execute SQL statements yielded by another SQL statement — original:
//! `FUN_082ccec4` @ `0x082ccec4` (116 bytes; six verified inbound direct
//! `bl` call sites, all unconditional: `0x083829cc`, `0x083829e0`,
//! `0x083829f4`, `0x08382a08`, `0x08382a1c`, and `0x08382a30`).
//!
//! Raw `osos.dec` confirms the exact extent `0x082ccec4..0x082ccf38`: it
//! prepares `query` with a NULL tail, steps it, and, for every `SQLITE_ROW`,
//! executes column zero as a new SQL string. It finalizes the outer statement
//! on a terminal step result or execution failure; on success it returns the
//! finalizer's result, while an inner-execution failure is preserved across
//! finalization. A prepare failure returns immediately without finalizing.
//!
//! Deliberate deviation: the three still-unported direct callees are exposed
//! as volatile seams. `sqlite3_step` and `sqlite3_finalize` are existing Rust
//! ports and are called directly.

use core::ptr::null_mut;

const SQLITE_ROW: i32 = 100;

/// `sqlite3_prepare_v2` wrapper @ `0x08390dcc`.
pub type PrepareV2Fn = unsafe extern "C" fn(
    db: *mut u8,
    query: *const u8,
    byte_count: i32,
    statement_out: *mut *mut u8,
    tail_out: *mut *const u8,
) -> i32;
/// `sqlite3_column_text` @ `0x0838fae4`.
pub type ColumnTextFn = unsafe extern "C" fn(statement: *mut u8, column: i32) -> *const u8;
/// Execute one SQL string to completion (`FUN_082ccf38` @ `0x082ccf38`).
pub type ExecuteSqlFn = unsafe extern "C" fn(db: *mut u8, query: *const u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_prepare_v2(
    db: *mut u8,
    query: *const u8,
    byte_count: i32,
    statement_out: *mut *mut u8,
    tail_out: *mut *const u8,
) -> i32 {
    let prepare: PrepareV2Fn = core::mem::transmute(0x0839_0dccusize);
    prepare(db, query, byte_count, statement_out, tail_out)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_column_text(statement: *mut u8, column: i32) -> *const u8 {
    let column_text: ColumnTextFn = core::mem::transmute(0x0838_fae4usize);
    column_text(statement, column)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_execute_sql(db: *mut u8, query: *const u8) -> i32 {
    let execute: ExecuteSqlFn = core::mem::transmute(0x082c_cf38usize);
    execute(db, query)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare_v2(
    _db: *mut u8,
    _query: *const u8,
    _byte_count: i32,
    _statement_out: *mut *mut u8,
    _tail_out: *mut *const u8,
) -> i32 {
    panic!("sqlite3_exec_first_column_sql requires sqlite3_prepare_v2 @ 0x08390dcc")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_column_text(_statement: *mut u8, _column: i32) -> *const u8 {
    panic!("sqlite3_exec_first_column_sql requires sqlite3_column_text @ 0x0838fae4")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_execute_sql(_db: *mut u8, _query: *const u8) -> i32 {
    panic!("sqlite3_exec_first_column_sql requires executor @ 0x082ccf38")
}

/// The unported direct calls made by [`sqlite3_exec_first_column_sql`].
#[derive(Clone, Copy)]
pub struct ExecFirstColumnSqlOps {
    pub prepare_v2: PrepareV2Fn,
    pub column_text: ColumnTextFn,
    pub execute_sql: ExecuteSqlFn,
}

#[cfg(target_os = "none")]
pub const DEFAULT_EXEC_FIRST_COLUMN_SQL_OPS: ExecFirstColumnSqlOps = ExecFirstColumnSqlOps {
    prepare_v2: retail_prepare_v2,
    column_text: retail_column_text,
    execute_sql: retail_execute_sql,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_EXEC_FIRST_COLUMN_SQL_OPS: ExecFirstColumnSqlOps = ExecFirstColumnSqlOps {
    prepare_v2: missing_prepare_v2,
    column_text: missing_column_text,
    execute_sql: missing_execute_sql,
};

/// Active unported-call targets, replaceable by host tests and future ports.
pub static mut EXEC_FIRST_COLUMN_SQL_OPS: ExecFirstColumnSqlOps = DEFAULT_EXEC_FIRST_COLUMN_SQL_OPS;

#[inline(always)]
unsafe fn exec_first_column_sql_ops() -> ExecFirstColumnSqlOps {
    core::ptr::read_volatile(core::ptr::addr_of!(EXEC_FIRST_COLUMN_SQL_OPS))
}

/// Prepare `query`, execute every UTF-8 SQL string from column zero, and
/// return the finalization status of the prepared query.
///
/// # Safety
/// `db` and `query` must meet SQLite's `sqlite3_prepare_v2` contract. Every
/// statement and text pointer returned by the configured operations must meet
/// the contracts of `sqlite3_step`, `sqlite3_finalize`, and the SQL executor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_exec_first_column_sql(
    db: *mut u8,
    query: *const u8,
) -> i32 {
    let ops = exec_first_column_sql_ops();
    let mut statement = null_mut();
    let prepare_result = (ops.prepare_v2)(db, query, -1, &mut statement, null_mut());
    if prepare_result != 0 {
        return prepare_result;
    }

    loop {
        let step_result = crate::sqlite::step::sqlite3_step(statement);
        if step_result != SQLITE_ROW {
            return crate::sqlite::finalize::sqlite3_finalize(statement.cast());
        }

        let row_sql = (ops.column_text)(statement, 0);
        let execute_result = (ops.execute_sql)(db, row_sql);
        if execute_result != 0 {
            crate::sqlite::finalize::sqlite3_finalize(statement.cast());
            return execute_result;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::api_exit::DB_ERR_MASK_OFFSET;
    use crate::sqlite::finalize::{FinalizeOps, FINALIZE_OPS};
    use crate::sqlite::step::{SQLITE_VDBE_REPREPARE, SQLITE_VDBE_RESET, SQLITE_VDBE_STEP};
    use crate::sqlite::vdbe::Vdbe;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_BYTES: usize = 0x1000;
    const STATEMENT_OFFSET: usize = 0x100;
    const DB_OFFSET: usize = 0x500;
    const EVENT_PREPARE: u8 = 1;
    const EVENT_STEP: u8 = 2;
    const EVENT_COLUMN: u8 = 3;
    const EVENT_EXECUTE: u8 = 4;
    const EVENT_LRU_REMOVE: u8 = 5;
    const EVENT_FINALIZE: u8 = 6;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<std::vec::Vec<u8>> = Mutex::new(std::vec::Vec::new());
    static PREPARE_RESULT: AtomicI32 = AtomicI32::new(0);
    static EXECUTE_RESULT: AtomicI32 = AtomicI32::new(0);
    static FINALIZE_RESULT: AtomicI32 = AtomicI32::new(0);
    static STEP_INDEX: AtomicUsize = AtomicUsize::new(0);
    static STEP_RESULTS: [AtomicI32; 3] = [AtomicI32::new(0), AtomicI32::new(0), AtomicI32::new(0)];

    fn slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            try_map_u32_slab(hints::SQLITE_EXEC_FIRST_COLUMN_SQL, SLAB_BYTES)
                .map(|pointer| pointer as usize)
        });
        SLAB.map(|pointer| pointer as *mut u8)
    }

    fn record(event: u8) {
        EVENTS.lock().push(event);
    }

    unsafe extern "C" fn recording_prepare(
        _db: *mut u8,
        _query: *const u8,
        byte_count: i32,
        statement_out: *mut *mut u8,
        tail_out: *mut *const u8,
    ) -> i32 {
        record(EVENT_PREPARE);
        assert_eq!(byte_count, -1);
        assert!(tail_out.is_null());
        if PREPARE_RESULT.load(Ordering::SeqCst) == 0 {
            *statement_out = slab().unwrap().add(STATEMENT_OFFSET);
        }
        PREPARE_RESULT.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn empty_statement_prepare(
        _db: *mut u8,
        _query: *const u8,
        byte_count: i32,
        statement_out: *mut *mut u8,
        tail_out: *mut *const u8,
    ) -> i32 {
        record(EVENT_PREPARE);
        assert_eq!(byte_count, -1);
        assert!(tail_out.is_null());
        *statement_out = null_mut();
        0
    }

    unsafe extern "C" fn recording_step(_statement: *mut u8) -> i32 {
        record(EVENT_STEP);
        let index = STEP_INDEX.fetch_add(1, Ordering::SeqCst);
        STEP_RESULTS[index].load(Ordering::SeqCst)
    }

    unsafe extern "C" fn recording_reset(_statement: *mut u8) -> i32 {
        panic!("row fixture must not reprepare")
    }

    unsafe extern "C" fn recording_column(statement: *mut u8, column: i32) -> *const u8 {
        record(EVENT_COLUMN);
        assert_eq!(statement, slab().unwrap().add(STATEMENT_OFFSET));
        assert_eq!(column, 0);
        b"DELETE FROM temp.rows\0".as_ptr()
    }

    unsafe extern "C" fn recording_execute(_db: *mut u8, query: *const u8) -> i32 {
        record(EVENT_EXECUTE);
        assert_eq!(query, b"DELETE FROM temp.rows\0".as_ptr());
        EXECUTE_RESULT.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn recording_lru_remove(_statement: *mut Vdbe) {
        record(EVENT_LRU_REMOVE);
    }

    unsafe extern "C" fn recording_finalize(_statement: *mut Vdbe) -> i32 {
        record(EVENT_FINALIZE);
        FINALIZE_RESULT.load(Ordering::SeqCst)
    }

    unsafe fn reset_fixture() {
        EVENTS.lock().clear();
        PREPARE_RESULT.store(0, Ordering::SeqCst);
        EXECUTE_RESULT.store(0, Ordering::SeqCst);
        FINALIZE_RESULT.store(0, Ordering::SeqCst);
        STEP_INDEX.store(0, Ordering::SeqCst);
        for result in &STEP_RESULTS {
            result.store(0, Ordering::SeqCst);
        }
        if let Some(slab) = slab() {
            slab.write_bytes(0, SLAB_BYTES);
            let statement = slab.add(STATEMENT_OFFSET);
            let db = slab.add(DB_OFFSET);
            statement.cast::<u32>().write(db as usize as u32);
            (db.add(DB_ERR_MASK_OFFSET) as *mut i32).write(-1);
        }
    }

    unsafe fn with_recording_ops(prepare: PrepareV2Fn, body: impl FnOnce()) {
        let _guard = OPS_LOCK.lock();
        let saved_exec_ops = core::ptr::read_volatile(core::ptr::addr_of!(EXEC_FIRST_COLUMN_SQL_OPS));
        let saved_step = core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_STEP));
        let saved_reprepare = core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_REPREPARE));
        let saved_reset = core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_RESET));
        let saved_finalize_ops = core::ptr::read_volatile(core::ptr::addr_of!(FINALIZE_OPS));
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(EXEC_FIRST_COLUMN_SQL_OPS),
            ExecFirstColumnSqlOps {
                prepare_v2: prepare,
                column_text: recording_column,
                execute_sql: recording_execute,
            },
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_STEP), recording_step);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_REPREPARE), recording_reset);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_RESET), recording_reset);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(FINALIZE_OPS),
            FinalizeOps {
                stmt_lru_remove: recording_lru_remove,
                vdbe_finalize: recording_finalize,
            },
        );
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(EXEC_FIRST_COLUMN_SQL_OPS), saved_exec_ops);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_STEP), saved_step);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_REPREPARE), saved_reprepare);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_RESET), saved_reset);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FINALIZE_OPS), saved_finalize_ops);
    }

    #[test]
    fn prepare_failure_returns_without_step_or_finalization() {
        unsafe {
            reset_fixture();
            PREPARE_RESULT.store(7, Ordering::SeqCst);
            with_recording_ops(recording_prepare, || {
                assert_eq!(sqlite3_exec_first_column_sql(core::ptr::null_mut(), b"bad\0".as_ptr()), 7);
            });
            assert_eq!(*EVENTS.lock(), [EVENT_PREPARE]);
        }
    }

    #[test]
    fn empty_prepared_query_returns_null_statement_finalization_status() {
        unsafe {
            reset_fixture();
            with_recording_ops(empty_statement_prepare, || {
                assert_eq!(sqlite3_exec_first_column_sql(core::ptr::null_mut(), b"-- comment\0".as_ptr()), 0);
            });
            assert_eq!(*EVENTS.lock(), [EVENT_PREPARE]);
        }
    }

    #[test]
    fn rows_execute_column_zero_then_return_outer_finalizer_status() {
        let Some(_) = slab() else {
            note_missing_u32_fixture("sqlite::exec_first_column_sql");
            return;
        };
        unsafe {
            reset_fixture();
            STEP_RESULTS[0].store(SQLITE_ROW, Ordering::SeqCst);
            STEP_RESULTS[1].store(101, Ordering::SeqCst);
            FINALIZE_RESULT.store(17, Ordering::SeqCst);
            with_recording_ops(recording_prepare, || {
                assert_eq!(sqlite3_exec_first_column_sql(slab().unwrap().add(DB_OFFSET), b"SELECT sql\0".as_ptr()), 17);
            });
            assert_eq!(
                *EVENTS.lock(),
                [EVENT_PREPARE, EVENT_STEP, EVENT_COLUMN, EVENT_EXECUTE, EVENT_STEP, EVENT_LRU_REMOVE, EVENT_FINALIZE]
            );
        }
    }

    #[test]
    fn execution_failure_is_preserved_after_outer_statement_finalization() {
        let Some(_) = slab() else {
            note_missing_u32_fixture("sqlite::exec_first_column_sql");
            return;
        };
        unsafe {
            reset_fixture();
            STEP_RESULTS[0].store(SQLITE_ROW, Ordering::SeqCst);
            EXECUTE_RESULT.store(19, Ordering::SeqCst);
            FINALIZE_RESULT.store(7, Ordering::SeqCst);
            with_recording_ops(recording_prepare, || {
                assert_eq!(sqlite3_exec_first_column_sql(slab().unwrap().add(DB_OFFSET), b"SELECT sql\0".as_ptr()), 19);
            });
            assert_eq!(
                *EVENTS.lock(),
                [EVENT_PREPARE, EVENT_STEP, EVENT_COLUMN, EVENT_EXECUTE, EVENT_LRU_REMOVE, EVENT_FINALIZE]
            );
        }
    }
}
