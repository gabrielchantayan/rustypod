//! `sqlite3_lock_and_prepare` — original: `FUN_0837d2fc` @ **0x0837d2fc**
//! (92 bytes; 4 verified inbound direct `bl` call sites, all unconditional
//! plain `bl` at 0x0838167c, 0x08381fe0, 0x08390de8, and 0x08390e54; no
//! predicated forms).
//!
//! Raw `osos.dec` establishes the exact extent 0x0837d2fc..0x0837d358: 23
//! ARM words from `stmdb sp!,{r2,r3,r4,r5,r6,r7,r8,r9,r10,lr}` through
//! `ldmia sp!,{r2,r3,r4,r5,r6,r7,r8,r9,r10,pc}`; the next distinct function
//! begins with `stmdb sp!,{r0,r1,r2,r3}` at 0x0837d358. The body contains
//! exactly four `bl` instructions (0x08382be4, 0x083711a8, 0x083811c4,
//! 0x08371dc8), matching Ghidra's count.
//!
//! # Algorithm
//!
//! SQLite's `sqlite3LockAndPrepare`. Gate on the safety/type-tag check
//! (`opaque_type_tag_is_allowed` @ 0x08382be4, ported); rejection returns
//! `SQLITE_MISUSE` (21 = 0x15) without touching anything else. Otherwise
//! enter every database B-tree (`btree_enter_all` @ 0x083711a8), run the
//! six-argument prepare core @ 0x083811c4, leave every B-tree
//! (`btree_leave_all` @ 0x08371dc8, ported), and return the core's status.
//! The two stack-passed arguments arrive in r8/r9 via `ldrd [sp,#0x28]` and
//! are re-stacked for the core with `strd [sp,#0]`.
//!
//! Deliberate deviations: the two unported callees (`0x083711a8`,
//! `0x083811c4`) are volatile seams on host builds and retailOS calls on
//! firmware builds, following the `sqlite/prepare.rs` convention.

use crate::cxx::opaque_type_tag_is_allowed::{
    opaque_type_tag_is_allowed, OpaqueTypeTaggedObject,
};
use crate::sqlite::btree_lock::btree_leave_all;

/// SQLite `SQLITE_MISUSE` result, returned when the safety check rejects `db`.
pub const SQLITE_MISUSE: i32 = 21;

/// Unported `btree_enter_all` (`sqlite3BtreeEnterAll`) @ 0x083711a8.
pub type BtreeEnterAllFn = unsafe extern "C" fn(db: *mut u8);

/// Unported six-argument prepare core @ 0x083811c4.
pub type LockAndPrepareCoreFn = unsafe extern "C" fn(
    db: *mut u8,
    sql: *const u8,
    byte_count: i32,
    save_sql: i32,
    statement_out: *mut *mut u8,
    tail_out: *mut *const u8,
) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_btree_enter_all(db: *mut u8) {
    let enter_all: BtreeEnterAllFn = core::mem::transmute(0x0837_11a8usize);
    enter_all(db)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_lock_and_prepare_core(
    db: *mut u8, sql: *const u8, byte_count: i32, save_sql: i32,
    statement_out: *mut *mut u8, tail_out: *mut *const u8,
) -> i32 {
    let core_fn: LockAndPrepareCoreFn = core::mem::transmute(0x0838_11c4usize);
    core_fn(db, sql, byte_count, save_sql, statement_out, tail_out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_btree_enter_all(_db: *mut u8) {
    panic!("sqlite3_lock_and_prepare requires btree_enter_all @ 0x083711a8")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lock_and_prepare_core(
    _db: *mut u8, _sql: *const u8, _byte_count: i32, _save_sql: i32,
    _statement_out: *mut *mut u8, _tail_out: *mut *const u8,
) -> i32 {
    panic!("sqlite3_lock_and_prepare requires the prepare core @ 0x083811c4")
}

#[cfg(target_os = "none")]
pub const DEFAULT_ENTER_ALL_OP: BtreeEnterAllFn = retail_btree_enter_all;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_ENTER_ALL_OP: BtreeEnterAllFn = missing_btree_enter_all;

#[cfg(target_os = "none")]
pub const DEFAULT_CORE_OP: LockAndPrepareCoreFn = retail_lock_and_prepare_core;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_CORE_OP: LockAndPrepareCoreFn = missing_lock_and_prepare_core;

/// Active `btree_enter_all` target, replaceable by host tests and a future port.
pub static mut ENTER_ALL_OP: BtreeEnterAllFn = DEFAULT_ENTER_ALL_OP;
/// Active prepare-core target, replaceable by host tests and a future port.
pub static mut CORE_OP: LockAndPrepareCoreFn = DEFAULT_CORE_OP;

#[inline(always)]
unsafe fn enter_all_op() -> BtreeEnterAllFn {
    core::ptr::read_volatile(core::ptr::addr_of!(ENTER_ALL_OP))
}

#[inline(always)]
unsafe fn core_op() -> LockAndPrepareCoreFn {
    core::ptr::read_volatile(core::ptr::addr_of!(CORE_OP))
}

/// sqlite3_lock_and_prepare — original: `FUN_0837d2fc` @ 0x0837d2fc (92
/// bytes; 4 unconditional plain `bl` call sites, binary-scanned).
///
/// Lock every B-tree of `db`, prepare `sql` (of `byte_count` bytes, or
/// NUL-terminated when negative) into `statement_out`, then unlock. When
/// `save_sql` is nonzero the core retains the SQL text for re-preparation;
/// when `tail_out` is non-null it receives a pointer past the consumed SQL.
/// Returns `SQLITE_MISUSE` immediately when the safety check rejects `db`.
///
/// # Safety
/// `db` must be a valid SQLite connection readable as an
/// [`OpaqueTypeTaggedObject`] and by the enter/leave walkers; all other
/// pointers must satisfy the retail prepare core's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_lock_and_prepare(
    db: *mut u8,
    sql: *const u8,
    byte_count: i32,
    save_sql: i32,
    statement_out: *mut *mut u8,
    tail_out: *mut *const u8,
) -> i32 {
    if opaque_type_tag_is_allowed(db as *const OpaqueTypeTaggedObject) == 0 {
        return SQLITE_MISUSE;
    }
    enter_all_op()(db);
    let result = core_op()(db, sql, byte_count, save_sql, statement_out, tail_out);
    btree_leave_all(db);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::opaque_type_tag_is_allowed::OPAQUE_TYPE_TAG_A;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const TAG_OFFSET: usize = 0x40;
    const DB_COUNT_OFFSET: usize = 0x04;
    const DATABASES_OFFSET: usize = 0x08;
    const RECORDS_OFFSET: usize = 0x100;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_LOCK_AND_PREPARE, FIXTURE_LEN).map(|p| p as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    /// A db fixture readable both as the tag-checked object and by the
    /// `btree_leave_all` walker, mapped below 4 GiB so the walker's
    /// target-width `aDb` pointer is real.
    unsafe fn database(n_db: i32) -> Option<*mut u8> {
        let db = (*FIXTURE)? as *mut u8;
        db.write_bytes(0, FIXTURE_LEN);
        db.add(DB_COUNT_OFFSET).cast::<i32>().write(n_db);
        db.add(DATABASES_OFFSET)
            .cast::<u32>()
            .write(db.add(RECORDS_OFFSET) as usize as u32);
        db.add(TAG_OFFSET).cast::<u32>().write(OPAQUE_TYPE_TAG_A);
        Some(db)
    }

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static CALL_LOG: Mutex<std::vec::Vec<&'static str>> = Mutex::new(std::vec::Vec::new());
    static CORE_RESULT: AtomicI32 = AtomicI32::new(0);
    static GOT_DB: AtomicUsize = AtomicUsize::new(0);
    static GOT_SQL: AtomicUsize = AtomicUsize::new(0);
    static GOT_BYTE_COUNT: AtomicI32 = AtomicI32::new(0);
    static GOT_SAVE_SQL: AtomicI32 = AtomicI32::new(0);
    static GOT_STATEMENT_OUT: AtomicUsize = AtomicUsize::new(0);
    static GOT_TAIL_OUT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recording_enter_all(db: *mut u8) {
        CALL_LOG.lock().push("enter_all");
        GOT_DB.store(db as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn recording_core(
        db: *mut u8,
        sql: *const u8,
        byte_count: i32,
        save_sql: i32,
        statement_out: *mut *mut u8,
        tail_out: *mut *const u8,
    ) -> i32 {
        CALL_LOG.lock().push("core");
        GOT_DB.store(db as usize, Ordering::SeqCst);
        GOT_SQL.store(sql as usize, Ordering::SeqCst);
        GOT_BYTE_COUNT.store(byte_count, Ordering::SeqCst);
        GOT_SAVE_SQL.store(save_sql, Ordering::SeqCst);
        GOT_STATEMENT_OUT.store(statement_out as usize, Ordering::SeqCst);
        GOT_TAIL_OUT.store(tail_out as usize, Ordering::SeqCst);
        CORE_RESULT.load(Ordering::SeqCst)
    }

    struct OpsGuard;
    impl OpsGuard {
        fn install() -> Self {
            unsafe {
                ENTER_ALL_OP = recording_enter_all;
                CORE_OP = recording_core;
            }
            OpsGuard
        }
    }
    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                ENTER_ALL_OP = DEFAULT_ENTER_ALL_OP;
                CORE_OP = DEFAULT_CORE_OP;
            }
        }
    }

    #[test]
    fn rejected_database_returns_misuse_without_calling_anything() {
        let _lock = OPS_LOCK.lock();
        let _ops = OpsGuard::install();
        CALL_LOG.lock().clear();

        let Some(db) = (unsafe { database(0) }) else {
            note_missing_u32_fixture("sqlite/lock_and_prepare");
            return;
        };
        unsafe { db.add(TAG_OFFSET).cast::<u32>().write(0xdead_beef) };
        let result = unsafe {
            sqlite3_lock_and_prepare(
                db,
                b"select 1\0".as_ptr(),
                -1,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, SQLITE_MISUSE);
        assert!(CALL_LOG.lock().is_empty());
    }

    #[test]
    fn null_database_returns_misuse() {
        let _lock = OPS_LOCK.lock();
        let _ops = OpsGuard::install();
        CALL_LOG.lock().clear();

        let result = unsafe {
            sqlite3_lock_and_prepare(
                core::ptr::null_mut(),
                b"select 1\0".as_ptr(),
                -1,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, SQLITE_MISUSE);
        assert!(CALL_LOG.lock().is_empty());
    }

    #[test]
    fn accepted_database_enters_prepares_leaves_and_forwards_arguments() {
        let _lock = OPS_LOCK.lock();
        let _ops = OpsGuard::install();
        CALL_LOG.lock().clear();
        CORE_RESULT.store(26, Ordering::SeqCst); /* SQLITE_NOTADB-style propagation check */

        let Some(db_ptr) = (unsafe { database(0) }) else {
            note_missing_u32_fixture("sqlite/lock_and_prepare");
            return;
        };
        let sql = b"select 1;\0";
        let mut statement: *mut u8 = core::ptr::null_mut();
        let mut tail: *const u8 = core::ptr::null();

        let result = unsafe {
            sqlite3_lock_and_prepare(
                db_ptr,
                sql.as_ptr(),
                9,
                1,
                &mut statement,
                &mut tail,
            )
        };

        assert_eq!(result, 26);
        assert_eq!(&*CALL_LOG.lock(), &["enter_all", "core"]);
        assert_eq!(GOT_DB.load(Ordering::SeqCst), db_ptr as usize);
        assert_eq!(GOT_SQL.load(Ordering::SeqCst), sql.as_ptr() as usize);
        assert_eq!(GOT_BYTE_COUNT.load(Ordering::SeqCst), 9);
        assert_eq!(GOT_SAVE_SQL.load(Ordering::SeqCst), 1);
        assert_eq!(
            GOT_STATEMENT_OUT.load(Ordering::SeqCst),
            &mut statement as *mut _ as usize
        );
        assert_eq!(GOT_TAIL_OUT.load(Ordering::SeqCst), &mut tail as *mut _ as usize);
    }

    #[test]
    fn walker_leave_all_skips_null_btree_after_core() {
        let _lock = OPS_LOCK.lock();
        let _fixture_guard = FIXTURE_LOCK.lock();
        let _ops = OpsGuard::install();
        CALL_LOG.lock().clear();
        CORE_RESULT.store(0, Ordering::SeqCst);

        // One Db record with a null pBt: the ported leave walker must read
        // n_db/aDb yet skip the record, proving leave runs against our db.
        let Some(db) = (unsafe { database(1) }) else {
            note_missing_u32_fixture("sqlite/lock_and_prepare");
            return;
        };

        let result = unsafe {
            sqlite3_lock_and_prepare(
                db,
                b"x\0".as_ptr(),
                1,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0);
        assert_eq!(&*CALL_LOG.lock(), &["enter_all", "core"]);
    }
}
