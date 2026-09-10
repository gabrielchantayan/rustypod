//! The public SQLite prepared-statement finalizer.
//!
//! - `sqlite3_finalize` — original: `FUN_083906d4` @ `0x083906d4`
//!   (32 bytes; 10 direct `bl` call sites verified by decoding every ARM
//!   branch word in `osos.dec`: 8 unconditional `bl`, 2 `blne`).
//!
//! Raw ARM is a NULL guard followed by `bl 0x08391d64` and a tail `b`
//! to `0x0838af84`. The first callee is SQLite's private statement-LRU
//! unlink (`stmtLruRemove`): it detaches the Vdbe from the global head/tail
//! list through its `+0x150`/`+0x154` links. The tail target is
//! `sqlite3VdbeFinalize`, which halts and destroys the statement and returns
//! its SQLite status. Thus NULL returns `SQLITE_OK` (zero); otherwise unlink
//! precedes finalization and the finalizer's status is returned unchanged.
//!
//! The eight plain sites finalize statements after stepping or preparing;
//! both predicated sites (`0x0838f648`, `0x08390558`) first prove the
//! statement pointer non-NULL. This body retains its own NULL guard because
//! the other eight callers do not supply one.
//!
//! Deliberate deviation: neither direct callee is ported. Target builds call
//! their exact retailOS load addresses through volatile, replaceable seams;
//! host tests install recorders. No mutex call appears in the verified
//! 32-byte body, so none is introduced here.

use super::vdbe::Vdbe;

/// RetailOS load address of SQLite's private `stmtLruRemove` helper.
pub const STMT_LRU_REMOVE_ADDRESS: usize = 0x0839_1d64;
/// RetailOS load address of `sqlite3VdbeFinalize`.
pub const VDBE_FINALIZE_ADDRESS: usize = 0x0838_af84;

/// Detach one Vdbe from SQLite's statement-memory LRU.
pub type StatementLruRemove = unsafe extern "C" fn(*mut Vdbe);
/// Halt, destroy, and return the result status of one Vdbe.
pub type VdbeFinalize = unsafe extern "C" fn(*mut Vdbe) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_stmt_lru_remove(statement: *mut Vdbe) {
    let remove: StatementLruRemove = core::mem::transmute(STMT_LRU_REMOVE_ADDRESS);
    remove(statement);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_finalize(statement: *mut Vdbe) -> i32 {
    let finalize: VdbeFinalize = core::mem::transmute(VDBE_FINALIZE_ADDRESS);
    finalize(statement)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_stmt_lru_remove(_statement: *mut Vdbe) {
    panic!("sqlite3_finalize requires retail helper @ 0x08391d64")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_finalize(_statement: *mut Vdbe) -> i32 {
    panic!("sqlite3_finalize requires retail helper @ 0x0838af84")
}

/// The two unavailable stages of the retail finalization path.
#[derive(Clone, Copy)]
pub struct FinalizeOps {
    pub stmt_lru_remove: StatementLruRemove,
    pub vdbe_finalize: VdbeFinalize,
}

/// On target, preserve the two direct retailOS call boundaries.
#[cfg(target_os = "none")]
pub const DEFAULT_FINALIZE_OPS: FinalizeOps = FinalizeOps {
    stmt_lru_remove: retail_stmt_lru_remove,
    vdbe_finalize: retail_vdbe_finalize,
};

/// Host callers must install the unavailable finalization stages explicitly.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_FINALIZE_OPS: FinalizeOps = FinalizeOps {
    stmt_lru_remove: missing_stmt_lru_remove,
    vdbe_finalize: missing_vdbe_finalize,
};

/// Active finalization stages, replaceable by tests and future ports.
pub static mut FINALIZE_OPS: FinalizeOps = DEFAULT_FINALIZE_OPS;

#[inline(always)]
unsafe fn stmt_lru_remove_op() -> StatementLruRemove {
    core::ptr::read_volatile(core::ptr::addr_of!(FINALIZE_OPS.stmt_lru_remove))
}

#[inline(always)]
unsafe fn vdbe_finalize_op() -> VdbeFinalize {
    core::ptr::read_volatile(core::ptr::addr_of!(FINALIZE_OPS.vdbe_finalize))
}

/// Finalize a prepared SQLite statement and return its SQLite result code.
///
/// # Safety
/// For a non-NULL `statement`, both configured operations must accept a
/// valid Vdbe. The statement-LRU operation runs first and the finalizer may
/// destroy `statement`; it must not be accessed after this call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_finalize(statement: *mut Vdbe) -> i32 {
    if statement.is_null() {
        return 0;
    }
    stmt_lru_remove_op()(statement);
    vdbe_finalize_op()(statement)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    static OPS_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static mut CALLS: [(u8, usize); 2] = [(0, 0); 2];
    static mut CALL_COUNT: usize = 0;
    static mut FINALIZE_RESULT: i32 = 0;

    unsafe extern "C" fn recording_stmt_lru_remove(statement: *mut Vdbe) {
        CALLS[CALL_COUNT] = (1, statement as usize);
        CALL_COUNT += 1;
    }

    unsafe extern "C" fn recording_vdbe_finalize(statement: *mut Vdbe) -> i32 {
        CALLS[CALL_COUNT] = (2, statement as usize);
        CALL_COUNT += 1;
        FINALIZE_RESULT
    }

    unsafe fn with_recorders<R>(result: i32, body: impl FnOnce() -> R) -> R {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(FINALIZE_OPS),
            FinalizeOps {
                stmt_lru_remove: recording_stmt_lru_remove,
                vdbe_finalize: recording_vdbe_finalize,
            },
        );
        CALLS = [(0, 0); 2];
        CALL_COUNT = 0;
        FINALIZE_RESULT = result;
        let result = body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FINALIZE_OPS), DEFAULT_FINALIZE_OPS);
        result
    }

    fn lock() -> MutexGuard<'static, ()> {
        OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    #[test]
    fn null_statement_returns_ok_without_calling_either_stage() {
        let _guard = lock();
        unsafe {
            with_recorders(99, || {
                assert_eq!(sqlite3_finalize(core::ptr::null_mut()), 0);
                assert_eq!(CALL_COUNT, 0, "the NULL guard precedes both calls");
            });
        }
    }

    #[test]
    fn nonnull_statement_unlinks_before_returning_finalizer_status() {
        let _guard = lock();
        let mut statement = 0u8;
        let statement = (&mut statement as *mut u8).cast::<Vdbe>();
        unsafe {
            with_recorders(0x11, || {
                assert_eq!(sqlite3_finalize(statement), 0x11);
                assert_eq!(CALL_COUNT, 2);
                assert_eq!(CALLS, [(1, statement as usize), (2, statement as usize)]);
            });
        }
    }
}
