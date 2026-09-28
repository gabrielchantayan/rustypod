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
//! Deliberate deviation: `stmtLruRemove` (`0x08391d64`) is now ported
//! (`super::stmt_lru_remove`) and target builds call it directly; only
//! `sqlite3VdbeFinalize` remains a volatile, replaceable seam to its exact
//! retailOS load address. Host tests install recorders for both. No mutex
//! call appears in the verified 32-byte body, so none is introduced here.

use super::vdbe::Vdbe;
use super::release_mem_array::release_mem_array;
use super::vdbe_reset::sqlite_vdbe_reset;

const VDBE_MAGIC_RUN: u32 = 0xbdf2_0da3;
const VDBE_MAGIC_HALT: u32 = 0x519c_2973;
const VDBE_MAGIC_INIT: u32 = 0x26bc_eaa5;
const SQLITE_MISUSE: i32 = 21;

type VdbeDelete = unsafe extern "C" fn(*mut Vdbe);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_delete(statement: *mut Vdbe) {
    let delete: VdbeDelete = core::mem::transmute(0x0838_6d24usize);
    delete(statement);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_delete(_statement: *mut Vdbe) {
    panic!("sqlite_vdbe_finalize requires sqlite3VdbeDelete @ 0x08386d24")
}

#[cfg(not(target_os = "none"))]
static mut VDBE_DELETE: VdbeDelete = missing_vdbe_delete;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn vdbe_delete_op() -> VdbeDelete {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_DELETE))
}

/// Finalize and destroy a VDBE — retailOS `FUN_0838af84` at `0x0838af84`
/// (108 bytes, `0x0838af84..0x0838aff0`, followed by three literal words and
/// the distinct `vdbe_free_cursor` prologue at `0x0838affc`). Raw ARM branch
/// decoding finds two inbound plain `bl` sites (`0x082b7a64`, `0x08382090`)
/// and no predicated `bl` sites.
///
/// SQLite 3.5.9's `sqlite3VdbeFinalize`: reset a running or halted statement,
/// reject every state except INIT, release its result-column `Mem` array, then
/// delete the VDBE. Deliberate deviation: `sqlite3VdbeDelete` at `0x08386d24`
/// is not yet ported, so target builds use its verified retail address and
/// host builds retain a replaceable seam.
///
/// # Safety
/// `statement` must be a live VDBE whose result-column array and delete
/// dependencies are valid. The statement is destroyed before this returns.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_vdbe_finalize(statement: *mut Vdbe) -> i32 {
    let mut result = 0;
    match (*statement).magic {
        VDBE_MAGIC_RUN | VDBE_MAGIC_HALT => result = sqlite_vdbe_reset(statement, 1usize as *mut u8),
        VDBE_MAGIC_INIT => {}
        _ => return SQLITE_MISUSE,
    }
    release_mem_array((*statement).a_col_name.cast(), (*statement).n_res_column, 1);
    #[cfg(target_os = "none")]
    retail_vdbe_delete(statement);
    #[cfg(not(target_os = "none"))]
    vdbe_delete_op()(statement);
    result
}


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
    super::stmt_lru_remove::stmt_lru_remove(statement.cast());
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_finalize(statement: *mut Vdbe) -> i32 {
    sqlite_vdbe_finalize(statement)
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
    static mut DELETE_CALL: usize = 0;

    unsafe extern "C" fn recording_stmt_lru_remove(statement: *mut Vdbe) {
        CALLS[CALL_COUNT] = (1, statement as usize);
        CALL_COUNT += 1;
    }

    unsafe extern "C" fn recording_vdbe_finalize(statement: *mut Vdbe) -> i32 {
        CALLS[CALL_COUNT] = (2, statement as usize);
        CALL_COUNT += 1;
        FINALIZE_RESULT
    }

    unsafe extern "C" fn recording_vdbe_delete(statement: *mut Vdbe) {
        DELETE_CALL = statement as usize;
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

    unsafe fn with_delete_recorder<R>(body: impl FnOnce() -> R) -> R {
        let saved = VDBE_DELETE;
        VDBE_DELETE = recording_vdbe_delete;
        DELETE_CALL = 0;
        let result = body();
        VDBE_DELETE = saved;
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

    #[test]
    fn vdbe_finalize_deletes_initialized_statement_and_returns_ok() {
        let _guard = lock();
        let mut statement: Vdbe = unsafe { core::mem::zeroed() };
        statement.magic = VDBE_MAGIC_INIT;
        unsafe {
            with_delete_recorder(|| {
                assert_eq!(sqlite_vdbe_finalize(&mut statement), 0);
                assert_eq!(DELETE_CALL, (&mut statement as *mut Vdbe) as usize);
            });
        }
    }

    #[test]
    fn vdbe_finalize_rejects_unknown_magic_without_deleting() {
        let _guard = lock();
        let mut statement: Vdbe = unsafe { core::mem::zeroed() };
        statement.magic = 0;
        unsafe {
            with_delete_recorder(|| {
                assert_eq!(sqlite_vdbe_finalize(&mut statement), SQLITE_MISUSE);
                assert_eq!(DELETE_CALL, 0);
            });
        }
    }
}
