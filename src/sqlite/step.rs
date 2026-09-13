//! SQLite statement executor — original: `FUN_08391470` @ `0x08391470`
//! (188 bytes; 6 verified direct `bl` call sites, all unconditional).
//!
//! Raw `osos.dec` confirms the complete extent: the `push {r4-r8,lr}` at
//! `0x08391470` runs through the tail `b 0x0836f468` at `0x08391528`; the
//! next separately linked function begins at `0x0839152c`. Decoding every
//! ARM B/BL-immediate word in the image finds inbound `bl` instructions at
//! `0x08215a60`, `0x08215ba8`, `0x082ccf20`, `0x082ccf7c`, `0x0838f428`, and
//! `0x083903c0`; none is predicated.
//!
//! # Algorithm
//!
//! SQLite 3.5.9's public `sqlite3_step`: a NULL statement returns
//! `SQLITE_MISUSE` (21). Otherwise it calls the VDBE step operation. On
//! `SQLITE_SCHEMA` (17), it reparses and resets the statement, clears the
//! statement's `expired` byte, and retries; the ARM permits five reparses,
//! hence at most six step calls. When reparsing ends with schema still
//! outstanding, a prepare-v2 statement copies the connection's current error
//! text into `zErrMsg`, unless allocation has failed, in which case it stores
//! `SQLITE_NOMEM` (7) as the statement result. The result always passes through
//! `sqlite_api_exit`.
//!
//! Deliberate deviation: `sqlite3Step`, `sqlite3Reprepare`, and
//! `sqlite3_reset` are not ported yet. Their three direct calls therefore use
//! replaceable, volatile dispatch slots. The shipped defaults conservatively
//! terminate as `SQLITE_MISUSE`/`SQLITE_ERROR` rather than inventing VDBE
//! execution; a future port wires the real entries into these slots.

use super::api_exit::sqlite_api_exit;
use super::error::DB_P_ERR_OFFSET;
use super::mem::MALLOC_FAILED_OFFSET;
use super::strdup::db_str_dup;
use super::value_set_str::SQLITE_NOMEM;
use super::value_text::sqlite3_value_text;
use crate::heap::tracked::tracked_free;

/// `SQLITE_ERROR`: the conservative terminal result for an unported reparse.
pub const SQLITE_ERROR: i32 = 1;
/// `SQLITE_NOMEM`: copied to `Vdbe.rc` when the error-message copy fails.
pub const SQLITE_NOMEM_RESULT: i32 = SQLITE_NOMEM;
/// `SQLITE_MISUSE`: returned for a NULL `sqlite3_stmt *`.
pub const SQLITE_MISUSE: i32 = 21;
/// `SQLITE_SCHEMA`: requests reprepare/retry.
pub const SQLITE_SCHEMA: i32 = 17;
const MAX_SCHEMA_REPREPARES: usize = 5;

// These are target-width word indices, not host byte offsets. `Vdbe` and
// `sqlite3` contain target pointers, so host fixtures use a low u32 slab.
const VDBE_DB_WORD: usize = 0;
const VDBE_RC_WORD: usize = 0x74 / 4;
const VDBE_Z_ERR_MSG_WORD: usize = 0xf4 / 4;
const VDBE_EXPIRED_BYTE: usize = 0xff;
const VDBE_PREPARE_V2_WORD: usize = 0x148 / 4;
const DB_P_ERR_WORD: usize = DB_P_ERR_OFFSET / 4;

/// `sqlite3Step(Vdbe *)` @ `0x08384a9c`.
pub type VdbeStepFn = unsafe extern "C" fn(statement: *mut u8) -> i32;
/// `sqlite3Reprepare(Vdbe *)` @ `0x083974cc`.
pub type VdbeReprepareFn = unsafe extern "C" fn(statement: *mut u8) -> i32;
/// `sqlite3_reset(sqlite3_stmt *)` @ `0x083910a4`.
pub type VdbeResetFn = unsafe extern "C" fn(statement: *mut u8) -> i32;

unsafe extern "C" fn missing_vdbe_step(_statement: *mut u8) -> i32 {
    SQLITE_MISUSE
}

unsafe extern "C" fn missing_vdbe_reprepare(_statement: *mut u8) -> i32 {
    SQLITE_ERROR
}

unsafe extern "C" fn missing_vdbe_reset(_statement: *mut u8) -> i32 {
    SQLITE_OK
}

const SQLITE_OK: i32 = 0;

/// Active `sqlite3Step` implementation. The target's direct BL is represented
/// as a volatile seam until `FUN_08384a9c` is ported.
pub static mut SQLITE_VDBE_STEP: VdbeStepFn = missing_vdbe_step;
/// Active `sqlite3Reprepare` implementation (target: `FUN_083974cc`).
pub static mut SQLITE_VDBE_REPREPARE: VdbeReprepareFn = missing_vdbe_reprepare;
/// Active public `sqlite3_reset` implementation (target: `FUN_083910a4`).
pub static mut SQLITE_VDBE_RESET: VdbeResetFn = missing_vdbe_reset;

#[inline(always)]
unsafe fn vdbe_step_op() -> VdbeStepFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_STEP))
}

#[inline(always)]
unsafe fn vdbe_reprepare_op() -> VdbeReprepareFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_REPREPARE))
}

#[inline(always)]
unsafe fn vdbe_reset_op() -> VdbeResetFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_RESET))
}

/// SQLite's public statement executor (`sqlite3_step`).
///
/// # Safety
///
/// `statement`, when non-NULL, must name a writable target-layout `Vdbe` at
/// least through word 82 and byte `0xff`; its db word must be a live target
/// `sqlite3` through `+0xc8`. A prepare-v2 statement with a non-NULL `pErr`
/// must satisfy `sqlite3_value_text` and `db_str_dup`'s contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_step(statement: *mut u8) -> i32 {
    if statement.is_null() {
        return SQLITE_MISUSE;
    }

    let statement_words = statement.cast::<u32>();
    let db = statement_words.add(VDBE_DB_WORD).read() as usize as *mut u8;
    let mut result_code = vdbe_step_op()(statement);
    let mut reprepare_count = 0;

    while result_code == SQLITE_SCHEMA && reprepare_count < MAX_SCHEMA_REPREPARES {
        reprepare_count += 1;
        if vdbe_reprepare_op()(statement) != SQLITE_OK {
            break;
        }
        vdbe_reset_op()(statement);
        statement.add(VDBE_EXPIRED_BYTE).write(0);
        result_code = vdbe_step_op()(statement);
    }

    if statement_words.add(VDBE_PREPARE_V2_WORD).read() != 0
        && db.cast::<u32>().add(DB_P_ERR_WORD).read() != 0
    {
        let error_value = db.cast::<u32>().add(DB_P_ERR_WORD).read() as usize as *mut u8;
        let error_text = sqlite3_value_text(error_value);
        tracked_free(statement_words.add(VDBE_Z_ERR_MSG_WORD).read() as usize as *mut u8);
        if db.add(MALLOC_FAILED_OFFSET).read() != 0 {
            statement_words.add(VDBE_RC_WORD).write(SQLITE_NOMEM as u32);
            statement_words.add(VDBE_Z_ERR_MSG_WORD).write(0);
        } else {
            statement_words.add(VDBE_Z_ERR_MSG_WORD).write(db_str_dup(db, error_text) as usize as u32);
        }
    }

    sqlite_api_exit(db, result_code)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static STEP_OPS_LOCK: Mutex<()> = Mutex::new(());
    static STEP_CALLS: AtomicUsize = AtomicUsize::new(0);
    static REPREPARE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RESET_CALLS: AtomicUsize = AtomicUsize::new(0);
    static STEP_FIRST_RESULT: AtomicI32 = AtomicI32::new(SQLITE_OK);
    static STEP_RETRY_RESULT: AtomicI32 = AtomicI32::new(SQLITE_OK);
    static REPREPARE_RESULT: AtomicI32 = AtomicI32::new(SQLITE_OK);

    unsafe extern "C" fn recording_step(_statement: *mut u8) -> i32 {
        if STEP_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
            STEP_FIRST_RESULT.load(Ordering::SeqCst)
        } else {
            STEP_RETRY_RESULT.load(Ordering::SeqCst)
        }
    }

    unsafe extern "C" fn recording_reprepare(_statement: *mut u8) -> i32 {
        REPREPARE_CALLS.fetch_add(1, Ordering::SeqCst);
        REPREPARE_RESULT.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn recording_reset(_statement: *mut u8) -> i32 {
        RESET_CALLS.fetch_add(1, Ordering::SeqCst);
        SQLITE_OK
    }

    unsafe fn with_recording_ops(body: impl FnOnce()) {
        let _guard = STEP_OPS_LOCK.lock();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_STEP), recording_step);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_REPREPARE), recording_reprepare);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_RESET), recording_reset);
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_STEP), missing_vdbe_step);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_REPREPARE), missing_vdbe_reprepare);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VDBE_RESET), missing_vdbe_reset);
    }

    unsafe fn fixture() -> Option<*mut u8> {
        let slab = try_map_u32_slab(hints::SQLITE_STEP, 0x2000)?;
        slab.write_bytes(0, 0x2000);
        let statement = slab;
        let db = slab.add(0x400);
        statement.cast::<u32>().add(VDBE_DB_WORD).write(db as usize as u32);
        (db.add(super::super::api_exit::DB_ERR_MASK_OFFSET) as *mut i32).write(-1);
        Some(statement)
    }

    fn reset_recording_results(first: i32, retry: i32, reprepare: i32) {
        STEP_CALLS.store(0, Ordering::SeqCst);
        REPREPARE_CALLS.store(0, Ordering::SeqCst);
        RESET_CALLS.store(0, Ordering::SeqCst);
        STEP_FIRST_RESULT.store(first, Ordering::SeqCst);
        STEP_RETRY_RESULT.store(retry, Ordering::SeqCst);
        REPREPARE_RESULT.store(reprepare, Ordering::SeqCst);
    }

    #[test]
    fn null_statement_is_misuse_without_entering_the_step_seam() {
        unsafe {
            with_recording_ops(|| {
                reset_recording_results(SQLITE_OK, SQLITE_OK, SQLITE_OK);
                assert_eq!(sqlite3_step(core::ptr::null_mut()), SQLITE_MISUSE);
                assert_eq!(STEP_CALLS.load(Ordering::SeqCst), 0);
            });
        }
    }

    #[test]
    fn ordinary_result_is_masked_without_reprepare_or_reset() {
        unsafe {
            with_recording_ops(|| {
                let Some(statement) = fixture() else {
                    note_missing_u32_fixture("sqlite/step");
                    return;
                };
                let db = statement.cast::<u32>().read() as usize as *mut u8;
                (db.add(super::super::api_exit::DB_ERR_MASK_OFFSET) as *mut i32).write(0x0f);
                reset_recording_results(0x35, SQLITE_OK, SQLITE_OK);

                assert_eq!(sqlite3_step(statement), 0x05);
                assert_eq!(STEP_CALLS.load(Ordering::SeqCst), 1);
                assert_eq!(REPREPARE_CALLS.load(Ordering::SeqCst), 0);
                assert_eq!(RESET_CALLS.load(Ordering::SeqCst), 0);
            });
        }
    }

    #[test]
    fn schema_reprepare_resets_clears_expired_and_retries_once() {
        unsafe {
            with_recording_ops(|| {
                let Some(statement) = fixture() else {
                    note_missing_u32_fixture("sqlite/step");
                    return;
                };
                statement.add(VDBE_EXPIRED_BYTE).write(0xa5);
                reset_recording_results(SQLITE_SCHEMA, 100, SQLITE_OK);

                assert_eq!(sqlite3_step(statement), 100);
                assert_eq!(STEP_CALLS.load(Ordering::SeqCst), 2);
                assert_eq!(REPREPARE_CALLS.load(Ordering::SeqCst), 1);
                assert_eq!(RESET_CALLS.load(Ordering::SeqCst), 1);
                assert_eq!(statement.add(VDBE_EXPIRED_BYTE).read(), 0);
            });
        }
    }

    #[test]
    fn schema_retry_stops_after_five_reprepares() {
        unsafe {
            with_recording_ops(|| {
                let Some(statement) = fixture() else {
                    note_missing_u32_fixture("sqlite/step");
                    return;
                };
                reset_recording_results(SQLITE_SCHEMA, SQLITE_SCHEMA, SQLITE_OK);

                assert_eq!(sqlite3_step(statement), SQLITE_SCHEMA);
                assert_eq!(STEP_CALLS.load(Ordering::SeqCst), 6);
                assert_eq!(REPREPARE_CALLS.load(Ordering::SeqCst), 5);
                assert_eq!(RESET_CALLS.load(Ordering::SeqCst), 5);
            });
        }
    }
}
