//! `sqlite_vdbe_reset` — original: `FUN_0838cb28` @ `0x0838cb28` (212 bytes;
//! 2 verified inbound direct `bl` call sites, both unconditional).
//!
//! Raw `osos.dec` establishes the exact extent `0x0838cb28..0x0838cbfc`;
//! `0x0838cbfc` and `0x0838cc00` are its two literal-pool words, and the next
//! separately linked function begins at `0x0838cc04`. The body makes five
//! unconditional outbound `bl` instructions and no predicated calls.
//!
//! # Algorithm
//!
//! SQLite 3.5.9's `sqlite3VdbeReset`: halt the Vdbe, preserve an error message
//! only for a completed statement or an expired failed unstarted statement,
//! clear its owned execution state, restore `VDBE_MAGIC_INIT`, clear `expired`,
//! and return `rc & db->errMask`.
//!
//! Deliberate deviations: `sqlite3VdbeHalt` and `sqlite3VdbeClearObject` are
//! unavailable ports, so target builds call their verified retail addresses and
//! host tests install replaceable recorders. The firmware's `zErrMsg` pointer
//! is stored as a target-width word to preserve the following `pResultSet`
//! offset on 64-bit hosts.

use super::error::{sqlite_error, DB_ERR_CODE_OFFSET, DB_P_ERR_OFFSET, SQLITE_FREE_X_DEL, SQLITE_UTF8};
use super::value_set_str::sqlite_value_set_str;
use super::vdbe::Vdbe;

pub const VDBE_HALT_ADDRESS: usize = 0x0838_b084;
pub const VDBE_CLEAR_OBJECT_ADDRESS: usize = 0x0804_4c78;
const VDBE_MAGIC_INIT: u32 = 0x26bc_eaa5;

pub type VdbeHalt = unsafe extern "C" fn(*mut Vdbe);
pub type VdbeClearObject = unsafe extern "C" fn(*mut Vdbe, *mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_halt(statement: *mut Vdbe) {
    let halt: VdbeHalt = core::mem::transmute(VDBE_HALT_ADDRESS);
    halt(statement);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_clear_object(statement: *mut Vdbe, arg: *mut u8) {
    let clear: VdbeClearObject = core::mem::transmute(VDBE_CLEAR_OBJECT_ADDRESS);
    clear(statement, arg);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_halt(_statement: *mut Vdbe) {
    panic!("sqlite_vdbe_reset requires retail helper @ 0x0838b084")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_clear_object(_statement: *mut Vdbe, _arg: *mut u8) {
    panic!("sqlite_vdbe_reset requires retail helper @ 0x08044c78")
}

#[derive(Clone, Copy)]
pub struct VdbeResetOps {
    pub halt: VdbeHalt,
    pub clear_object: VdbeClearObject,
}

#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_RESET_OPS: VdbeResetOps = VdbeResetOps {
    halt: retail_vdbe_halt,
    clear_object: retail_vdbe_clear_object,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_RESET_OPS: VdbeResetOps = VdbeResetOps {
    halt: missing_vdbe_halt,
    clear_object: missing_vdbe_clear_object,
};

pub static mut VDBE_RESET_OPS: VdbeResetOps = DEFAULT_VDBE_RESET_OPS;

#[inline(always)]
unsafe fn halt_op() -> VdbeHalt {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_RESET_OPS.halt))
}

#[inline(always)]
unsafe fn clear_object_op() -> VdbeClearObject {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_RESET_OPS.clear_object))
}
const VDBE_RC_OFFSET: usize = 0x74;
const VDBE_Z_ERR_MSG_OFFSET: usize = 0xf4;

#[inline(always)]
unsafe fn rc(statement: *mut Vdbe) -> i32 {
    statement.cast::<u8>().add(VDBE_RC_OFFSET).cast::<i32>().read()
}

#[inline(always)]
unsafe fn z_err_msg(statement: *mut Vdbe) -> u32 {
    statement.cast::<u8>().add(VDBE_Z_ERR_MSG_OFFSET).cast::<u32>().read()
}

#[inline(always)]
unsafe fn clear_z_err_msg(statement: *mut Vdbe) {
    statement.cast::<u8>().add(VDBE_Z_ERR_MSG_OFFSET).cast::<u32>().write(0);
}

/// Reset a halted SQLite virtual machine and return its masked result code.
///
/// # Safety
/// `statement` must reference a live `Vdbe`, its `db` must satisfy
/// [`sqlite_error`], and both configured reset operations must accept it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_vdbe_reset(statement: *mut Vdbe, clear_arg: *mut u8) -> i32 {
    halt_op()(statement);

    let db = (*statement).db;
    let result_code = rc(statement);
    if (*statement).pc < 0 {
        if result_code != 0 && (*statement).expired != 0 {
            sqlite_error(db, result_code, core::ptr::null(), core::ptr::null());
            sqlite_value_set_str(
                (db.add(DB_P_ERR_OFFSET) as *const *mut u8).read(),
                -1,
                z_err_msg(statement) as usize as *mut u8,
                SQLITE_UTF8,
                SQLITE_FREE_X_DEL,
            );
            clear_z_err_msg(statement);
        }
    } else if z_err_msg(statement) == 0 {
        sqlite_error(db, result_code, core::ptr::null(), core::ptr::null());
    } else {
        sqlite_value_set_str(
            (db.add(DB_P_ERR_OFFSET) as *const *mut u8).read(),
            -1,
            z_err_msg(statement) as usize as *mut u8,
            SQLITE_UTF8,
            SQLITE_FREE_X_DEL,
        );
        (db.add(DB_ERR_CODE_OFFSET) as *mut i32).write(result_code);
        clear_z_err_msg(statement);
    }

    clear_object_op()(statement, clear_arg);
    (*statement).magic = VDBE_MAGIC_INIT;
    (*statement).expired = 0;
    result_code & (db.add(0x18) as *const i32).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::Mem;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    static OPS_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static mut CALLS: [u8; 2] = [0; 2];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn halt(statement: *mut Vdbe) {
        CALLS[CALL_COUNT] = 1;
        CALL_COUNT += 1;
        assert!(!statement.is_null());
    }

    unsafe extern "C" fn clear(statement: *mut Vdbe, arg: *mut u8) {
        CALLS[CALL_COUNT] = 2;
        CALL_COUNT += 1;
        assert!(!statement.is_null());
        assert_eq!(arg as usize, 0x1234);
    }

    unsafe fn with_ops<R>(body: impl FnOnce() -> R) -> R {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(VDBE_RESET_OPS), VdbeResetOps { halt, clear_object: clear });
        CALLS = [0; 2];
        CALL_COUNT = 0;
        let result = body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(VDBE_RESET_OPS), DEFAULT_VDBE_RESET_OPS);
        result
    }

    fn lock() -> MutexGuard<'static, ()> {
        OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    #[repr(align(8))]
    struct Db([u8; 0xd0]);

    fn statement(db: *mut u8, pc: i32, rc: i32, z_err_msg: u32, expired: u8) -> Vdbe {
        let mut statement = unsafe { core::mem::zeroed::<Vdbe>() };
        statement.db = db;
        statement.pc = pc;
        unsafe {
            (&mut statement as *mut Vdbe).cast::<u8>().add(VDBE_RC_OFFSET).cast::<i32>().write(rc);
            (&mut statement as *mut Vdbe).cast::<u8>().add(VDBE_Z_ERR_MSG_OFFSET).cast::<u32>().write(z_err_msg);
        }
        statement.expired = expired;
        statement
    }

    #[test]
    fn completed_statement_reports_rc_without_message() {
        let _guard = lock();
        let mut db = Db([0; 0xd0]);
        let mut error_value: Mem = unsafe { core::mem::zeroed() };
        unsafe {
            (db.0.as_mut_ptr().add(DB_P_ERR_OFFSET) as *mut *mut u8).write((&mut error_value as *mut Mem).cast());
            (db.0.as_mut_ptr().add(0x18) as *mut i32).write(0xff);
            let mut vdbe = statement(db.0.as_mut_ptr(), 0, 0x123, 0, 1);
            with_ops(|| assert_eq!(sqlite_vdbe_reset(&mut vdbe, 0x1234usize as *mut u8), 0x23));
            assert_eq!(CALLS, [1, 2]);
            assert_eq!(vdbe.magic, VDBE_MAGIC_INIT);
            assert_eq!(vdbe.expired, 0);
        }
    }

    #[test]
    fn negative_pc_skips_error_state_without_expired_failure() {
        let _guard = lock();
        let mut db = Db([0; 0xd0]);
        let mut error_value: Mem = unsafe { core::mem::zeroed() };
        unsafe {
            (db.0.as_mut_ptr().add(DB_P_ERR_OFFSET) as *mut *mut u8).write((&mut error_value as *mut Mem).cast());
            (db.0.as_mut_ptr().add(0x18) as *mut i32).write(-1);
            let mut untouched = statement(db.0.as_mut_ptr(), -1, 0, 0xfeed_beef, 0);
            with_ops(|| assert_eq!(sqlite_vdbe_reset(&mut untouched, 0x1234usize as *mut u8), 0));
            assert_eq!(z_err_msg(&mut untouched), 0xfeed_beef);
            assert_eq!(CALLS, [1, 2]);
        }
    }
}
