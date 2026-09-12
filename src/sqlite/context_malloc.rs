//! Scalar-function result allocation.
//!
//! - `context_malloc` — original: `FUN_082c4e84` @ **0x082c4e84**
//!   (104 bytes, 0x082c4e84..0x082c4eec; **8 `bl` call sites**, all
//!   unconditional, decoded from every ARM `B`/`BL` word in `osos.dec).
//!   Upstream SQLite 3.5.x's private `contextMalloc` helper from `func.c`.
//!
//! The callback context owns an embedded scalar-result [`Mem`]. Its `db`
//! field supplies `aLimit[SQLITE_LIMIT_LENGTH]` at `db + 0x50`. A request
//! above that signed 64-bit limit reports `SQLITE_TOOBIG`; an allocation
//! failure for a strictly positive request reports `SQLITE_NOMEM`. Zero and
//! negative requests flow to `sqlite3_malloc` unchanged and do not report an
//! error when that allocator returns NULL.
//!
//! The retail error-reporting helpers `FUN_083911d0` and `FUN_083911a8` are
//! not ported, so target builds reach their verified fixed load addresses
//! through the two callback slots. Host tests replace those slots. The raw
//! `sqlite3_malloc` callee at 0x08390b14 is already ported and is called
//! directly.
//!
//! ### Deliberate deviations
//!
//! Rust receives the natural `i64` rather than exposing AAPCS's unused `r1`
//! register. The unported result-error helpers are address-loaded callbacks
//! instead of their original PC-relative `bl` instructions; their defaults
//! remain the exact retail entry addresses on the target.

use super::aggregate_context::SqliteContext;
use super::mem::sqlite3_malloc;
use super::vm_printf::DB_LENGTH_LIMIT_OFFSET;

/// `sqlite3_result_error_toobig(context)` at this retailOS load address.
pub const RESULT_ERROR_TOOBIG_ADDRESS: usize = 0x0839_11d0;
/// `sqlite3_result_error_nomem(context)` at this retailOS load address.
pub const RESULT_ERROR_NOMEM_ADDRESS: usize = 0x0839_11a8;

/// ABI of the two result-error helpers.
pub type ResultErrorFn = unsafe extern "C" fn(context: *mut SqliteContext);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_result_error_toobig(context: *mut SqliteContext) {
    let result_error: ResultErrorFn = core::mem::transmute(RESULT_ERROR_TOOBIG_ADDRESS);
    result_error(context);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_result_error_toobig(_context: *mut SqliteContext) {
    panic!("context_malloc requires sqlite3_result_error_toobig @ 0x083911d0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_result_error_nomem(context: *mut SqliteContext) {
    let result_error: ResultErrorFn = core::mem::transmute(RESULT_ERROR_NOMEM_ADDRESS);
    result_error(context);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_result_error_nomem(_context: *mut SqliteContext) {
    panic!("context_malloc requires sqlite3_result_error_nomem @ 0x083911a8")
}

/// Callbacks for the two still-stock error-reporting helpers.
#[derive(Clone, Copy)]
pub struct ContextMallocOps {
    pub result_error_toobig: ResultErrorFn,
    pub result_error_nomem: ResultErrorFn,
}

/// Target defaults preserve the two original calls.
pub const DEFAULT_CONTEXT_MALLOC_OPS: ContextMallocOps = ContextMallocOps {
    result_error_toobig: retail_result_error_toobig,
    result_error_nomem: retail_result_error_nomem,
};

/// Active result-error helpers; host tests install recorders here.
pub static mut CONTEXT_MALLOC_OPS: ContextMallocOps = DEFAULT_CONTEXT_MALLOC_OPS;

/// Read the callbacks volatily so target fixed-address calls cannot vanish.
#[inline(always)]
unsafe fn context_malloc_ops() -> ContextMallocOps {
    core::ptr::read_volatile(core::ptr::addr_of!(CONTEXT_MALLOC_OPS))
}

/// context_malloc — original: `FUN_082c4e84` @ 0x082c4e84 (104 bytes; 8 `bl`).
/// `contextMalloc`: allocate `n_byte` bytes for a scalar-function callback
/// context. `context->s.db` must be a live connection holding the signed
/// length limit at +0x50; as in retailOS, it is not NULL-checked. Requests
/// strictly above that limit produce `SQLITE_TOOBIG`. Otherwise this calls
/// `sqlite3_malloc(n_byte as i32)` and reports `SQLITE_NOMEM` only when the
/// request is strictly positive and allocation returns NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_malloc(context: *mut SqliteContext, n_byte: i64) -> *mut u8 {
    let db = (*context).s.db;
    let limit = db.add(DB_LENGTH_LIMIT_OFFSET).cast::<i32>().read();
    let ops = context_malloc_ops();

    // `asr`/`subs`/`sbcs` compare the sign-extended i32 limit with the full
    // r2:r3 request. Equality remains permitted.
    if n_byte > i64::from(limit) {
        (ops.result_error_toobig)(context);
        return core::ptr::null_mut();
    }

    // The ABI places this naturally 8-byte-aligned i64 in r2:r3 after the
    // context pointer, leaving r1 unused. The retail call passes r2 alone.
    let allocation = sqlite3_malloc(n_byte as i32);
    if allocation.is_null() && n_byte > 0 {
        (ops.result_error_nomem)(context);
    }
    allocation
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::vdbe::Mem;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ERRORS: Vec<i32> = Vec::new();

    unsafe extern "C" fn record_toobig(_context: *mut SqliteContext) {
        ERRORS.push(18);
    }

    unsafe extern "C" fn record_nomem(_context: *mut SqliteContext) {
        ERRORS.push(7);
    }

    struct OpsGuard(MutexGuard<'static, ()>);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(CONTEXT_MALLOC_OPS),
                    DEFAULT_CONTEXT_MALLOC_OPS,
                );
            }
        }
    }

    fn install_recorders() -> OpsGuard {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ERRORS.clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(CONTEXT_MALLOC_OPS),
                ContextMallocOps {
                    result_error_toobig: record_toobig,
                    result_error_nomem: record_nomem,
                },
            );
        }
        OpsGuard(guard)
    }

    #[repr(align(4))]
    struct Db([u8; DB_LENGTH_LIMIT_OFFSET + 4]);

    impl Db {
        fn with_limit(limit: i32) -> Self {
            let mut db = Self([0; DB_LENGTH_LIMIT_OFFSET + 4]);
            db.0[DB_LENGTH_LIMIT_OFFSET..DB_LENGTH_LIMIT_OFFSET + 4]
                .copy_from_slice(&limit.to_le_bytes());
            db
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    fn context_with_db(db: *mut u8) -> SqliteContext {
        SqliteContext {
            p_func: core::ptr::null_mut(),
            _gap_04: [0; 4],
            s: Mem {
                u: 0,
                r: 0.0,
                db,
                z: core::ptr::null_mut(),
                n: 0,
                flags: 0,
                value_type: 0,
                enc: 0,
                x_del: core::ptr::null_mut(),
                z_malloc: core::ptr::null_mut(),
            },
            p_mem: core::ptr::null_mut(),
            is_error: 0,
        }
    }

    #[test]
    fn a_request_strictly_above_the_limit_reports_toobig() {
        let _guard = install_recorders();
        let mut db = Db::with_limit(9);
        let mut context = context_with_db(db.ptr());

        assert!(unsafe { context_malloc(&mut context, 10) }.is_null());
        assert_eq!(unsafe { &*core::ptr::addr_of!(ERRORS) }, &[18]);
    }

    #[test]
    fn an_exact_limit_request_is_not_too_big() {
        let _guard = install_recorders();
        let mut db = Db::with_limit(0);
        let mut context = context_with_db(db.ptr());

        assert!(unsafe { context_malloc(&mut context, 0) }.is_null());
        assert!(unsafe { (&*core::ptr::addr_of!(ERRORS)).is_empty() });
    }

    #[test]
    fn nonpositive_requests_return_null_without_an_error() {
        let _guard = install_recorders();
        let mut db = Db::with_limit(0);
        let mut context = context_with_db(db.ptr());


        for n_byte in [-1, i64::MIN] {
            assert!(unsafe { context_malloc(&mut context, n_byte) }.is_null());
        }
        assert!(unsafe { (&*core::ptr::addr_of!(ERRORS)).is_empty() });
    }
}
