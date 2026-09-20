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
//! `FUN_083911d0` is ported as
//! [`sqlite3_result_error_toobig`](super::result_error_toobig::sqlite3_result_error_toobig).
//! `FUN_083911a8` remains a fixed-address callback so host tests can replace
//! the allocation-failure path.
//!
//! ### Deliberate deviations
//!
//! Rust receives the natural `i64` rather than exposing AAPCS's unused `r1`
//! register. The unported NOMEM helper remains an address-loaded callback;
//! its target default is the exact retail entry address.

use super::aggregate_context::SqliteContext;
use super::mem::sqlite3_malloc;
use super::vm_printf::DB_LENGTH_LIMIT_OFFSET;

/// `sqlite3_result_error_nomem(context)` at this retailOS load address.
pub const RESULT_ERROR_NOMEM_ADDRESS: usize = 0x0839_11a8;

/// ABI of the unported NOMEM result-error helper.
pub type ResultErrorFn = unsafe extern "C" fn(context: *mut SqliteContext);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_result_error_nomem(context: *mut SqliteContext) {
    let result_error: ResultErrorFn = core::mem::transmute(RESULT_ERROR_NOMEM_ADDRESS);
    result_error(context);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_result_error_nomem(_context: *mut SqliteContext) {
    panic!("context_malloc requires sqlite3_result_error_nomem @ 0x083911a8")
}

/// Callback for the still-stock NOMEM result-error helper.
#[derive(Clone, Copy)]
pub struct ContextMallocOps {
    pub result_error_nomem: ResultErrorFn,
}

/// Target default preserves the original NOMEM call.
pub const DEFAULT_CONTEXT_MALLOC_OPS: ContextMallocOps = ContextMallocOps {
    result_error_nomem: retail_result_error_nomem,
};

/// Active NOMEM helper; host tests install a recorder here.
pub static mut CONTEXT_MALLOC_OPS: ContextMallocOps = DEFAULT_CONTEXT_MALLOC_OPS;

/// Read the callback volatily so the target fixed-address call cannot vanish.
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
        super::result_error_toobig::sqlite3_result_error_toobig(context);
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
