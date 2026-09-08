//! `cxx_mutex_destroy` — original: `FUN_08261e54` @ 0x08261e54.
//!
//! The raw ARM extent is 20 bytes of code (0x08261e54..0x08261e68; the
//! next function begins at 0x08261e68), with no literal pool:
//!
//! ```text
//! push {r4, lr}
//! mov  r4, r0
//! bl   0x082e82a4       ; pthread_mutex_destroy
//! mov  r0, r4
//! pop  {r4, pc}
//! ```
//!
//! Binary-decoding every ARM B/BL word finds 19 unconditional `bl` callers,
//! zero predicated calls, and four tail `b` callers; no image word equals this
//! address, so it is not a data-dispatched virtual target. The wrapper calls
//! pthread_mutex_destroy on its embedded mutex at offset zero, discards that
//! function's status, and returns `this` unchanged. It deliberately has no
//! NULL guard: NULL reaches the callee, whose native error status is then
//! discarded.
//!
//! Deviation: pthread_mutex_destroy @ 0x082e82a4 is not ported. The call
//! therefore crosses [`CXX_MUTEX_DESTROY_OPS`] and defaults to an inert,
//! success-returning stub. This wrapper is not hook-ready until that callee is
//! ported; the dispatch retains the exact one-call and return-this contract.

/// Indirect callee for the unresolved pthread_mutex_destroy @ 0x082e82a4.
/// The native return status is intentionally discarded by
/// [`cxx_mutex_destroy`].
#[derive(Clone, Copy)]
pub struct CxxMutexDestroyOps {
    pub mutex_destroy: unsafe extern "C" fn(mutex: *mut u8) -> u32,
}

unsafe extern "C" fn mutex_destroy_unported(_mutex: *mut u8) -> u32 { 0 }

/// Default while pthread_mutex_destroy remains unported.
pub const DEFAULT_CXX_MUTEX_DESTROY_OPS: CxxMutexDestroyOps = CxxMutexDestroyOps {
    mutex_destroy: mutex_destroy_unported,
};

/// Active native-destroy boundary. Host tests replace it with a recorder.
pub static mut CXX_MUTEX_DESTROY_OPS: CxxMutexDestroyOps = DEFAULT_CXX_MUTEX_DESTROY_OPS;

/// cxx_mutex_destroy — original: `FUN_08261e54` @ 0x08261e54
/// (20 bytes; 19 unconditional `bl` call sites, no predicated calls, and
/// four tail `b` callers, binary-scanned).
///
/// Destroys the embedded POSIX mutex at `this` through pthread_mutex_destroy,
/// ignores its status, and returns `this` unchanged. No NULL guard, matching
/// the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutex_destroy(this: *mut u8) -> *mut u8 {
    let mutex_destroy = core::ptr::read_volatile(core::ptr::addr_of!(CXX_MUTEX_DESTROY_OPS.mutex_destroy));
    mutex_destroy(this);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static CXX_MUTEX_DESTROY_OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut DESTROY_ARGUMENT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_mutex_destroy(mutex: *mut u8) -> u32 {
        *core::ptr::addr_of_mut!(DESTROY_ARGUMENT) = mutex;
        20
    }

    struct DestroyOpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for DestroyOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CXX_MUTEX_DESTROY_OPS)
                    .write_volatile(DEFAULT_CXX_MUTEX_DESTROY_OPS);
            }
        }
    }

    fn install_destroy_recorder() -> DestroyOpsGuard {
        let lock = CXX_MUTEX_DESTROY_OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            *core::ptr::addr_of_mut!(DESTROY_ARGUMENT) = core::ptr::null_mut();
            core::ptr::addr_of_mut!(CXX_MUTEX_DESTROY_OPS).write_volatile(CxxMutexDestroyOps {
                mutex_destroy: recording_mutex_destroy,
            });
        }
        DestroyOpsGuard { _lock: lock }
    }

    #[test]
    fn destroy_forwards_this_discards_status_and_returns_this() {
        let mut wrapper = [0xa5u8; 0x1c];
        let this = wrapper.as_mut_ptr();
        let _ops = install_destroy_recorder();

        let returned = unsafe { cxx_mutex_destroy(this) };

        assert_eq!(unsafe { core::ptr::addr_of!(DESTROY_ARGUMENT).read() }, this, "the only call receives the embedded mutex at this+0");
        assert_eq!(returned, this, "the native status is discarded and mov r0, r4 returns this");
        assert_eq!(wrapper, [0xa5u8; 0x1c], "the wrapper itself performs no writes");
    }

    #[test]
    fn destroy_forwards_null_without_a_wrapper_guard() {
        let _ops = install_destroy_recorder();

        let returned = unsafe { cxx_mutex_destroy(core::ptr::null_mut()) };

        assert!(unsafe { core::ptr::addr_of!(DESTROY_ARGUMENT).read().is_null() }, "NULL reaches pthread_mutex_destroy");
        assert!(returned.is_null(), "the unchanged NULL this pointer is returned");
    }
}
