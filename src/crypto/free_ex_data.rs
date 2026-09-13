//! OpenSSL's `CRYPTO_free_ex_data` dispatch shim.
//!
//! Port: `crypto_free_ex_data` — retailOS `FUN_080439e0` @ `0x080439e0`
//! (**60 bytes**: 56 bytes of code plus the singleton literal at
//! `0x08043a1c`). Decoding every ARM B/BL word in `osos.dec` finds **7 direct
//! call sites**, all unconditional `bl` (`0x0803d430`, `0x0803d940`,
//! `0x080623c0`, `0x0806254c`, `0x0806fe88`, `0x08070560`, and `0x080ec2b0`);
//! there are no predicated direct calls.
//!
//! # Algorithm
//!
//! The singleton at `0x08a0e9e0` holds an ex-data implementation vtable. If
//! its vtable word is null, the routine calls the lazy initializer
//! `FUN_08075914`, reloads that word, and tail-dispatches `(class_index,
//! object, ex_data)` through vtable slot `+0x14`. The dispatch target's
//! identity is not established by this wrapper, so it remains an indirect
//! call rather than being named or inlined here.
//!
//! # Deliberate deviations
//!
//! `FUN_08075914` is not ported. Target builds call its verified entry; host
//! builds model the singleton and its implementation slot with
//! [`CRYPTO_EX_DATA_OPS`]. The target tail branch is an ordinary returning
//! call because Rust functions return normally.

use core::ffi::c_void;

/// Host representation of the singleton's initialization check, initializer,
/// and `+0x14` implementation-vtable slot.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct CryptoExDataOps {
    pub is_initialized: unsafe extern "C" fn() -> bool,
    pub initialize: unsafe extern "C" fn(),
    pub free_ex_data: unsafe extern "C" fn(i32, *mut c_void, *mut c_void),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialized() -> bool {
    false
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize() {
    panic!("crypto_free_ex_data requires installed host CRYPTO_EX_DATA_OPS")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_free_ex_data(
    _class_index: i32,
    _object: *mut c_void,
    _ex_data: *mut c_void,
) {
    panic!("crypto_free_ex_data requires installed host CRYPTO_EX_DATA_OPS")
}

/// Host model of the fixed singleton and its implementation vtable.
#[cfg(not(target_os = "none"))]
pub static mut CRYPTO_EX_DATA_OPS: CryptoExDataOps = CryptoExDataOps {
    is_initialized: missing_initialized,
    initialize: missing_initialize,
    free_ex_data: missing_free_ex_data,
};

#[cfg(test)]
pub static CRYPTO_EX_DATA_OPS_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn crypto_ex_data_ops() -> CryptoExDataOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CRYPTO_EX_DATA_OPS)) }
}

/// crypto_free_ex_data — original: `FUN_080439e0` @ `0x080439e0` (60 bytes;
/// 7 direct unconditional `bl` call sites, binary-verified from `osos.dec`).
///
/// Lazily initializes the fixed ex-data implementation singleton and calls
/// its `+0x14` virtual slot with the three arguments unchanged.
///
/// # Safety
///
/// On target, the singleton at `0x08a0e9e0` and its initialized vtable must be
/// valid. `object` and `ex_data` must satisfy the installed implementation's
/// contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crypto_free_ex_data(
    class_index: i32,
    object: *mut c_void,
    ex_data: *mut c_void,
) {
    #[cfg(target_os = "none")]
    {
        const SINGLETON_OBJECT: *const u32 = 0x08a0_e9e0 as *const u32;
        const INITIALIZE_ADDRESS: usize = 0x0807_5914;

        let mut vtable = unsafe { core::ptr::read_volatile(SINGLETON_OBJECT) };
        if vtable == 0 {
            let initialize: unsafe extern "C" fn() = unsafe { core::mem::transmute(INITIALIZE_ADDRESS) };
            unsafe { initialize() };
            vtable = unsafe { core::ptr::read_volatile(SINGLETON_OBJECT) };
        }
        let free_ex_data_word = unsafe { core::ptr::read_volatile((vtable as usize as *const u32).add(5)) };
        let free_ex_data: unsafe extern "C" fn(i32, *mut c_void, *mut c_void) =
            unsafe { core::mem::transmute(free_ex_data_word as usize) };
        unsafe { free_ex_data(class_index, object, ex_data) };
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { crypto_ex_data_ops() };
        if !unsafe { (ops.is_initialized)() } {
            unsafe { (ops.initialize)() };
        }
        let ops = unsafe { crypto_ex_data_ops() };
        unsafe { (ops.free_ex_data)(class_index, object, ex_data) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::vec::Vec;

    static INITIALIZED: AtomicBool = AtomicBool::new(false);
    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Initialize,
        Free(i32, usize, usize),
    }

    unsafe extern "C" fn is_initialized() -> bool {
        INITIALIZED.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn initialize() {
        EVENTS.lock().push(Event::Initialize);
        INITIALIZED.store(true, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_free(class_index: i32, object: *mut c_void, ex_data: *mut c_void) {
        EVENTS.lock().push(Event::Free(class_index, object as usize, ex_data as usize));
    }

    unsafe extern "C" fn stale_free(_class_index: i32, _object: *mut c_void, _ex_data: *mut c_void) {
        panic!("crypto_free_ex_data failed to reload the vtable after initialization")
    }

    unsafe extern "C" fn initialize_and_replace_dispatch() {
        EVENTS.lock().push(Event::Initialize);
        INITIALIZED.store(true, Ordering::SeqCst);
        unsafe {
            core::ptr::addr_of_mut!(CRYPTO_EX_DATA_OPS).write(CryptoExDataOps {
                is_initialized,
                initialize,
                free_ex_data: record_free,
            });
        }
    }

    struct OpsGuard {
        saved: CryptoExDataOps,
    }

    impl OpsGuard {
        unsafe fn install(initialize: unsafe extern "C" fn(), free_ex_data: unsafe extern "C" fn(i32, *mut c_void, *mut c_void)) -> Self {
            let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CRYPTO_EX_DATA_OPS)) };
            unsafe {
                core::ptr::addr_of_mut!(CRYPTO_EX_DATA_OPS).write(CryptoExDataOps {
                    is_initialized,
                    initialize,
                    free_ex_data,
                });
            }
            Self { saved }
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(CRYPTO_EX_DATA_OPS).write(self.saved) };
        }
    }

    fn reset(initialized: bool) {
        INITIALIZED.store(initialized, Ordering::SeqCst);
        EVENTS.lock().clear();
    }

    #[test]
    fn initialized_singleton_dispatches_arguments_unchanged() {
        let _serial = CRYPTO_EX_DATA_OPS_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install(initialize, record_free) };
        reset(true);
        let mut object = 0u8;
        let mut ex_data = 0u8;

        unsafe {
            crypto_free_ex_data(
                6,
                (&mut object as *mut u8).cast(),
                (&mut ex_data as *mut u8).cast(),
            )
        };

        assert_eq!(*EVENTS.lock(), [Event::Free(6, (&mut object) as *mut u8 as usize, (&mut ex_data) as *mut u8 as usize)]);
    }

    #[test]
    fn uninitialized_singleton_initializes_then_reloads_dispatch() {
        let _serial = CRYPTO_EX_DATA_OPS_TEST_LOCK.lock();
        let _ops = unsafe { OpsGuard::install(initialize_and_replace_dispatch, stale_free) };
        reset(false);
        let mut object = 0u8;
        let mut ex_data = 0u8;

        unsafe {
            crypto_free_ex_data(
                0,
                (&mut object as *mut u8).cast(),
                (&mut ex_data as *mut u8).cast(),
            )
        };

        assert_eq!(
            *EVENTS.lock(),
            [
                Event::Initialize,
                Event::Free(0, (&mut object) as *mut u8 as usize, (&mut ex_data) as *mut u8 as usize),
            ],
        );
    }
}
