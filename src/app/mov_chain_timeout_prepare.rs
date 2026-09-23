//! `mov_chain_timeout_prepare` — original: `FUN_081e41a4` @ `0x081e41a4`.
//!
//! Raw A32 words establish the true 144-byte instruction extent
//! `0x081e41a4..0x081e4233`; its `0x2710` literal is at `0x081e4234`, and
//! the push at `0x081e4238` starts the next real function. The body has four
//! unconditional direct `bl` instructions (one lock, one timeout setup, and
//! two unlock paths), no predicated direct `bl` forms, and one unconditional
//! virtual `blx` through state-vtable slot +0x3c. Ghidra's three reported
//! call sites are the three distinct direct targets, not the four direct-call
//! instructions.
//!
//! It locks state +0x13a0, invokes the state virtual callback, records a
//! successful callback at byte +0x1391, configures state +0x139c with a
//! 10,000-unit timeout, then unlocks. Any lock, timeout, or nonzero callback
//! status maps to 3; a zero callback status skips timeout setup but still
//! unlocks. Deliberate deviation: `FUN_082283c4` has no recovered identity,
//! so target builds call its verified address while host builds use a
//! replaceable seam.

#[cfg(target_os = "none")]
use crate::app::lock_service::{lock_service_lock, lock_service_unlock};
#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::Mutex;

type StateVirtualCallback = unsafe extern "C" fn(*mut u8) -> i32;
type ConfigureTimeout = unsafe extern "C" fn(*mut u8, i32) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lock_state(state: *mut u8) -> i32 {
    unsafe { lock_service_lock(core::ptr::null_mut(), state.add(0x13a0).cast::<Mutex>()) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lock_state(_: *mut u8) -> i32 {
    0
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_state(state: *mut u8) -> i32 {
    unsafe { lock_service_unlock(core::ptr::null_mut(), state.add(0x13a0).cast::<Mutex>()) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn unlock_state(_: *mut u8) -> i32 {
    0
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn state_virtual_callback(state: *mut u8) -> i32 {
    let vtable = unsafe { state.cast::<u32>().read() } as usize;
    let callback = unsafe { ((vtable + 0x3c) as *const u32).read() } as usize;
    let callback: StateVirtualCallback = unsafe { core::mem::transmute(callback) };
    unsafe { callback(state) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_state_virtual_callback(_: *mut u8) -> i32 {
    panic!("mov_chain_timeout_prepare requires state vtable slot +0x3c")
}

#[cfg(not(target_os = "none"))]
pub static mut MOV_CHAIN_TIMEOUT_STATE_VIRTUAL: StateVirtualCallback = missing_state_virtual_callback;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn state_virtual_callback(state: *mut u8) -> i32 {
    let callback = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(MOV_CHAIN_TIMEOUT_STATE_VIRTUAL))
    };
    unsafe { callback(state) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn configure_timeout(timeout_state: *mut u8, timeout: i32) -> i32 {
    let configure: ConfigureTimeout = unsafe { core::mem::transmute(0x0822_83c4usize) };
    unsafe { configure(timeout_state, timeout) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_configure_timeout(_: *mut u8, _: i32) -> i32 {
    panic!("mov_chain_timeout_prepare requires FUN_082283c4")
}

#[cfg(not(target_os = "none"))]
pub static mut MOV_CHAIN_TIMEOUT_CONFIGURE: ConfigureTimeout = missing_configure_timeout;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn configure_timeout(timeout_state: *mut u8, timeout: i32) -> i32 {
    let configure = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(MOV_CHAIN_TIMEOUT_CONFIGURE))
    };
    unsafe { configure(timeout_state, timeout) }
}

/// mov_chain_timeout_prepare — original: `FUN_081e41a4` @ `0x081e41a4` (144 bytes).
///
/// Locks the embedded mutex, runs state-vtable slot +0x3c, and, when that
/// callback succeeds, records byte +0x1391 and configures a 10,000-unit
/// timeout at +0x139c. It always releases the mutex after a successful lock.
/// Returns zero only when every required step succeeds; all failures are 3.
///
/// # Safety
///
/// `state` must address the firmware state object, including its vtable word,
/// mutex at +0x13a0, callback-success byte at +0x1391, and timeout storage at
/// +0x139c. Its slot +0x3c callback and the timeout adapter must accept those
/// same storage regions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_chain_timeout_prepare(state: *mut u8) -> i32 {
    if unsafe { lock_state(state) } != 0 {
        return 3;
    }

    if unsafe { state_virtual_callback(state) } != 0 {
        unsafe { state.add(0x1391).write(1) };
        if unsafe { configure_timeout(state.add(0x139c), 10_000) } != 0 {
            unsafe { unlock_state(state) };
            return 3;
        }
    }

    if unsafe { unlock_state(state) } != 0 { 3 } else { 0 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex as HostMutex;
    use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

    static TEST_LOCK: HostMutex<()> = HostMutex::new(());
    static CALLBACK_RESULT: AtomicI32 = AtomicI32::new(0);
    static TIMEOUT_RESULT: AtomicI32 = AtomicI32::new(0);
    static TIMEOUT_CALLS: AtomicU32 = AtomicU32::new(0);
    static TIMEOUT_STATE: AtomicUsize = AtomicUsize::new(0);
    static TIMEOUT_VALUE: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn callback(_: *mut u8) -> i32 {
        CALLBACK_RESULT.load(Ordering::Relaxed)
    }

    unsafe extern "C" fn timeout(state: *mut u8, value: i32) -> i32 {
        TIMEOUT_CALLS.fetch_add(1, Ordering::Relaxed);
        TIMEOUT_STATE.store(state as usize, Ordering::Relaxed);
        TIMEOUT_VALUE.store(value, Ordering::Relaxed);
        TIMEOUT_RESULT.load(Ordering::Relaxed)
    }

    #[test]
    fn configures_timeout_only_after_a_successful_callback() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            MOV_CHAIN_TIMEOUT_STATE_VIRTUAL = callback;
            MOV_CHAIN_TIMEOUT_CONFIGURE = timeout;
        }

        for (callback_result, timeout_result, expected, timeout_calls, marker) in [
            (0, 0, 0, 0, 0),
            (7, 0, 0, 1, 1),
            (7, 9, 3, 1, 1),
        ] {
            let mut state = [0u8; 0x13a4];
            CALLBACK_RESULT.store(callback_result, Ordering::Relaxed);
            TIMEOUT_RESULT.store(timeout_result, Ordering::Relaxed);
            TIMEOUT_CALLS.store(0, Ordering::Relaxed);
            TIMEOUT_STATE.store(0, Ordering::Relaxed);
            TIMEOUT_VALUE.store(0, Ordering::Relaxed);

            assert_eq!(unsafe { mov_chain_timeout_prepare(state.as_mut_ptr()) }, expected);
            assert_eq!(state[0x1391], marker);
            assert_eq!(TIMEOUT_CALLS.load(Ordering::Relaxed), timeout_calls);
            if timeout_calls != 0 {
                assert_eq!(TIMEOUT_STATE.load(Ordering::Relaxed), state.as_mut_ptr().wrapping_add(0x139c) as usize);
                assert_eq!(TIMEOUT_VALUE.load(Ordering::Relaxed), 10_000);
            }
        }
    }
}
