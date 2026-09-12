//! `service_state_synchronize` — original: `FUN_081c843c` @ `0x081c843c`.
//!
//! Raw ARM establishes **108 bytes** from `0x081c843c` through `0x081c84a7`;
//! the next separately linked function starts at `0x081c84a8`. A full-image
//! decode of every aligned ARM `B`/`BL` finds **8 inbound direct calls**: 7
//! unconditional `bl` calls at `0x081af6dc`, `0x0820cfb8`, `0x0820d028`,
//! `0x0820d1fc`, `0x0820d27c`, `0x0820d2e0`, and `0x0820d518`, plus one
//! `blne` at `0x08201a38`. The predicated caller gates the operation itself;
//! this callee has no NULL guard.
//!
//! # Algorithm
//!
//! Locks the embedded `Mutex` at `this + 0xcd4`, reads the byte at
//! `this + 0xcb8` into a transient stack byte through `FUN_081af73c`, invokes
//! the global wrapper at `0x08228400` with `this + 0xccc`, then unlocks the
//! same mutex. It returns the first nonzero helper status, or zero after the
//! complete sequence. Raw bodies establish that all four direct callees return
//! zero today; the tests cover the resulting lock/read/wrapper/unlock path.
//!
//! # Deliberate deviations
//!
//! The target calls the stock `0x08228400` wrapper directly because its
//! downstream target (`0x080d7110` with global `0x08a09d78`) has no established
//! identity or port. Host tests replace that wrapper with a recorder and shift
//! their backing object by four bytes so its target `+0xcd4` field is aligned
//! for the host's 8-byte-aligned native [`Mutex`]. The byte read is volatile
//! so the otherwise dead transient read remains observable, matching the stock
//! `ldrb` and out-parameter call.

use core::ffi::c_void;
use core::ptr;

use crate::app::lock_service::{lock_service_lock, lock_service_unlock};
use crate::kernel::sync_mutex::Mutex;

const STATE_BYTE_OFFSET: usize = 0x0cb8;
const WRAPPER_CONTEXT_OFFSET: usize = 0x0ccc;
const MUTEX_OFFSET: usize = 0x0cd4;
const RETAIL_GLOBAL_WRAPPER: usize = 0x0822_8400;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_global_wrapper(_context: *mut c_void) {}

/// Host replacement for the unidentified stock wrapper at `0x08228400`.
#[cfg(not(target_os = "none"))]
pub static mut SERVICE_STATE_GLOBAL_WRAPPER: unsafe extern "C" fn(*mut c_void) = missing_global_wrapper;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn invoke_global_wrapper(context: *mut c_void) -> i32 {
    let wrapper: unsafe extern "C" fn(*mut c_void) -> i32 =
        core::mem::transmute(RETAIL_GLOBAL_WRAPPER);
    wrapper(context)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn invoke_global_wrapper(context: *mut c_void) -> i32 {
    ptr::read_volatile(ptr::addr_of!(SERVICE_STATE_GLOBAL_WRAPPER))(context);
    // Raw 0x08228400 overwrites its callee's result with `mov r0, #0`.
    0
}

/// Synchronizes the service state under its embedded mutex.
///
/// Original: `FUN_081c843c` at `0x081c843c` (108 bytes; 8 direct callers,
/// 7 `bl` plus 1 `blne`).
///
/// # Safety
///
/// `service` must point to a writable retail service object with a live
/// [`Mutex`] at `+0xcd4`; as in stock, neither the object nor its mutex is
/// NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_state_synchronize(service: *mut u8) -> i32 {
    let wrapper_context = service.add(WRAPPER_CONTEXT_OFFSET).cast::<c_void>();
    let mutex = service.add(MUTEX_OFFSET).cast::<Mutex>();

    if lock_service_lock(wrapper_context, mutex) != 0 {
        return 1;
    }

    // `FUN_081af73c(service + 0xcb0, sp)` loads this byte and returns zero.
    let _state = ptr::read_volatile(service.add(STATE_BYTE_OFFSET));

    if invoke_global_wrapper(wrapper_context) != 0 {
        return 1;
    }

    if lock_service_unlock(wrapper_context, mutex) != 0 {
        return 1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex as TestMutex;

    static TEST_LOCK: TestMutex<()> = TestMutex::new(());
    static mut WRAPPER_CALLS: u32 = 0;
    static mut WRAPPER_CONTEXT: *mut c_void = core::ptr::null_mut();

    unsafe extern "C" fn record_global_wrapper(context: *mut c_void) {
        WRAPPER_CALLS += 1;
        WRAPPER_CONTEXT = context;
    }

    #[test]
    fn synchronizes_a_zero_handle_mutex_and_invokes_the_global_wrapper_once() {
        let _guard = TEST_LOCK.lock();
        let mut service = [0u64; (MUTEX_OFFSET + core::mem::size_of::<Mutex>() + 11) / 8];
        // Target `+0xcd4` is four-byte aligned. Shift this eight-byte-aligned
        // backing store so the host's native-width Mutex remains aligned.
        let service_bytes = unsafe { service.as_mut_ptr().cast::<u8>().add(4) };

        unsafe {
            service_bytes.add(STATE_BYTE_OFFSET).write(0xa5);
            WRAPPER_CALLS = 0;
            WRAPPER_CONTEXT = core::ptr::null_mut();
            SERVICE_STATE_GLOBAL_WRAPPER = record_global_wrapper;

            assert_eq!(service_state_synchronize(service_bytes), 0);
            assert_eq!(WRAPPER_CALLS, 1);
            assert_eq!(WRAPPER_CONTEXT, service_bytes.add(WRAPPER_CONTEXT_OFFSET).cast());

            SERVICE_STATE_GLOBAL_WRAPPER = missing_global_wrapper;
        }
    }
}
