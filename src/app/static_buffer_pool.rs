//! Lazy accessor for the ten-slot, 192-byte-buffer pool used by the five-entry
//! allocation/free loops at 0x08104ce0 and 0x08105024.
//!
//! `static_buffer_pool_get` — FUN_08205eb0 @ 0x08205eb0, **88 bytes**:
//! 72 instruction bytes and 16 literal bytes, next function at 0x08205f08.
//! Raw A32 words contain four outbound plain BLs, no predicated BLs; whole
//! image decoding finds two inbound plain BLs, no predicated BLs.
//! Test object+8 guard bit zero, acquire the complete guard, invoke the stock
//! initializer, register its r0 with the stock handler word and DSO handle,
//! release, and return the fixed object (not the initializer result).
//!
//! Deviations: target addresses and unported initializer/handler are retained
//! exactly; host builds substitute storage and require an explicit initializer
//! binding. Tests replace registration/release to avoid shared shutdown state.

use core::{ffi::c_void, ptr};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

type Initializer = unsafe extern "C" fn(*mut u32) -> *mut u32;
type Register = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type Release = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
static mut HOST_OBJECT: [u32; 3] = [0; 3];
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initializer(_: *mut u32) -> *mut u32 {
    panic!("static_buffer_pool_get requires stock initializer 0x08205f08")
}
#[cfg(not(target_os = "none"))]
static mut INITIALIZER: Initializer = missing_initializer;
static mut REGISTER: Register = cxa_atexit;
static mut RELEASE: Release = cxa_guard_release;

#[inline(always)]
unsafe fn object() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x08a0_9fec as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_OBJECT).cast() }
}

#[inline(always)]
unsafe fn initializer() -> Initializer {
    #[cfg(target_os = "none")]
    { core::mem::transmute(0x0820_5f08usize) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(INITIALIZER)) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_handler(_: *mut c_void) {
    panic!("stock shutdown handler 0x081fb080 is unavailable on host")
}

#[inline(always)]
unsafe fn handler() -> ShutdownHandlerFn {
    #[cfg(target_os = "none")]
    { core::mem::transmute(0x081f_b080usize) }
    #[cfg(not(target_os = "none"))]
    { host_handler }
}

/// Returns the fixed pool after ADS one-time initialization.
///
/// # Safety
/// Target firmware globals and the stock initializer must be available. The
/// caller must obey the retail single-threaded initialization protocol.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn static_buffer_pool_get() -> *mut u32 {
    let pool = object();
    let guard = pool.add(2);
    if ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        let initialized = initializer()(pool);
        ptr::read_volatile(ptr::addr_of!(REGISTER))(initialized.cast(), handler(), 0x089c_a09c);
        ptr::read_volatile(ptr::addr_of!(RELEASE))(guard);
    }
    pool
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut PHASE: u32 = 0;
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn initialize(pool: *mut u32) -> *mut u32 {
        assert_eq!(PHASE, 0);
        assert_eq!(pool.add(2).read(), 1); // acquire publishes before construction
        assert_eq!(static_buffer_pool_get(), pool); // recursive access must skip
        pool.write(0x12345678);
        PHASE = 1;
        ptr::addr_of_mut!(RESULT)
    }
    unsafe extern "C" fn register(arg: *mut c_void, callback: ShutdownHandlerFn, dso: i32) -> i32 {
        assert_eq!(PHASE, 1);
        assert_eq!(arg, ptr::addr_of_mut!(RESULT).cast());
        assert_eq!(callback as usize, host_handler as *const () as usize);
        assert_eq!(dso, 0x089ca09c);
        PHASE = 2;
        -1 // ignored allocation failure must still release
    }
    unsafe extern "C" fn release(guard: *mut u32) {
        assert_eq!(PHASE, 2);
        assert_eq!(guard, object().add(2));
        cxa_guard_release(guard);
        PHASE = 3;
    }

    #[test]
    fn first_access_publishes_registers_and_releases_even_when_registration_fails() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            HOST_OBJECT = [0, 0xabcdef01, 0];
            PHASE = 0;
            INITIALIZER = initialize;
            REGISTER = register;
            RELEASE = release;
            assert_eq!(static_buffer_pool_get(), object());
            assert_eq!(HOST_OBJECT, [0x12345678, 0xabcdef01, 1]);
            assert_eq!(PHASE, 3);
            assert_eq!(static_buffer_pool_get(), object());
            assert_eq!(PHASE, 3);
            INITIALIZER = missing_initializer;
            REGISTER = cxa_atexit;
            RELEASE = cxa_guard_release;
        }
    }

    #[test]
    fn every_nonzero_guard_skips_initialization_including_bit_zero_clear() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            INITIALIZER = missing_initializer;
            for guard in [1, 2, 4, 0x80000000, u32::MAX] {
                HOST_OBJECT = [7, 9, guard];
                assert_eq!(static_buffer_pool_get(), object());
                assert_eq!(HOST_OBJECT, [7, 9, guard]);
            }
        }
    }
}

