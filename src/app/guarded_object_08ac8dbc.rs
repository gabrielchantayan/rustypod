//! Guarded fixed-object accessor — `FUN_081952d8` @ **0x081952d8**.
//!
//! True extent: 92 bytes, [0x081952d8, 0x08195334): 72 instruction bytes
//! followed by five literal words, then the next real constructor entry.
//! Raw-word verification: four plain outbound BLs, zero predicated BLs;
//! two plain inbound BLs at 0x081657e8 and 0x0825a66c, zero predicated BLs.
//! Test guard bit zero at 0x089ccb60; if clear and ADS acquire succeeds,
//! invoke constructor 0x08195334 on object 0x08ac8dbc, register its return
//! with opaque handler word 0x0818a4c8 and DSO handle 0x089ca09c, then
//! release the guard. Always return the fixed object, even when registration
//! fails or the constructor returns a different pointer.
//!
//! Deliberate deviations: constructor/handler identities remain opaque;
//! target dispatch retains their verified addresses. Host builds use local
//! storage and require an installed constructor. Tests replace registration
//! and release to isolate the process-global shutdown chain.

use core::ffi::c_void;
use core::ptr;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

pub type GuardedObjectConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Register = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type Release = unsafe extern "C" fn(*mut u32);
const DSO_HANDLE: i32 = 0x089c_a09c;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_constructor(object: *mut u8) -> *mut u8 {
    let constructor: GuardedObjectConstructor = unsafe { core::mem::transmute(0x0819_5334usize) };
    unsafe { constructor(object) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_constructor(_: *mut u8) -> *mut u8 {
    panic!("guarded_object_08ac8dbc_get requires constructor 0x08195334")
}
#[cfg(target_os = "none")]
pub static mut GUARDED_OBJECT_08AC8DBC_CONSTRUCTOR: GuardedObjectConstructor = firmware_constructor;
#[cfg(not(target_os = "none"))]
pub static mut GUARDED_OBJECT_08AC8DBC_CONSTRUCTOR: GuardedObjectConstructor = missing_constructor;
static mut REGISTER: Register = cxa_atexit;
static mut RELEASE: Release = cxa_guard_release;
#[cfg(not(target_os = "none"))]
static mut HOST_GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut HOST_OBJECT: u8 = 0;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_handler(_: *mut c_void) {}

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn guarded_object_08ac8dbc_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    let (guard, object, handler) = (0x089c_cb60 as *mut u32, 0x08ac_8dbc as *mut u8,
        unsafe { core::mem::transmute::<usize, ShutdownHandlerFn>(0x0818_a4c8) });
    #[cfg(not(target_os = "none"))]
    let (guard, object, handler) = (ptr::addr_of_mut!(HOST_GUARD), ptr::addr_of_mut!(HOST_OBJECT), host_handler as ShutdownHandlerFn);
    if unsafe { ptr::read_volatile(guard) } & 1 == 0 && unsafe { cxa_guard_acquire(guard) } != 0 {
        let constructor = unsafe { ptr::read_volatile(ptr::addr_of!(GUARDED_OBJECT_08AC8DBC_CONSTRUCTOR)) };
        let initialized = unsafe { constructor(object) };
        unsafe {
            ptr::read_volatile(ptr::addr_of!(REGISTER))(initialized.cast(), handler, DSO_HANDLE);
            ptr::read_volatile(ptr::addr_of!(RELEASE))(guard);
        }
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    static mut CONSTRUCTIONS: u32 = 0;
    static mut REGISTRATIONS: u32 = 0;
    static mut RELEASES: u32 = 0;
    static mut RESULT: u8 = 0;
    static mut REGISTER_RESULT: i32 = 1;

    unsafe extern "C" fn construct(object: *mut u8) -> *mut u8 {
        unsafe {
            assert_eq!(object, ptr::addr_of_mut!(HOST_OBJECT));
            assert_eq!(HOST_GUARD, 1); // ADS publishes before construction.
            assert_eq!(guarded_object_08ac8dbc_get(), object); // Re-entry skips construction.
            CONSTRUCTIONS += 1;
        }
        ptr::addr_of_mut!(RESULT)
    }
    unsafe extern "C" fn register(object: *mut c_void, handler: ShutdownHandlerFn, key: i32) -> i32 {
        unsafe {
            assert_eq!(CONSTRUCTIONS, 1);
            assert_eq!(RELEASES, 0);
            assert_eq!(object, ptr::addr_of_mut!(RESULT).cast());
            assert_eq!(handler as usize, host_handler as usize);
            assert_eq!(key, DSO_HANDLE);
            REGISTRATIONS += 1;
            REGISTER_RESULT
        }
    }
    unsafe extern "C" fn release(guard: *mut u32) {
        unsafe {
            assert_eq!(REGISTRATIONS, 1);
            assert_eq!(guard, ptr::addr_of_mut!(HOST_GUARD));
            RELEASES += 1;
            cxa_guard_release(guard);
        }
    }
    #[test]
    fn guard_transitions_reentry_and_registration_failure() {
        unsafe {
            GUARDED_OBJECT_08AC8DBC_CONSTRUCTOR = construct;
            REGISTER = register;
            RELEASE = release;
            for (initial, registration_result, expected) in [(0, 1, 1), (0, 0, 1), (1, 1, 0), (2, 1, 0), (3, 1, 0), (0x80000000, 1, 0)] {
                HOST_GUARD = initial;
                REGISTER_RESULT = registration_result;
                CONSTRUCTIONS = 0;
                REGISTRATIONS = 0;
                RELEASES = 0;
                assert_eq!(guarded_object_08ac8dbc_get(), ptr::addr_of_mut!(HOST_OBJECT));
                assert_eq!(guarded_object_08ac8dbc_get(), ptr::addr_of_mut!(HOST_OBJECT));
                assert_eq!((CONSTRUCTIONS, REGISTRATIONS, RELEASES), (expected, expected, expected));
                assert_eq!(HOST_GUARD, if initial == 0 { 1 } else { initial });
            }
            GUARDED_OBJECT_08AC8DBC_CONSTRUCTOR = missing_constructor;
            REGISTER = cxa_atexit;
            RELEASE = cxa_guard_release;
            HOST_GUARD = 0;
        }
    }
}
