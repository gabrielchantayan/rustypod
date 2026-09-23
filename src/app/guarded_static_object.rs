//! `guarded_static_object_get` — original: `FUN_081e22c0` @ **0x081e22c0**.
//!
//! Raw `osos.dec` establishes 72 instruction bytes at `0x081e22c0..0x081e2307`,
//! followed by its four-word literal pool through `0x081e2317`; the next real
//! function starts at `0x081e2318`, making the true extent 88 bytes. Decoding
//! every immediate ARM B/BL word finds three inbound plain `bl` calls
//! (`0x0808cd68`, `0x081e60e0`, and `0x081e61ac`) and no predicated BL calls.
//! The function makes four plain BL calls: `cxa_guard_acquire` @ `0x082ab31c`,
//! unported constructor `FUN_081e2358` @ `0x081e2358`, `cxa_atexit` @
//! `0x082ab1c8`, and `cxa_guard_release` @ `0x082ab338`.
//!
//! Algorithm: test bit zero of guard `0x089caf3c`; if clear and acquired,
//! construct the fixed object `0x08a762c8`, register the constructor return
//! with handler word `0x081d74bc` and `__dso_handle` `0x089ca09c`, then release
//! the guard. Every path returns the fixed object, not the constructor result.
//!
//! Deliberate deviation: the constructor and destructor identities are not
//! inferred. Target builds dispatch the constructor to its verified retailOS
//! address and retain the raw destructor word; host tests provide a recording
//! constructor and inert destructor.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const FIRMWARE_GUARD: usize = 0x089c_af3c;
const FIRMWARE_OBJECT: usize = 0x08a7_62c8;
const FIRMWARE_CONSTRUCTOR: usize = 0x081e_2358;
const FIRMWARE_DESTRUCTOR_WORD: usize = 0x081d_74bc;
const DSO_HANDLE: i32 = 0x089c_a09c;

pub type GuardedStaticObjectCtor = unsafe extern "C" fn(*mut u8) -> *mut u8;
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

static mut GUARDED_STATIC_OBJECT_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut GUARDED_STATIC_OBJECT_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[cfg(not(target_os = "none"))]
static mut GUARDED_STATIC_OBJECT_GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut GUARDED_STATIC_OBJECT: u8 = 0;

#[inline(always)]
unsafe fn cxa_atexit_call() -> CxaAtexit {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GUARDED_STATIC_OBJECT_CXA_ATEXIT)) }
}

#[inline(always)]
unsafe fn cxa_guard_release_call() -> CxaGuardRelease {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GUARDED_STATIC_OBJECT_CXA_GUARD_RELEASE)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn guard() -> *mut u32 { FIRMWARE_GUARD as *mut u32 }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn guard() -> *mut u32 { core::ptr::addr_of_mut!(GUARDED_STATIC_OBJECT_GUARD) }

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn object() -> *mut u8 { FIRMWARE_OBJECT as *mut u8 }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn object() -> *mut u8 { core::ptr::addr_of_mut!(GUARDED_STATIC_OBJECT) }

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_constructor(this: *mut u8) -> *mut u8 {
    let constructor: GuardedStaticObjectCtor = unsafe { core::mem::transmute(FIRMWARE_CONSTRUCTOR) };
    unsafe { constructor(this) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_constructor(_this: *mut u8) -> *mut u8 {
    panic!("guarded_static_object_get requires constructor 0x081e2358")
}

#[cfg(target_os = "none")]
pub static mut GUARDED_STATIC_OBJECT_CTOR: GuardedStaticObjectCtor = firmware_constructor;
#[cfg(not(target_os = "none"))]
pub static mut GUARDED_STATIC_OBJECT_CTOR: GuardedStaticObjectCtor = missing_constructor;

#[inline(always)]
unsafe fn constructor() -> GuardedStaticObjectCtor {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GUARDED_STATIC_OBJECT_CTOR)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destructor() -> ShutdownHandlerFn { unsafe { core::mem::transmute(FIRMWARE_DESTRUCTOR_WORD) } }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_destructor(_object: *mut c_void) {}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destructor() -> ShutdownHandlerFn { host_destructor }

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn guarded_static_object_get() -> *mut u8 {
    let guard = unsafe { guard() };
    let object = unsafe { object() };
    if unsafe { core::ptr::read_volatile(guard) } & 1 == 0 && unsafe { cxa_guard_acquire(guard) } != 0 {
        let initialized = unsafe { constructor()(object) };
        unsafe {
            cxa_atexit_call()(initialized.cast::<c_void>(), destructor(), DSO_HANDLE);
            cxa_guard_release_call()(guard);
        }
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE};
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INPUTS: Vec<*mut u8> = Vec::new();
    static mut RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_constructor(value: *mut u8) -> *mut u8 {
        unsafe { (*ptr::addr_of_mut!(INPUTS)).push(value) };
        unsafe { ptr::read_volatile(ptr::addr_of!(RESULT)) }
    }
    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode { next: ptr::null_mut(), arg: ptr::null_mut(), handler: host_destructor, key: 0 })) as *mut u8
    }
    unsafe extern "C" fn box_free(node: *mut u8) { unsafe { drop(Box::from_raw(node.cast::<ShutdownNode>())) }; }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            GUARDED_STATIC_OBJECT_GUARD = 0;
            GUARDED_STATIC_OBJECT = 0xa5;
            GUARDED_STATIC_OBJECT_CTOR = missing_constructor;
            RESULT = object();
            (*ptr::addr_of_mut!(INPUTS)).clear();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        lock
    }
    fn restore(lock: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            GUARDED_STATIC_OBJECT_CTOR = missing_constructor;
            GUARDED_STATIC_OBJECT_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_object() {
        let lock = reset();
        unsafe {
            GUARDED_STATIC_OBJECT_CTOR = recording_constructor;
            RESULT = ptr::addr_of_mut!(RESULT).cast::<u8>();
            assert_eq!(guarded_static_object_get(), object());
            assert_eq!(*ptr::addr_of!(INPUTS), std::vec![object()]);
            assert_eq!(GUARDED_STATIC_OBJECT_GUARD, 1);
            let registration = *shutdown_chain_head();
            assert!(!registration.is_null());
            assert_eq!((*registration).arg, RESULT.cast::<c_void>());
            assert_eq!((*registration).handler as usize, host_destructor as usize);
            assert_eq!((*registration).key, DSO_HANDLE);
            assert!((*registration).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn initialized_guard_skips_constructor_and_registration() {
        let lock = reset();
        unsafe {
            GUARDED_STATIC_OBJECT_CTOR = recording_constructor;
            GUARDED_STATIC_OBJECT_GUARD = 3;
            assert_eq!(guarded_static_object_get(), object());
            assert!((*ptr::addr_of!(INPUTS)).is_empty());
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }

    #[test]
    fn incomplete_nonzero_guard_is_rejected_without_construction() {
        let lock = reset();
        unsafe {
            GUARDED_STATIC_OBJECT_CTOR = recording_constructor;
            GUARDED_STATIC_OBJECT_GUARD = 2;
            assert_eq!(guarded_static_object_get(), object());
            assert!((*ptr::addr_of!(INPUTS)).is_empty());
            assert!(shutdown_chain_head().read().is_null());
            assert_eq!(GUARDED_STATIC_OBJECT_GUARD, 2);
        }
        restore(lock);
    }
}
