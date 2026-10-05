//! Event-dispatch singleton accessor — `FUN_081e1448` @ **0x081e1448**.
//!
//! True extent: **88 bytes**, 72 instruction bytes followed by four literal
//! words; the next real function starts at 0x081e14a0. Raw A32 decoding finds
//! two inbound plain BLs (0x081d228c, 0x081d24e4), zero predicated inbound BLs,
//! and four outgoing plain BLs, zero predicated outgoing BLs.
//!
//! Test guard bit zero; if clear and acquired, construct fixed object
//! 0x08ad7db8, register the constructor return with handler word 0x081d6724
//! and DSO handle 0x089ca09c, then release the guard. Always return the fixed
//! object, even when acquisition or shutdown registration fails. Callers use
//! it for virtual event dispatch and fallback event handling; its class name
//! is unknown. The constructor at 0x081e1594 remains unported.
//!
//! Deliberate deviations: target constructor dispatch retains its verified
//! firmware address; host builds use private storage and require a constructor
//! seam. Tests isolate shutdown registration rather than mutate its shared
//! global chain. No guessed constructor or destructor implementation.

use core::ffi::c_void;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

pub type EventDispatchConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;
type RegisterShutdown = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type ReleaseGuard = unsafe extern "C" fn(*mut u32);
const DSO_HANDLE: i32 = 0x089c_a09c;
static mut REGISTER_SHUTDOWN: RegisterShutdown = cxa_atexit;
static mut RELEASE_GUARD: ReleaseGuard = cxa_guard_release;

#[cfg(not(target_os = "none"))]
static mut GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut OBJECT: [u32; 20] = [0; 20];

#[inline(always)]
unsafe fn guard() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x089d_01ec as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(GUARD) }
}
#[inline(always)]
unsafe fn object() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x08ad_7db8 as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(OBJECT).cast() }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_constructor(this: *mut u8) -> *mut u8 {
    let ctor: EventDispatchConstructor = core::mem::transmute(0x081e_1594usize);
    ctor(this)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_constructor(_this: *mut u8) -> *mut u8 {
    panic!("event_dispatch_singleton_get requires constructor 0x081e1594")
}
#[cfg(target_os = "none")]
pub static mut EVENT_DISPATCH_CONSTRUCTOR: EventDispatchConstructor = firmware_constructor;
#[cfg(not(target_os = "none"))]
pub static mut EVENT_DISPATCH_CONSTRUCTOR: EventDispatchConstructor = missing_constructor;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_destructor(_object: *mut c_void) {}
#[inline(always)]
unsafe fn destructor() -> ShutdownHandlerFn {
    #[cfg(target_os = "none")]
    { core::mem::transmute(0x081d_6724usize) }
    #[cfg(not(target_os = "none"))]
    { host_destructor }
}

/// Return the fixed event-dispatch singleton, initializing it once.
///
/// # Safety
/// Firmware storage and constructor must be valid; calls and seam changes
/// must be externally serialized, as with the original ADS guard helpers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn event_dispatch_singleton_get() -> *mut u8 {
    let guard = guard();
    let object = object();
    if core::ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        let ctor = core::ptr::read_volatile(core::ptr::addr_of!(EVENT_DISPATCH_CONSTRUCTOR));
        let initialized = ctor(object);
        let register = core::ptr::read_volatile(core::ptr::addr_of!(REGISTER_SHUTDOWN));
        register(initialized.cast(), destructor(), DSO_HANDLE);
        let release = core::ptr::read_volatile(core::ptr::addr_of!(RELEASE_GUARD));
        release(guard);
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCTIONS: u32 = 0;
    static mut REGISTRATIONS: u32 = 0;
    static mut RELEASES: u32 = 0;
    static mut RESULT: u8 = 0;

    unsafe extern "C" fn construct(this: *mut u8) -> *mut u8 {
        assert_eq!(this, object());
        assert_eq!(guard().read(), 1);
        CONSTRUCTIONS += 1;
        // ADS acquire publishes the flag before construction: reentry skips it.
        assert_eq!(event_dispatch_singleton_get(), this);
        core::ptr::addr_of_mut!(RESULT)
    }
    unsafe extern "C" fn register(arg: *mut c_void, handler: ShutdownHandlerFn, key: i32) -> i32 {
        assert_eq!(CONSTRUCTIONS, 1);
        assert_eq!(RELEASES, 0);
        assert_eq!(arg, core::ptr::addr_of_mut!(RESULT).cast());
        assert_eq!(handler as usize, host_destructor as *const () as usize);
        assert_eq!(key, DSO_HANDLE);
        REGISTRATIONS += 1;
        0 // Allocation failure must not undo initialization or change the return.
    }
    unsafe extern "C" fn release(value: *mut u32) {
        assert_eq!(value, guard());
        assert_eq!(REGISTRATIONS, 1);
        RELEASES += 1;
        cxa_guard_release(value);
    }

    #[test]
    fn initialization_reentry_registration_failure_and_guard_states() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            EVENT_DISPATCH_CONSTRUCTOR = construct;
            REGISTER_SHUTDOWN = register;
            RELEASE_GUARD = release;
            for initial_guard in [0, 1, 2, 3, 0x8000_0000] {
                GUARD = initial_guard;
                CONSTRUCTIONS = 0;
                REGISTRATIONS = 0;
                RELEASES = 0;
                assert_eq!(event_dispatch_singleton_get(), object());
                let expected = u32::from(initial_guard == 0);
                assert_eq!(CONSTRUCTIONS, expected);
                assert_eq!(REGISTRATIONS, expected);
                assert_eq!(RELEASES, expected);
                assert_eq!(GUARD, if initial_guard == 0 { 1 } else { initial_guard });
                assert_eq!(event_dispatch_singleton_get(), object());
                assert_eq!(CONSTRUCTIONS, expected);
                assert_eq!(REGISTRATIONS, expected);
                assert_eq!(RELEASES, expected);
            }
            EVENT_DISPATCH_CONSTRUCTOR = missing_constructor;
            REGISTER_SHUTDOWN = cxa_atexit;
            RELEASE_GUARD = cxa_guard_release;
            GUARD = 0;
        }
    }
}
