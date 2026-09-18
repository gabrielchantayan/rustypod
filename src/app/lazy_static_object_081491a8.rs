//! An opaque function-local-static accessor.
//!
//! Port: [`lazy_static_object_081491a8_get`] — original: `FUN_081491a8` @
//! `0x081491a8` (**116 bytes: 100 bytes of code plus its 16-byte literal
//! pool; 5 direct plain `bl` calls and 0 predicated `bl` calls**).
//!
//! Raw ARM ends at `pop {r4, pc}` at `0x08149208`. The literal pool at
//! `0x0814920c..0x08149218` identifies the ready/guard pair (`0x08a09d1c`),
//! fixed object (`0x08adc720`), `__dso_handle` (`0x089ca09c`), and handler
//! word (`0x0813e448`). The next real function starts at `0x0814921c`, so the
//! raw extent is 116 bytes rather than Ghidra's code-only 100 bytes.
//!
//! ## Algorithm
//!
//! Test guard bit zero, acquire the ADS guard when clear, construct the fixed
//! object, register the constructor return for shutdown, and release the
//! guard. If the adjacent ready byte is clear, run its one-time follow-up and
//! set the byte. Every path returns the fixed object literal, not either call
//! result.
//!
//! ## Deliberate deviations
//!
//! The fixed RAM addresses are crate statics on the host. The constructor
//! (`FUN_081492d8`) and ready follow-up (`FUN_08149288`) remain device seams;
//! host tests install models. The handler word has no verified semantic name,
//! so target builds retain that raw address and host builds use an inert
//! callback.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const FIRMWARE_STATE: usize = 0x08a0_9d1c;
const FIRMWARE_OBJECT: usize = 0x08ad_c720;
const FIRMWARE_CONSTRUCTOR: usize = 0x0814_92d8;
const FIRMWARE_READY_FOLLOW_UP: usize = 0x0814_9288;
const FIRMWARE_DESTRUCTOR_WORD: usize = 0x0813_e448;
const DSO_HANDLE: i32 = 0x089c_a09c;
const OBJECT_SIZE: usize = 0x44;

type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);
pub type LazyStaticObject081491a8Constructor = unsafe extern "C" fn(*mut u8) -> *mut u8;
pub type LazyStaticObject081491a8ReadyFollowUp = unsafe extern "C" fn();

#[repr(C)]
struct LazyStaticObject081491a8State {
    ready: u8,
    _padding: [u8; 3],
    guard: u32,
}

static mut LAZY_STATIC_OBJECT_081491A8_STATE: LazyStaticObject081491a8State = LazyStaticObject081491a8State {
    ready: 0,
    _padding: [0; 3],
    guard: 0,
};
static mut LAZY_STATIC_OBJECT_081491A8: [u8; OBJECT_SIZE] = [0; OBJECT_SIZE];
static mut LAZY_STATIC_OBJECT_081491A8_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut LAZY_STATIC_OBJECT_081491A8_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_constructor(this: *mut u8) -> *mut u8 {
    let constructor: LazyStaticObject081491a8Constructor = core::mem::transmute(FIRMWARE_CONSTRUCTOR);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_constructor(_this: *mut u8) -> *mut u8 {
    panic!("lazy_static_object_081491a8_get requires constructor 0x081492d8")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_ready_follow_up() {
    let follow_up: LazyStaticObject081491a8ReadyFollowUp = core::mem::transmute(FIRMWARE_READY_FOLLOW_UP);
    follow_up();
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ready_follow_up() {
    panic!("lazy_static_object_081491a8_get requires ready follow-up 0x08149288")
}

#[cfg(target_os = "none")]
pub static mut LAZY_STATIC_OBJECT_081491A8_CTOR: LazyStaticObject081491a8Constructor = firmware_constructor;
#[cfg(not(target_os = "none"))]
pub static mut LAZY_STATIC_OBJECT_081491A8_CTOR: LazyStaticObject081491a8Constructor = missing_constructor;
#[cfg(target_os = "none")]
pub static mut LAZY_STATIC_OBJECT_081491A8_READY_FOLLOW_UP: LazyStaticObject081491a8ReadyFollowUp = firmware_ready_follow_up;
#[cfg(not(target_os = "none"))]
pub static mut LAZY_STATIC_OBJECT_081491A8_READY_FOLLOW_UP: LazyStaticObject081491a8ReadyFollowUp = missing_ready_follow_up;

#[inline(always)]
unsafe fn state() -> *mut LazyStaticObject081491a8State {
    #[cfg(target_os = "none")]
    { FIRMWARE_STATE as *mut LazyStaticObject081491a8State }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(LAZY_STATIC_OBJECT_081491A8_STATE) }
}

#[inline(always)]
unsafe fn object() -> *mut u8 {
    #[cfg(target_os = "none")]
    { FIRMWARE_OBJECT as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(LAZY_STATIC_OBJECT_081491A8) as *mut u8 }
}

#[inline(always)]
unsafe fn constructor() -> LazyStaticObject081491a8Constructor {
    core::ptr::read_volatile(core::ptr::addr_of!(LAZY_STATIC_OBJECT_081491A8_CTOR))
}

#[inline(always)]
unsafe fn ready_follow_up() -> LazyStaticObject081491a8ReadyFollowUp {
    core::ptr::read_volatile(core::ptr::addr_of!(LAZY_STATIC_OBJECT_081491A8_READY_FOLLOW_UP))
}

#[inline(always)]
unsafe fn cxa_atexit_call() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(LAZY_STATIC_OBJECT_081491A8_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn cxa_guard_release_call() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(LAZY_STATIC_OBJECT_081491A8_CXA_GUARD_RELEASE))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destructor() -> ShutdownHandlerFn {
    core::mem::transmute(FIRMWARE_DESTRUCTOR_WORD)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_destructor(_object: *mut c_void) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destructor() -> ShutdownHandlerFn {
    host_destructor
}

/// Runs the retailOS function-local-static initialization and returns its
/// fixed opaque object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_static_object_081491a8_get() -> *mut u8 {
    let state = state();
    let guard = core::ptr::addr_of_mut!((*state).guard);
    let object = object();
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = constructor()(object);
        cxa_atexit_call()(this.cast::<c_void>(), destructor(), DSO_HANDLE);
        cxa_guard_release_call()(guard);
    }
    if core::ptr::read_volatile(core::ptr::addr_of!((*state).ready)) == 0 {
        ready_follow_up()();
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).ready), 1);
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

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCTOR_CALLS: usize = 0;
    static mut FOLLOW_UP_CALLS: usize = 0;
    static mut CONSTRUCTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn modeled_constructor(this: *mut u8) -> *mut u8 {
        CONSTRUCTOR_CALLS += 1;
        this.write_volatile(0x5a);
        CONSTRUCTOR_RESULT
    }

    unsafe extern "C" fn modeled_follow_up() { FOLLOW_UP_CALLS += 1; }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode { next: ptr::null_mut(), arg: ptr::null_mut(), handler: host_destructor, key: 0 })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) { drop(Box::from_raw(block as *mut ShutdownNode)); }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            LAZY_STATIC_OBJECT_081491A8_STATE.ready = 0;
            LAZY_STATIC_OBJECT_081491A8_STATE.guard = 0;
            LAZY_STATIC_OBJECT_081491A8.fill(0xa5);
            LAZY_STATIC_OBJECT_081491A8_CTOR = missing_constructor;
            LAZY_STATIC_OBJECT_081491A8_READY_FOLLOW_UP = missing_ready_follow_up;
            LAZY_STATIC_OBJECT_081491A8_CXA_ATEXIT = cxa_atexit;
            LAZY_STATIC_OBJECT_081491A8_CXA_GUARD_RELEASE = cxa_guard_release;
            CONSTRUCTOR_CALLS = 0;
            FOLLOW_UP_CALLS = 0;
            CONSTRUCTOR_RESULT = object();
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
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_runs_follow_up_and_returns_fixed_object() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_081491A8_CTOR = modeled_constructor;
            LAZY_STATIC_OBJECT_081491A8_READY_FOLLOW_UP = modeled_follow_up;
            assert_eq!(lazy_static_object_081491a8_get(), object());
            assert_eq!(CONSTRUCTOR_CALLS, 1);
            assert_eq!(FOLLOW_UP_CALLS, 1);
            assert_eq!(LAZY_STATIC_OBJECT_081491A8_STATE.guard, 1);
            assert_eq!(LAZY_STATIC_OBJECT_081491A8_STATE.ready, 1);
            assert_eq!(object().read(), 0x5a);
            let node = *shutdown_chain_head();
            assert!(!node.is_null());
            assert_eq!((*node).arg as *mut u8, object());
            assert_eq!((*node).handler as usize, host_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn ready_fast_path_does_not_repeat_constructor_or_follow_up() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_081491A8_CTOR = modeled_constructor;
            LAZY_STATIC_OBJECT_081491A8_READY_FOLLOW_UP = modeled_follow_up;
            lazy_static_object_081491a8_get();
            assert_eq!(lazy_static_object_081491a8_get(), object());
            assert_eq!(CONSTRUCTOR_CALLS, 1);
            assert_eq!(FOLLOW_UP_CALLS, 1);
        }
        restore(lock);
    }

    #[test]
    fn rejected_nonzero_guard_still_runs_follow_up_and_returns_object() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_081491A8_CTOR = modeled_constructor;
            LAZY_STATIC_OBJECT_081491A8_READY_FOLLOW_UP = modeled_follow_up;
            LAZY_STATIC_OBJECT_081491A8_STATE.guard = 2;
            assert_eq!(lazy_static_object_081491a8_get(), object());
            assert_eq!(CONSTRUCTOR_CALLS, 0);
            assert_eq!(FOLLOW_UP_CALLS, 1);
            assert_eq!(LAZY_STATIC_OBJECT_081491A8_STATE.guard, 2);
            assert_eq!(LAZY_STATIC_OBJECT_081491A8_STATE.ready, 1);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }
}
