//! `global_observer_get` — original: `FUN_080b43e8` @ 0x080b43e8.
//! True extent: 88 bytes (72 code + 16 literal bytes), ending at the next
//! independent `bx lr` function at 0x080b4440. Raw aligned A32 decoding finds
//! two incoming plain BLs, four outgoing plain BLs, and zero predicated BLs.
//!
//! Tests guard bit zero, acquires the whole-word ADS guard, constructs the
//! fixed observable array, registers its return with the exact handler word
//! 0x08266e54 and DSO key 0x089ca09c, then releases the guard. Always returns
//! fixed storage, including when registration fails. Acquire publishes first.
//! Deliberate deviations: host backing replaces fixed addresses; registration
//! has a module-local binding (default: ported cxa_atexit), as in
//! lazy_static_object.rs. The handler word starts with BL inside existing code;
//! no destructor identity is inferred. Host invocation of it is unsupported.

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut};
use crate::cxx::observable_array::{observable_array_construct, ObservableArray, FrameworkObject};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

type Registration = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type Release = unsafe extern "C" fn(*mut u32);
static mut REGISTER: Registration = cxa_atexit;
static mut RELEASE: Release = cxa_guard_release;

#[cfg(not(target_os = "none"))]
static mut GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut OBJECT: ObservableArray = ObservableArray {
    base: FrameworkObject { vtable: 0 }, len: 0, storage: 0, observers: 0,
};

#[inline(always)]
unsafe fn guard() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x089c_c89c as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { addr_of_mut!(GUARD) }
}

#[inline(always)]
unsafe fn storage() -> *mut ObservableArray {
    #[cfg(target_os = "none")]
    { 0x08a7_9d84 as *mut ObservableArray }
    #[cfg(not(target_os = "none"))]
    { addr_of_mut!(OBJECT) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unsupported_handler(_: *mut c_void) {
    panic!("retail handler word 0x08266e54 cannot execute on host")
}

#[inline(always)]
unsafe fn handler() -> ShutdownHandlerFn {
    #[cfg(target_os = "none")]
    { core::mem::transmute(0x0826_6e54usize) }
    #[cfg(not(target_os = "none"))]
    { unsupported_handler }
}

/// Returns the fixed global observable array. Requires single-threaded access
/// to the retail static and a working shutdown allocator on first use.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_observer_get() -> *mut ObservableArray {
    let guard = guard();
    let object = storage();
    if guard.read_volatile() & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        let initialized = observable_array_construct(object);
        core::ptr::read_volatile(addr_of!(REGISTER))(initialized.cast(), handler(), 0x089c_a09c);
        core::ptr::read_volatile(addr_of!(RELEASE))(guard);
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE;
    static mut CALLS: u32 = 0;
    static mut RESULT: i32 = 1;

    unsafe extern "C" fn registration(object: *mut c_void, _: ShutdownHandlerFn, key: i32) -> i32 {
        assert_eq!(object, storage().cast());
        assert_eq!(key, 0x089c_a09c);
        assert_eq!(guard().read(), 1);
        // Re-entry sees the published guard and must not recursively register.
        assert_eq!(global_observer_get(), storage());
        CALLS += 1;
        RESULT
    }

    #[test]
    fn initializes_once_even_if_registration_fails_and_reenters() {
        unsafe {
            addr_of_mut!(REGISTER).write(registration);
            for result in [0, 1] {
                RESULT = result;
                CALLS = 0;
                guard().write(0);
                storage().cast::<u32>().write(0xdead_beef);
                for word in 1..4 { storage().cast::<u32>().add(word).write(u32::MAX); }
                assert_eq!(global_observer_get(), storage());
                assert_eq!((*storage()).base.vtable, OBSERVABLE_ARRAY_VTABLE);
                assert_eq!((*storage()).len, 0);
                assert_eq!((*storage()).storage, 0);
                assert_eq!((*storage()).observers, 0);
                (*storage()).len = 7;
                assert_eq!(global_observer_get(), storage());
                assert_eq!((*storage()).len, 7);
                assert_eq!(addr_of!(CALLS).read(), 1);
            }
            for seed in [1, 2, 0x8000_0000, u32::MAX] {
                guard().write(seed);
                CALLS = 0;
                storage().cast::<u32>().write(0xdead_beef);
                (*storage()).len = 19;
                assert_eq!(global_observer_get(), storage());
                assert_eq!(guard().read(), seed);
                assert_eq!((*storage()).base.vtable, 0xdead_beef);
                assert_eq!((*storage()).len, 19);
                assert_eq!(addr_of!(CALLS).read(), 0);
            }
            addr_of_mut!(REGISTER).write(cxa_atexit);
        }
    }
}
