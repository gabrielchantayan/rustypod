//! `lazy_static_object_get` — original: `FUN_08104c84` @ **0x08104c84**.
//!
//! Raw ARM establishes a 72-byte instruction extent,
//! `0x08104c84..0x08104cc8`; the following five-word literal pool occupies
//! `0x08104ccc..0x08104cdc`, and the next function starts at `0x08104ce0`.
//! Decoding every immediate ARM B/BL word in `osos.dec` finds six inbound
//! calls, all plain unconditional `bl` at `0x08104e8c`, `0x08104ebc`,
//! `0x08104ecc`, `0x08104ed8`, `0x08104efc`, and `0x08294fa8`; there are no
//! predicated BL forms. The accessor itself makes four direct BL calls:
//! `cxa_guard_acquire` @ `0x082ab31c`, the unported constructor
//! `FUN_08105378` @ `0x08105378`, `cxa_atexit` @ `0x082ab1c8`, and
//! `cxa_guard_release` @ `0x082ab338`.
//!
//! Algorithm: test bit zero of the guard at `0x089d056c`. If it is clear and
//! `cxa_guard_acquire` accepts the complete word, construct the fixed object
//! at `0x08ad8424`, register the constructor result for shutdown, and release
//! the guard. Every path returns the fixed object literal, never the
//! constructor result.
//!
//! The destructor word `0x080fa520` is not a function entry: raw bytes put it
//! inside the preceding routine, at `ldr r1, [r1, #0x24]`, followed by
//! `blx r1`. Its identity is deliberately not invented. Target builds retain
//! that exact handler word; host builds use an inert handler because invoking
//! that interior instruction as a shutdown callback is not meaningful. The
//! constructor remains unported, so target builds call its fixed retailOS
//! address and host tests install a recording seam. The fixed firmware guard
//! and object addresses are likewise modeled by host statics.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const FIRMWARE_GUARD: usize = 0x089d_056c;
const FIRMWARE_OBJECT: usize = 0x08ad_8424;
const FIRMWARE_CONSTRUCTOR: usize = 0x0810_5378;
const FIRMWARE_DESTRUCTOR_WORD: usize = 0x080f_a520;
const DSO_HANDLE: i32 = 0x089c_a09c;

/// ABI of the unported in-place constructor `FUN_08105378`.
pub type LazyStaticObjectCtor = unsafe extern "C" fn(*mut u8) -> *mut u8;

type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

/// Volatile bindings retain the retail registration and release call
/// boundaries; the empty release routine is otherwise eliminated by LLVM.
static mut LAZY_STATIC_OBJECT_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut LAZY_STATIC_OBJECT_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[inline(always)]
unsafe fn lazy_static_object_cxa_atexit() -> CxaAtexit {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LAZY_STATIC_OBJECT_CXA_ATEXIT)) }
}

#[inline(always)]
unsafe fn lazy_static_object_cxa_guard_release() -> CxaGuardRelease {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LAZY_STATIC_OBJECT_CXA_GUARD_RELEASE)) }
}

#[cfg(not(target_os = "none"))]
static mut LAZY_STATIC_OBJECT_GUARD: u32 = 0;

/// Host-only backing for the opaque fixed object. Its full extent is owned by
/// the unported constructor and is not inferred from this accessor.
#[cfg(not(target_os = "none"))]
static mut LAZY_STATIC_OBJECT: u8 = 0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lazy_static_object_guard() -> *mut u32 {
    FIRMWARE_GUARD as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lazy_static_object_guard() -> *mut u32 {
    core::ptr::addr_of_mut!(LAZY_STATIC_OBJECT_GUARD)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lazy_static_object_storage() -> *mut u8 {
    FIRMWARE_OBJECT as *mut u8
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lazy_static_object_storage() -> *mut u8 {
    core::ptr::addr_of_mut!(LAZY_STATIC_OBJECT)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_lazy_static_object_ctor(this: *mut u8) -> *mut u8 {
    let ctor: LazyStaticObjectCtor = unsafe { core::mem::transmute(FIRMWARE_CONSTRUCTOR) };
    unsafe { ctor(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lazy_static_object_ctor(_this: *mut u8) -> *mut u8 {
    panic!("lazy_static_object_get requires constructor 0x08105378")
}

/// Target builds call `FUN_08105378`; host tests replace the missing firmware
/// constructor with a model that records the exact pointer and return value.
#[cfg(target_os = "none")]
pub static mut LAZY_STATIC_OBJECT_CTOR: LazyStaticObjectCtor = firmware_lazy_static_object_ctor;

#[cfg(not(target_os = "none"))]
pub static mut LAZY_STATIC_OBJECT_CTOR: LazyStaticObjectCtor = missing_lazy_static_object_ctor;

#[inline(always)]
unsafe fn lazy_static_object_ctor() -> LazyStaticObjectCtor {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LAZY_STATIC_OBJECT_CTOR)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lazy_static_object_destructor() -> ShutdownHandlerFn {
    unsafe { core::mem::transmute(FIRMWARE_DESTRUCTOR_WORD) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_lazy_static_object_destructor(_object: *mut c_void) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lazy_static_object_destructor() -> ShutdownHandlerFn {
    host_lazy_static_object_destructor
}

/// Runs the retailOS function-local-static initialization and returns its
/// opaque fixed object.
///
/// The guard fast path tests bit zero only. A nonzero word with bit zero clear
/// enters the slow path but is rejected by [`cxa_guard_acquire`], exactly as
/// the ARM sequence specifies.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_static_object_get() -> *mut u8 {
    let guard = unsafe { lazy_static_object_guard() };
    let object = unsafe { lazy_static_object_storage() };
    if unsafe { core::ptr::read_volatile(guard) } & 1 == 0 && unsafe { cxa_guard_acquire(guard) } != 0 {
        let initialized = unsafe { lazy_static_object_ctor()(object) };
        unsafe {
            lazy_static_object_cxa_atexit()(
                initialized.cast::<c_void>(),
                lazy_static_object_destructor(),
                DSO_HANDLE,
            );
            lazy_static_object_cxa_guard_release()(guard);
        }
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static LAZY_STATIC_OBJECT_LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCTOR_INPUTS: Vec<*mut u8> = Vec::new();
    static mut CONSTRUCTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_constructor(object: *mut u8) -> *mut u8 {
        unsafe { (*ptr::addr_of_mut!(CONSTRUCTOR_INPUTS)).push(object) };
        unsafe { ptr::read_volatile(ptr::addr_of!(CONSTRUCTOR_RESULT)) }
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: host_lazy_static_object_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(node: *mut u8) {
        unsafe { drop(Box::from_raw(node.cast::<ShutdownNode>())) };
    }

    fn object() -> *mut u8 {
        unsafe { lazy_static_object_storage() }
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = LAZY_STATIC_OBJECT_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            LAZY_STATIC_OBJECT_GUARD = 0;
            LAZY_STATIC_OBJECT = 0xa5;
            LAZY_STATIC_OBJECT_CTOR = missing_lazy_static_object_ctor;
            CONSTRUCTOR_RESULT = object();
            (*ptr::addr_of_mut!(CONSTRUCTOR_INPUTS)).clear();
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
            LAZY_STATIC_OBJECT_CTOR = missing_lazy_static_object_ctor;
            LAZY_STATIC_OBJECT_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_object() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_CTOR = recording_constructor;
            let constructor_result = ptr::addr_of_mut!(CONSTRUCTOR_RESULT).cast::<u8>();
            CONSTRUCTOR_RESULT = constructor_result;

            assert_eq!(lazy_static_object_get(), object());
            assert_eq!(*ptr::addr_of!(CONSTRUCTOR_INPUTS), std::vec![object()]);
            assert_eq!(LAZY_STATIC_OBJECT_GUARD, 1, "acquire publishes the guard");

            let registration = *shutdown_chain_head();
            assert!(!registration.is_null(), "cxa_atexit registration exists");
            assert_eq!((*registration).arg, constructor_result.cast::<c_void>());
            assert_eq!((*registration).handler as usize, host_lazy_static_object_destructor as usize);
            assert_eq!((*registration).key, DSO_HANDLE);
            assert!((*registration).next.is_null(), "exactly one registration");
        }
        restore(lock);
    }

    #[test]
    fn initialized_guard_skips_constructor_and_registration() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_CTOR = recording_constructor;
            LAZY_STATIC_OBJECT_GUARD = 3;
            assert_eq!(lazy_static_object_get(), object());
            assert!((*ptr::addr_of!(CONSTRUCTOR_INPUTS)).is_empty());
            assert!(shutdown_chain_head().read().is_null());
            assert_eq!(LAZY_STATIC_OBJECT_GUARD, 3);
        }
        restore(lock);
    }

    #[test]
    fn nonzero_bit_zero_clear_guard_is_refused_by_acquire() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_CTOR = recording_constructor;
            LAZY_STATIC_OBJECT_GUARD = 2;
            assert_eq!(lazy_static_object_get(), object());
            assert!((*ptr::addr_of!(CONSTRUCTOR_INPUTS)).is_empty());
            assert!(shutdown_chain_head().read().is_null());
            assert_eq!(LAZY_STATIC_OBJECT_GUARD, 2);
        }
        restore(lock);
    }

    #[test]
    fn later_calls_take_fast_path_without_second_registration() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_CTOR = recording_constructor;
            lazy_static_object_get();
            LAZY_STATIC_OBJECT = 0x5a;
            assert_eq!(lazy_static_object_get(), object());
            assert_eq!((*ptr::addr_of!(CONSTRUCTOR_INPUTS)).len(), 1);
            assert_eq!(LAZY_STATIC_OBJECT, 0x5a, "the opaque object is not reconstructed");
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }
}
