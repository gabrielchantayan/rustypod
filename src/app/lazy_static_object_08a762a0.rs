//! Lazy accessor for the opaque static object at `0x08a762a0`.
//!
//! Port: [`lazy_static_object_08a762a0_get`] — original: `FUN_08086d78` @
//! `0x08086d78` (88 bytes: 72 bytes of code plus a four-word literal pool).
//! Raw A32 decoding establishes four outbound plain `bl` calls
//! (`cxa_guard_acquire`, the unported constructor, `cxa_atexit`, and
//! `cxa_guard_release`) and no predicated BL calls. Whole-image decoding
//! establishes three inbound plain `bl` calls and no predicated forms.
//!
//! The object class is not identified. Its constructor at `0x081687a0` is
//! unported, so the accessor retains that direct-call boundary as a seam.
//! The pool's `0x0815d908` destructor word is an instruction inside another
//! function, not a callable entry; the host-safe no-op is deliberate.

use core::ffi::c_void;
use core::ptr;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

/// Minimum storage directly written by `FUN_081687a0`: words 0 through 9.
pub const LAZY_STATIC_OBJECT_08A762A0_SIZE: usize = 40;
const DSO_HANDLE: i32 = 0x089c_a09c;

/// ADS local-static guard, original word @ `0x089caf38`.
pub static mut LAZY_STATIC_OBJECT_08A762A0_GUARD: u32 = 0;
/// Opaque object storage, original address @ `0x08a762a0`.
pub static mut LAZY_STATIC_OBJECT_08A762A0: [u8; LAZY_STATIC_OBJECT_08A762A0_SIZE] = [0; LAZY_STATIC_OBJECT_08A762A0_SIZE];

pub type Constructor = unsafe extern "C" fn(*mut u8) -> *mut u8;
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

unsafe extern "C" fn zeroing_constructor(this: *mut u8) -> *mut u8 {
    for offset in 0..LAZY_STATIC_OBJECT_08A762A0_SIZE {
        this.add(offset).write_volatile(0);
    }
    this
}

/// Dispatch seam for unported `FUN_081687a0`.
pub static mut LAZY_STATIC_OBJECT_08A762A0_CTOR: Constructor = zeroing_constructor;
static mut LAZY_STATIC_OBJECT_08A762A0_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut LAZY_STATIC_OBJECT_08A762A0_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[inline(always)]
unsafe fn cxa_atexit_call() -> CxaAtexit {
    ptr::read_volatile(ptr::addr_of!(LAZY_STATIC_OBJECT_08A762A0_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn cxa_guard_release_call() -> CxaGuardRelease {
    ptr::read_volatile(ptr::addr_of!(LAZY_STATIC_OBJECT_08A762A0_CXA_GUARD_RELEASE))
}

/// The pool word `0x0815d908` is not a function entry, so it cannot be called.
unsafe extern "C" fn static_object_destructor(_object: *mut c_void) {}

/// `lazy_static_object_08a762a0_get` — original: `FUN_08086d78` @
/// `0x08086d78` (88 bytes: 72 bytes of code plus a four-word literal pool;
/// four outbound plain BL calls, no predicated BL calls; three inbound plain
/// BL callers, no predicated forms; raw-binary verified).
///
/// Returns the fixed opaque object, lazily initializing it with the ADS guard
/// protocol. The fast path tests bit zero only; an accepted guard acquisition
/// constructs, registers the constructor result, and releases the guard.
///
/// Deliberate deviations: firmware addresses are crate statics; the unported
/// constructor is a replaceable seam; and the non-entry destructor pool word
/// is represented by a no-op callback. The default constructor only zeroes
/// the 40 bytes directly written by the retail constructor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_static_object_08a762a0_get() -> *mut u8 {
    let guard = ptr::addr_of_mut!(LAZY_STATIC_OBJECT_08A762A0_GUARD);
    let object = ptr::addr_of_mut!(LAZY_STATIC_OBJECT_08A762A0) as *mut u8;
    if (ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let constructed = ptr::read_volatile(ptr::addr_of!(LAZY_STATIC_OBJECT_08A762A0_CTOR))(object);
        cxa_atexit_call()(constructed.cast::<c_void>(), static_object_destructor, DSO_HANDLE);
        cxa_guard_release_call()(guard);
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
    static mut CTOR_CALLS: usize = 0;
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_constructor(this: *mut u8) -> *mut u8 {
        CTOR_CALLS += 1;
        this.add(39).write_volatile(0x5a);
        CTOR_RESULT
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode { next: ptr::null_mut(), arg: ptr::null_mut(), handler: static_object_destructor, key: 0 })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(LAZY_STATIC_OBJECT_08A762A0) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            LAZY_STATIC_OBJECT_08A762A0_GUARD = 0;
            LAZY_STATIC_OBJECT_08A762A0_CTOR = zeroing_constructor;
            LAZY_STATIC_OBJECT_08A762A0_CXA_ATEXIT = cxa_atexit;
            LAZY_STATIC_OBJECT_08A762A0_CXA_GUARD_RELEASE = cxa_guard_release;
            CTOR_CALLS = 0;
            CTOR_RESULT = storage();
            *shutdown_chain_head() = ptr::null_mut();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
        }
        lock
    }

    fn restore(lock: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            LAZY_STATIC_OBJECT_08A762A0_CTOR = zeroing_constructor;
            LAZY_STATIC_OBJECT_08A762A0_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_constructor_result_and_returns_storage() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_08A762A0_CTOR = recording_constructor;
            assert_eq!(lazy_static_object_08a762a0_get(), storage());
            assert_eq!(CTOR_CALLS, 1);
            assert_eq!(storage().add(39).read(), 0x5a);
            assert_eq!(LAZY_STATIC_OBJECT_08A762A0_GUARD, 1);
            let node = *shutdown_chain_head();
            assert!(!node.is_null());
            assert_eq!((*node).arg as *mut u8, CTOR_RESULT);
            assert_eq!((*node).handler as usize, static_object_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn initialized_guard_skips_constructor_and_registration() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_08A762A0_GUARD = 1;
            LAZY_STATIC_OBJECT_08A762A0_CTOR = recording_constructor;
            assert_eq!(lazy_static_object_08a762a0_get(), storage());
            assert_eq!(CTOR_CALLS, 0);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }

    #[test]
    fn bit_zero_clear_nonzero_guard_is_refused_by_acquire() {
        let lock = reset();
        unsafe {
            LAZY_STATIC_OBJECT_08A762A0_GUARD = 2;
            LAZY_STATIC_OBJECT_08A762A0_CTOR = recording_constructor;
            assert_eq!(lazy_static_object_08a762a0_get(), storage());
            assert_eq!(CTOR_CALLS, 0);
            assert_eq!(LAZY_STATIC_OBJECT_08A762A0_GUARD, 2);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }
}
