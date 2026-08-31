//! The AppMotor fixed singleton accessor.
//!
//! Port:
//! - [`app_motor_get`] — original: `FUN_08295be0` @ 0x08295be0
//!   (88 bytes: 56 bytes of code plus a 4-word literal pool; **27
//!   unconditional plain `bl` call sites, no predicated forms or tail
//!   branches**, verified by decoding every ARM B/BL word in osos.dec).
//!
//! The accessor is an ADS function-local static over the fixed AppMotor
//! object at 0x08a1b774. Its constructor, `FUN_08296cc8`, identifies the
//! object through the literal `"eAppMotor"` and writes through +0x2b4, so its
//! exact storage extent is 0x2b8 bytes. The constructor is not yet ported;
//! [`APP_MOTOR_CTOR`] preserves the direct-call boundary as a seam.
//!
//! The pool's destructor word, 0x0828bf04, is not a function entry: raw ARM
//! places it inside `FUN_0828bed0`, on the conditional `beq 0x0828bf10`.
//! Registering that address as a shutdown callback cannot produce a valid
//! call frame. retailOS never runs this shutdown chain in normal operation;
//! the Rust port deliberately uses a no-op callback, as other verified
//! non-entry destructor pool words do.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// Exact fixed storage extent: `FUN_08296cc8`'s final word store is at +0x2b4.
pub const APP_MOTOR_SIZE: usize = 0x2b8;

/// The common ADS `__dso_handle` literal, pool word @ 0x08295c30.
const DSO_HANDLE: i32 = 0x089ca09c;

/// The one-time guard, original word @ 0x089ca8b8 (pool word @ 0x08295c28).
pub static mut APP_MOTOR_GUARD: u32 = 0;

/// Fixed AppMotor storage, original object @ 0x08a1b774 (pool word @ 0x08295c2c).
pub static mut APP_MOTOR: [u8; APP_MOTOR_SIZE] = [0; APP_MOTOR_SIZE];

/// An ADS C++ constructor: it receives storage and returns `this` in r0.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// Host-safe default for the unported `FUN_08296cc8` constructor.
///
/// This is deliberately incomplete: the retail constructor initializes
/// embedded objects and app state, so a target hook is not safe until that
/// constructor is ported or installed through [`APP_MOTOR_CTOR`]. Volatile
/// byte stores avoid an ARM `__aeabi_memclr` libcall.
unsafe extern "C" fn zeroing_app_motor_ctor(this: *mut u8) -> *mut u8 {
    for offset in 0..APP_MOTOR_SIZE {
        this.add(offset).write_volatile(0);
    }
    this
}

/// Dispatch seam for unported AppMotor constructor `FUN_08296cc8`.
pub static mut APP_MOTOR_CTOR: Constructor = zeroing_app_motor_ctor;

/// The pool word @ 0x08295c34 is 0x0828bf04, a verified non-entry branch.
/// A no-op is the deliberate, observable shutdown-chain-safe deviation.
unsafe extern "C" fn app_motor_destructor(_object: *mut c_void) {}

/// app_motor_get — original: `FUN_08295be0` @ 0x08295be0 (88 bytes:
/// 56 bytes of code plus a 4-word literal pool; 27 unconditional plain
/// `bl` call sites, no predicated forms or tail branches, binary-verified).
///
/// Returns the fixed AppMotor object and runs its C++ local-static
/// initialization exactly once. The fast path tests guard bit 0, then the
/// slow path acquires the complete guard word, calls the constructor,
/// registers its return with `cxa_atexit`, and releases the guard.
///
/// Deliberate deviations: the fixed firmware addresses are crate statics,
/// the unported constructor is a replaceable seam, and the non-entry
/// destructor pool word is represented by a no-op callback. Therefore this
/// accessor is not hook-ready with its default constructor.
///
/// Faithful details:
/// - The object literal is returned after initialization, never the
///   constructor's return; only `cxa_atexit` receives the latter.
/// - `tst guard,#1` admits a bit-0-clear nonzero guard to the slow path,
///   where `cxa_guard_acquire` rejects it; no construction occurs.
/// - A refused acquire returns the fixed object without registration.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_motor_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(APP_MOTOR_GUARD);
    let object = core::ptr::addr_of_mut!(APP_MOTOR) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = core::ptr::read_volatile(core::ptr::addr_of!(APP_MOTOR_CTOR))(object);
        cxa_atexit(this as *mut c_void, app_motor_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
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

    /// Serializes global singleton and shutdown-chain state.
    static APP_MOTOR_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_BLOCKS: Vec<*mut u8> = Vec::new();
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
        this.add(0x245).write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: app_motor_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(APP_MOTOR) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = APP_MOTOR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            APP_MOTOR_GUARD = 0;
            for offset in 0..APP_MOTOR_SIZE {
                storage().add(offset).write(0xa5);
            }
            APP_MOTOR_CTOR = zeroing_app_motor_ctor;
            CTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            APP_MOTOR_CTOR = zeroing_app_motor_ctor;
            APP_MOTOR_GUARD = 0;
        }
        drop(guard);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_storage() {
        let guard = reset();
        unsafe {
            APP_MOTOR_CTOR = recording_ctor;
            assert_eq!(app_motor_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![storage()]);
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_MOTOR_GUARD)), 1);
            assert_eq!(storage().add(0x245).read(), 0x5a);

            let head = *shutdown_chain_head();
            assert!(!head.is_null(), "registered with cxa_atexit");
            assert_eq!((*head).arg as *mut u8, storage());
            assert_eq!((*head).handler as usize, app_motor_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE);
            assert!((*head).next.is_null(), "registered once");
        }
        restore(guard);
    }

    #[test]
    fn bit_zero_fast_path_preserves_existing_object() {
        let guard = reset();
        unsafe {
            APP_MOTOR_CTOR = recording_ctor;
            app_motor_get();
            storage().add(0x294).write(0x33);
            assert_eq!(app_motor_get(), storage());
            assert_eq!(app_motor_get(), storage());
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1);
            assert_eq!(storage().add(0x294).read(), 0x33);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(guard);
    }

    #[test]
    fn bit_zero_clear_nonzero_guard_is_refused_by_acquire() {
        let guard = reset();
        unsafe {
            APP_MOTOR_CTOR = recording_ctor;
            APP_MOTOR_GUARD = 2;
            assert_eq!(app_motor_get(), storage());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_MOTOR_GUARD)), 2);
            assert!(shutdown_chain_head().read().is_null());
            assert_eq!(storage().read(), 0xa5);
        }
        restore(guard);
    }

    #[test]
    fn registration_receives_constructor_result_but_return_is_fixed_object() {
        let guard = reset();
        unsafe {
            APP_MOTOR_CTOR = recording_ctor;
            CTOR_RESULT = storage().add(8);
            assert_eq!(app_motor_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(8));
        }
        restore(guard);
    }

    #[test]
    fn registered_non_entry_destructor_is_shutdown_safe_noop() {
        let guard = reset();
        unsafe {
            APP_MOTOR_CTOR = recording_ctor;
            app_motor_get();
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(guard);
    }
}
