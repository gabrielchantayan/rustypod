//! The record-manager singleton accessor.
//!
//! Port:
//! - [`record_manager_get`] — original: `FUN_081c83b4` @ `0x081c83b4`
//!   (**104 bytes: 88 bytes of code plus its 16-byte literal pool; 20 direct
//!   `bl` call sites, all unconditional and zero predicated**).
//!
//! Raw ARM ends its code at `0x081c840c`; the four pool words at
//! `0x081c840c..0x081c8418` name the private guard state (`0x089cfd4c`),
//! fixed object (`0x08ad1f70`), `__dso_handle` (`0x089ca09c`), and registered
//! destructor (`0x081bdae8`). The next function begins at `0x081c841c`, so
//! Ghidra's reported 88-byte code extent omits the pool.
//!
//! The object owns a 128-entry primary record table and a 32-entry secondary
//! table. The unported constructor `FUN_081c8954` builds those tables and
//! finishes with the mutex at `this + 0xcd4`; therefore the fixed object's
//! exact observed extent is 0xcd8 bytes. The class identity does not survive
//! in the image, so `record_manager` describes the tables it owns rather than
//! inventing a C++ class name.
//!
//! ## Algorithm
//!
//! This is the ADS function-local-static sequence: test guard bit 0, acquire
//! the guard if clear, construct the fixed object, register the constructor's
//! return with `cxa_atexit`, release the guard, set the adjacent byte flag if
//! it was zero, then reload and return the fixed object literal. All twenty
//! callers use plain `bl`; none conditionally skip the accessor.
//!
//! ## Deliberate deviations
//!
//! The firmware's runtime RAM globals are crate statics, preserving their
//! zeroed pre-init state. The unported constructor is a replaceable seam whose
//! default zeroes the observed object extent. The destructor pool word is not
//! a callable function entry: `0x081bdae8` is an interior tail that branches
//! to a frame teardown at `0x081bda64` without establishing that frame. It
//! cannot safely run as a shutdown handler, and retailOS never runs this
//! chain, so the registered Rust handler is deliberately a no-op.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// The final mutex word is at `this + 0xcd4` in `FUN_081c8954`.
pub const RECORD_MANAGER_SIZE: usize = 0xcd8;

/// The fixed object's one-time-init guard (original: `0x089cfd50`).
pub static mut RECORD_MANAGER_GUARD: u32 = 0;

/// The adjacent byte state flag (original: `0x089cfd4c`).
pub static mut RECORD_MANAGER_READY: u8 = 0;

/// Fixed record-manager storage (original: `0x08ad1f70`).
pub static mut RECORD_MANAGER: [u8; RECORD_MANAGER_SIZE] = [0; RECORD_MANAGER_SIZE];

/// An ADS C++ constructor: receives the fixed storage and returns `this`.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// The unported `FUN_081c8954` default: zero only the known object extent.
unsafe extern "C" fn zeroing_record_manager_ctor(this: *mut u8) -> *mut u8 {
    for offset in 0..RECORD_MANAGER_SIZE {
        this.add(offset).write_volatile(0);
    }
    this
}

/// Constructor seam for `FUN_081c8954` (`bl` at `0x081c83dc`).
pub static mut RECORD_MANAGER_CTOR: Constructor = zeroing_record_manager_ctor;

/// `__dso_handle`, the third `cxa_atexit` argument at `0x081c83e0`.
const DSO_HANDLE: i32 = 0x089ca09c;

/// Deliberately inert replacement for the invalid handler pointer at
/// `0x081bdae8`; see the module header.
unsafe extern "C" fn record_manager_destructor(_object: *mut c_void) {}

/// record_manager_get — original: `FUN_081c83b4` @ `0x081c83b4` (104 bytes:
/// 88 bytes of code plus 16-byte literal pool; 20 direct, unconditional `bl`
/// call sites, binary-verified by decoding every ARM B/BL word).
///
/// Lazily constructs and returns the fixed record manager. The getter always
/// reloads the object literal after initialization; it does not return the
/// constructor's result. A bit-0-clear, nonzero guard takes the slow path but
/// is refused by `cxa_guard_acquire`, exactly like the ARM sequence.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record_manager_get")]
pub unsafe extern "C" fn record_manager_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(RECORD_MANAGER_GUARD);
    let object = core::ptr::addr_of_mut!(RECORD_MANAGER) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = core::ptr::read_volatile(core::ptr::addr_of!(RECORD_MANAGER_CTOR))(object);
        cxa_atexit(this as *mut c_void, record_manager_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }
    if core::ptr::read_volatile(core::ptr::addr_of!(RECORD_MANAGER_READY)) == 0 {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(RECORD_MANAGER_READY), 1);
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

    static RECORD_MANAGER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_BLOCKS: Vec<*mut u8> = Vec::new();
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
        this.write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: record_manager_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(RECORD_MANAGER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = RECORD_MANAGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RECORD_MANAGER_GUARD = 0;
            RECORD_MANAGER_READY = 0;
            for offset in 0..RECORD_MANAGER_SIZE {
                storage().add(offset).write(0xa5);
            }
            RECORD_MANAGER_CTOR = zeroing_record_manager_ctor;
            CTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
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
            RECORD_MANAGER_CTOR = zeroing_record_manager_ctor;
            RECORD_MANAGER_GUARD = 0;
            RECORD_MANAGER_READY = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_marks_ready_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            RECORD_MANAGER_CTOR = recording_ctor;
            assert_eq!(record_manager_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![storage()]);
            assert_eq!(RECORD_MANAGER_GUARD, 1, "acquire publishes the guard");
            assert_eq!(RECORD_MANAGER_READY, 1, "the byte flag is set after initialization");
            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut u8, storage(), "constructor return is registered");
            assert_eq!((*node).handler as usize, record_manager_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn fast_path_preserves_manager_state_and_does_not_register_twice() {
        let lock = reset();
        unsafe {
            RECORD_MANAGER_CTOR = recording_ctor;
            record_manager_get();
            storage().add(0xa0c).write(0x31);
            assert_eq!(record_manager_get(), storage());
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1);
            assert_eq!(storage().add(0xa0c).read(), 0x31);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn guard_edge_cases_skip_construction_but_still_mark_ready() {
        let lock = reset();
        unsafe {
            RECORD_MANAGER_CTOR = recording_ctor;
            RECORD_MANAGER_GUARD = 3;
            assert_eq!(record_manager_get(), storage());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
            assert_eq!(RECORD_MANAGER_READY, 1);
            assert!(shutdown_chain_head().read().is_null());

            RECORD_MANAGER_GUARD = 2;
            RECORD_MANAGER_READY = 0;
            assert_eq!(record_manager_get(), storage());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty(), "acquire rejects nonzero guards");
            assert_eq!(RECORD_MANAGER_GUARD, 2);
            assert_eq!(RECORD_MANAGER_READY, 1);
        }
        restore(lock);
    }

    #[test]
    fn getter_returns_literal_while_shutdown_carries_constructor_result() {
        let lock = reset();
        unsafe {
            RECORD_MANAGER_CTOR = recording_ctor;
            CTOR_RESULT = storage().add(4);
            assert_eq!(record_manager_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(4));
        }
        restore(lock);
    }

    #[test]
    fn default_constructor_zeroes_the_observed_extent_and_noop_destructor_preserves_it() {
        let lock = reset();
        unsafe {
            record_manager_get();
            assert!((0..RECORD_MANAGER_SIZE).all(|offset| storage().add(offset).read() == 0));
            storage().add(0xcd4).write(0xa5);
            lib_shutdown_chain(0);
            assert_eq!(storage().add(0xcd4).read(), 0xa5, "invalid stock handler is inert");
        }
        restore(lock);
    }

    #[test]
    fn object_extent_covers_the_last_constructor_mutex_word() {
        assert_eq!(RECORD_MANAGER_SIZE, 0xcd8);
    }
}
