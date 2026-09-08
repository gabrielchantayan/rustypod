//! The StreamCache mass-storage-manager singleton accessor.
//!
//! Port:
//! - [`stream_cache_mass_storage_manager_get`] — original: `FUN_08228068` @
//!   `0x08228068` (**88 bytes: 72 bytes of code plus its 16-byte literal
//!   pool; 19 direct `bl` call sites, all unconditional and zero
//!   predicated**).
//!
//! Raw ARM ends its code at `0x082280b0`; the four pool words at
//! `0x082280b0..0x082280c0` name the private guard (`0x08a09d74`), fixed
//! object (`0x08ae4b4c`), `__dso_handle` (`0x089ca09c`), and registered
//! handler (`0x0821d440`). The next separately linked function starts at
//! `0x082280c0`, so Ghidra's 72-byte code extent drops the literal pool.
//!
//! ## Algorithm
//!
//! Test guard bit 0; if clear and `cxa_guard_acquire` accepts the whole
//! zero-valued word, construct the fixed manager through `FUN_08228270`,
//! register the constructor return with `cxa_atexit`, and release the guard.
//! Reload and return the fixed object literal regardless of the constructor
//! return value. Every direct caller is a plain `bl`; none conditionally
//! skips this accessor.
//!
//! ## Deliberate deviations
//!
//! On-device the constructor seam calls the retained retailOS constructor at
//! `0x08228270`. Host tests replace it because that code is unavailable there;
//! their default is an inert return of the already zero-initialized fixed
//! storage. The registered word `0x0821d440` is not a function entry: the
//! actual frame-establishing prologue begins at `0x0821d43c`, so entering at
//! `+4` eventually pops an unestablished frame. The Rust shutdown handler is
//! deliberately a no-op rather than inventing a callable destructor.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// The worker at `FUN_082280c0` reads the final word at `this + 0x30`.
pub const STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE: usize = 0x34;

/// Fixed manager storage (original: `0x08ae4b4c`).
pub static mut STREAM_CACHE_MASS_STORAGE_MANAGER: [u8; STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE] =
    [0; STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE];

/// The function-local-static guard (original: `0x08a09d74`).
pub static mut STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD: u32 = 0;

/// An ADS C++ constructor: receives the fixed storage and returns `this`.
pub type MassStorageManagerCtor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_mass_storage_manager_ctor(this: *mut u8) -> *mut u8 {
    let constructor: MassStorageManagerCtor = core::mem::transmute(0x0822_8270usize);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_mass_storage_manager_ctor(this: *mut u8) -> *mut u8 {
    this
}

/// Constructor boundary for `FUN_08228270` (`bl` at `0x08228090`).
#[cfg(target_os = "none")]
pub static mut STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR: MassStorageManagerCtor =
    firmware_mass_storage_manager_ctor;

/// Host stand-in for the retailOS constructor; tests install a recording seam.
#[cfg(not(target_os = "none"))]
pub static mut STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR: MassStorageManagerCtor =
    host_mass_storage_manager_ctor;

/// `__dso_handle`, the third `cxa_atexit` argument at `0x08228098`.
const DSO_HANDLE: i32 = 0x089c_a09c;

/// Safe replacement for invalid handler word `0x0821d440`; see module docs.
unsafe extern "C" fn mass_storage_manager_destructor(_object: *mut c_void) {}

/// stream_cache_mass_storage_manager_get — original: `FUN_08228068` @
/// `0x08228068` (88 bytes: 72 bytes of code and a 16-byte literal pool; 19
/// direct unconditional `bl` call sites, binary-verified by decoding every
/// ARM B/BL word).
///
/// Lazily constructs and returns the fixed manager. The accessor reloads the
/// fixed-object literal after initialization, never returning the constructor
/// result. A nonzero guard with bit 0 clear reaches `cxa_guard_acquire`, which
/// refuses it exactly as the raw ARM sequence does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_cache_mass_storage_manager_get")]
pub unsafe extern "C" fn stream_cache_mass_storage_manager_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD);
    let manager = core::ptr::addr_of_mut!(STREAM_CACHE_MASS_STORAGE_MANAGER) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = core::ptr::read_volatile(core::ptr::addr_of!(STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR))(manager);
        cxa_atexit(this as *mut c_void, mass_storage_manager_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }
    manager
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

    static MANAGER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_CALLS: Vec<*mut u8> = Vec::new();
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_CALLS)).push(this);
        this.write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: mass_storage_manager_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(STREAM_CACHE_MASS_STORAGE_MANAGER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = MANAGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD = 0;
            for offset in 0..STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE {
                storage().add(offset).write(0xa5);
            }
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = host_mass_storage_manager_ctor;
            CTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CTOR_CALLS)).clear();
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
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = host_mass_storage_manager_ctor;
            STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_CALLS), std::vec![storage()]);
            assert_eq!(STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD, 1);
            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut u8, storage());
            assert_eq!((*node).handler as usize, mass_storage_manager_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn fast_path_preserves_state_and_does_not_register_twice() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            stream_cache_mass_storage_manager_get();
            storage().add(0x30).write(0x31);
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert_eq!((*ptr::addr_of!(CTOR_CALLS)).len(), 1);
            assert_eq!(storage().add(0x30).read(), 0x31);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn guard_edge_cases_skip_construction() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD = 3;
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert!(shutdown_chain_head().read().is_null());

            STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD = 2;
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert_eq!(STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD, 2);
        }
        restore(lock);
    }

    #[test]
    fn getter_returns_literal_while_shutdown_carries_constructor_result() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            CTOR_RESULT = storage().add(4);
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(4));
        }
        restore(lock);
    }

    #[test]
    fn storage_covers_worker_final_word_and_noop_shutdown_preserves_it() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            stream_cache_mass_storage_manager_get();
            storage().add(0x30).write(0xa5);
            lib_shutdown_chain(0);
            assert_eq!(storage().add(0x30).read(), 0xa5);
        }
        assert_eq!(STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE, 0x34);
        restore(lock);
    }
}
