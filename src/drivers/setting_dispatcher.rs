//! Fixed settings-dispatcher singleton accessor.
//!
//! Port:
//! - [`setting_dispatcher_get`] — original: `FUN_0820a008` @ `0x0820a008`
//!   (**88 bytes: 72 bytes of code plus its 16-byte literal pool; 10 direct
//!   `bl` call sites, all unconditional and zero predicated**).
//!
//! Raw ARM ends its code at `0x0820a050`; the pool words at
//! `0x0820a050..0x0820a060` name the private guard (`0x08a09d68`), fixed
//! object (`0x08ae4978`), `__dso_handle` (`0x089ca09c`), and the registered
//! word (`0x082112fc`). The next independently entered function begins at
//! `0x0820a060`, so Ghidra's 72-byte extent omits the literal pool.
//!
//! ## Algorithm
//!
//! Test guard bit 0; if clear and `cxa_guard_acquire` accepts the complete
//! word, construct the fixed dispatcher, register the constructor result for
//! shutdown, and release the guard. Reload and return the fixed dispatcher
//! address rather than the constructor result. All direct callers use plain
//! `bl`; none conditionally skips this accessor.
//!
//! The installed vtable's `+0x10` method accepts setting selectors 0 through
//! 5 and writes their low-byte values to fixed hardware-setting words. That
//! establishes this object's behavior without assigning an unverified class
//! identity.
//!
//! ## Deliberate deviations
//!
//! The constructor at `0x0821c198` is not ported, so target builds reach it
//! through a typed fixed-address seam and host tests replace the seam. The
//! registered word `0x082112fc` is not a valid function entry: raw ARM begins
//! there with `bne 0x082112c0`, after a separately entered function's frame
//! setup. Shutdown therefore uses an inert handler rather than inventing a
//! destructor target.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

/// `FUN_0821bd10` writes through `this + 0x1d1` during construction.
pub const SETTING_DISPATCHER_SIZE: usize = 0x1d4;

/// Fixed dispatcher storage (original: `0x08ae4978`).
pub static mut SETTING_DISPATCHER: [u8; SETTING_DISPATCHER_SIZE] = [0; SETTING_DISPATCHER_SIZE];

/// The function-local-static guard (original: `0x08a09d68`).
pub static mut SETTING_DISPATCHER_GUARD: u32 = 0;

/// ADS constructor for the fixed dispatcher at `0x0821c198`.
pub type SettingDispatcherCtor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

/// Volatile call boundaries retain the retail initialization call sequence.
static mut SETTING_DISPATCHER_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut SETTING_DISPATCHER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_setting_dispatcher_ctor(this: *mut u8) -> *mut u8 {
    let constructor: SettingDispatcherCtor = core::mem::transmute(0x0821_c198usize);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_setting_dispatcher_ctor(this: *mut u8) -> *mut u8 {
    this
}

/// Constructor boundary for `FUN_0821c198` (`bl` at `0x0820a030`).
#[cfg(target_os = "none")]
pub static mut SETTING_DISPATCHER_CTOR: SettingDispatcherCtor = firmware_setting_dispatcher_ctor;

/// Host stand-in for the retailOS constructor; tests install a recording seam.
#[cfg(not(target_os = "none"))]
pub static mut SETTING_DISPATCHER_CTOR: SettingDispatcherCtor = host_setting_dispatcher_ctor;

/// `__dso_handle`, the third `cxa_atexit` argument at `0x0820a03c`.
const DSO_HANDLE: i32 = 0x089c_a09c;

/// Safe replacement for the invalid registered word `0x082112fc`; see module docs.
unsafe extern "C" fn setting_dispatcher_destructor(_object: *mut c_void) {}

#[inline(always)]
unsafe fn setting_dispatcher_cxa_atexit() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(SETTING_DISPATCHER_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn setting_dispatcher_cxa_guard_release() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(SETTING_DISPATCHER_CXA_GUARD_RELEASE))
}

/// setting_dispatcher_get — original: `FUN_0820a008` @ `0x0820a008` (88
/// bytes: 72 bytes of code and a 16-byte literal pool; 10 direct unconditional
/// `bl` call sites, binary-verified by decoding every ARM B/BL word).
///
/// Lazily constructs and returns the fixed setting dispatcher. The accessor
/// reloads the fixed object literal after initialization, never returning the
/// constructor result. A nonzero guard with bit 0 clear reaches
/// `cxa_guard_acquire`, which refuses it exactly as the raw ARM sequence does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.setting_dispatcher_get")]
pub unsafe extern "C" fn setting_dispatcher_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(SETTING_DISPATCHER_GUARD);
    let dispatcher = core::ptr::addr_of_mut!(SETTING_DISPATCHER) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = core::ptr::read_volatile(core::ptr::addr_of!(SETTING_DISPATCHER_CTOR))(dispatcher);
        setting_dispatcher_cxa_atexit()(this as *mut c_void, setting_dispatcher_destructor, DSO_HANDLE);
        setting_dispatcher_cxa_guard_release()(guard);
    }
    dispatcher
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

    static DISPATCHER_LOCK: Mutex<()> = Mutex::new(());
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
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: setting_dispatcher_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(SETTING_DISPATCHER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = DISPATCHER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SETTING_DISPATCHER_GUARD = 0;
            for offset in 0..SETTING_DISPATCHER_SIZE {
                storage().add(offset).write(0xa5);
            }
            SETTING_DISPATCHER_CTOR = host_setting_dispatcher_ctor;
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
            SETTING_DISPATCHER_CTOR = host_setting_dispatcher_ctor;
            SETTING_DISPATCHER_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            SETTING_DISPATCHER_CTOR = recording_ctor;
            assert_eq!(setting_dispatcher_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_CALLS), std::vec![storage()]);
            assert_eq!(SETTING_DISPATCHER_GUARD, 1);
            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut u8, storage());
            assert_eq!((*node).handler as usize, setting_dispatcher_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn fast_path_preserves_state_and_does_not_register_twice() {
        let lock = reset();
        unsafe {
            SETTING_DISPATCHER_CTOR = recording_ctor;
            setting_dispatcher_get();
            storage().add(0x1d1).write(0x31);
            assert_eq!(setting_dispatcher_get(), storage());
            assert_eq!((*ptr::addr_of!(CTOR_CALLS)).len(), 1);
            assert_eq!(storage().add(0x1d1).read(), 0x31);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn guard_edge_cases_skip_construction() {
        let lock = reset();
        unsafe {
            SETTING_DISPATCHER_CTOR = recording_ctor;
            SETTING_DISPATCHER_GUARD = 3;
            assert_eq!(setting_dispatcher_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert!(shutdown_chain_head().read().is_null());

            SETTING_DISPATCHER_GUARD = 2;
            assert_eq!(setting_dispatcher_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert_eq!(SETTING_DISPATCHER_GUARD, 2);
        }
        restore(lock);
    }

    #[test]
    fn getter_returns_literal_while_shutdown_carries_constructor_result() {
        let lock = reset();
        unsafe {
            SETTING_DISPATCHER_CTOR = recording_ctor;
            CTOR_RESULT = storage().add(4);
            assert_eq!(setting_dispatcher_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(4));
        }
        restore(lock);
    }

    #[test]
    fn storage_covers_constructor_final_byte_and_noop_shutdown_preserves_it() {
        let lock = reset();
        unsafe {
            SETTING_DISPATCHER_CTOR = recording_ctor;
            setting_dispatcher_get();
            storage().add(0x1d1).write(0xa5);
            lib_shutdown_chain(0);
            assert_eq!(storage().add(0x1d1).read(), 0xa5);
        }
        assert_eq!(SETTING_DISPATCHER_SIZE, 0x1d4);
        restore(lock);
    }
}
