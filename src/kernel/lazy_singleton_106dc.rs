//! C++ local-static accessor for the singleton at 0x220106dc.
//!
//! `lazy_singleton_106dc_target_acquire` — original: `FUN_080060e0` @
//! 0x080060e0 (104 bytes: 88 bytes of code and a four-word literal pool;
//! **4 plain unconditional `bl` calls, no predicated calls**, verified
//! from osos.dec). The next real function begins at 0x08006148.
//!
//! The accessor tests bit 0 of the guard word at 0x22008ce0. When clear and
//! acquired, it constructs the fixed singleton, registers its destructor,
//! and releases the guard. It then sets the separate state byte at
//! 0x22008cdc if needed and always returns 0x220106dc.
//!
//! Deliberate deviations: host builds use static state and object fixtures;
//! the unported constructor remains an address-backed seam. The destructor
//! is called through its verified IRAM address on target and is a host no-op.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

const STATE_ADDRESS: usize = 0x2200_8cdc;
const OBJECT_ADDRESS: usize = 0x2201_06dc;
const DESTRUCTOR_ADDRESS: usize = 0x2200_6ab4;
const DSO_HANDLE: i32 = 0x089c_a09c;

#[cfg(not(target_os = "none"))]
#[repr(align(4))]
struct HostState([u8; 8]);

#[cfg(not(target_os = "none"))]
static mut HOST_STATE: HostState = HostState([0; 8]);
#[cfg(not(target_os = "none"))]
static mut HOST_OBJECT: u8 = 0;

#[inline(always)]
unsafe fn state() -> *mut u8 {
    #[cfg(target_os = "none")]
    { STATE_ADDRESS as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(HOST_STATE.0).cast() }
}

#[inline(always)]
unsafe fn object() -> *mut u8 {
    #[cfg(target_os = "none")]
    { OBJECT_ADDRESS as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(HOST_OBJECT) }
}

pub type SingletonConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn original_singleton_constructor(this: *mut u8) -> *mut u8 {
    let constructor: SingletonConstructor = unsafe { core::mem::transmute(0x0800_6988usize) };
    unsafe { constructor(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn original_singleton_constructor(this: *mut u8) -> *mut u8 { this }

/// The unported `FUN_08006988` constructor boundary.
pub static mut SINGLETON_106DC_CONSTRUCTOR: SingletonConstructor = original_singleton_constructor;

#[cfg(target_os = "none")]
unsafe extern "C" fn singleton_destructor(this: *mut c_void) {
    let destructor: unsafe extern "C" fn(*mut c_void) = unsafe {
        core::mem::transmute(DESTRUCTOR_ADDRESS)
    };
    unsafe { destructor(this) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn singleton_destructor(_this: *mut c_void) {}

/// Acquires the fixed 0x220106dc singleton through its ADS C++ once guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_singleton_106dc_target_acquire() -> *mut u8 {
    let state = unsafe { state() };
    let guard = unsafe { state.add(4).cast::<u32>() };
    if unsafe { core::ptr::read_volatile(guard) } & 1 == 0
        && unsafe { cxa_guard_acquire(guard) } != 0
    {
        let object = unsafe { object() };
        let this = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SINGLETON_106DC_CONSTRUCTOR))(object) };
        unsafe { cxa_atexit(this.cast::<c_void>(), singleton_destructor, DSO_HANDLE) };
        unsafe { cxa_guard_release(guard) };
    }
    if unsafe { state.read() } == 0 {
        unsafe { state.write(1) };
    }
    unsafe { object() }
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

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCTIONS: u32 = 0;

    unsafe extern "C" fn recording_constructor(this: *mut u8) -> *mut u8 {
        CONSTRUCTIONS += 1;
        this.write(0x5a);
        this.add(1)
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: singleton_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            HOST_STATE = HostState([0; 8]);
            HOST_OBJECT = 0;
            CONSTRUCTIONS = 0;
            SINGLETON_106DC_CONSTRUCTOR = recording_constructor;
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
            SINGLETON_106DC_CONSTRUCTOR = original_singleton_constructor;
        }
        drop(lock);
    }

    #[test]
    fn initializes_once_marks_both_state_fields_and_returns_fixed_object() {
        let lock = reset();
        unsafe {
            let fixed = object();
            assert_eq!(lazy_singleton_106dc_target_acquire(), fixed);
            assert_eq!(CONSTRUCTIONS, 1);
            assert_eq!(fixed.read(), 0x5a);
            assert_eq!(state().read(), 1);
            assert_eq!(state().add(4).cast::<u32>().read(), 1);
            assert_eq!(lazy_singleton_106dc_target_acquire(), fixed);
            assert_eq!(CONSTRUCTIONS, 1);
        }
        restore(lock);
    }

    #[test]
    fn nonzero_bit_zero_clear_guard_skips_constructor_but_sets_state_byte() {
        let lock = reset();
        unsafe {
            state().add(4).cast::<u32>().write(2);
            assert_eq!(lazy_singleton_106dc_target_acquire(), object());
            assert_eq!(CONSTRUCTIONS, 0);
            assert_eq!(state().add(4).cast::<u32>().read(), 2);
            assert_eq!(state().read(), 1);
        }
        restore(lock);
    }
}
