//! `global_dispatch_target_get` — original: `FUN_081f39c8` @ **0x081f39c8**.
//!
//! Raw ARM establishes a 76-byte instruction extent,
//! `0x081f39c8..0x081f3a14`; its five-word literal pool occupies
//! `0x081f3a14..0x081f3a24`, and the next function starts at `0x081f3a28`.
//! Decoding every direct ARM B/BL word in `osos.dec` finds four inbound plain
//! `bl` calls at `0x081533dc`, `0x08159650`, `0x081596b0`, and `0x08159744`;
//! there are no predicated BL forms or tail branches. The accessor itself calls
//! `cxa_guard_acquire` @ `0x082ab31c`, `cxa_atexit` @ `0x082ab1c8`, and
//! `cxa_guard_release` @ `0x082ab338`.
//!
//! Algorithm: test bit zero of the guard at `0x089cb204`. If clear and the
//! complete guard word is acquired, store fixed dispatch target `0x089900d0`
//! into slot `0x089cb208`, register that slot with the handler word
//! `0x081e8bc4`, and release the guard. Every path returns the slot, whose
//! first word is the dispatch target.
//!
//! Deliberate deviations: the handler word does not have a recovered function
//! identity, so target builds retain it exactly while host builds use an inert
//! handler. Host statics model the fixed guard, slot, and dispatch-target word.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const FIRMWARE_GUARD: usize = 0x089c_b204;
const FIRMWARE_SLOT: usize = 0x089c_b208;
const FIRMWARE_DISPATCH_TARGET: usize = 0x0899_00d0;
const FIRMWARE_HANDLER_WORD: usize = 0x081e_8bc4;
const DSO_HANDLE: i32 = 0x089c_a09c;

type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

/// Volatile bindings retain the retail registration and release call
/// boundaries; the empty release routine is otherwise eliminated by LLVM.
static mut GLOBAL_DISPATCH_TARGET_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut GLOBAL_DISPATCH_TARGET_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[inline(always)]
unsafe fn global_dispatch_target_cxa_atexit() -> CxaAtexit {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_DISPATCH_TARGET_CXA_ATEXIT)) }
}

#[inline(always)]
unsafe fn global_dispatch_target_cxa_guard_release() -> CxaGuardRelease {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_DISPATCH_TARGET_CXA_GUARD_RELEASE)) }
}

#[cfg(not(target_os = "none"))]
static mut GLOBAL_DISPATCH_TARGET_GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut GLOBAL_DISPATCH_TARGET_SLOT: *mut u8 = core::ptr::null_mut();
#[cfg(not(target_os = "none"))]
static mut GLOBAL_DISPATCH_TARGET: u8 = 0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_dispatch_target_guard() -> *mut u32 {
    FIRMWARE_GUARD as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn global_dispatch_target_guard() -> *mut u32 {
    core::ptr::addr_of_mut!(GLOBAL_DISPATCH_TARGET_GUARD)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_dispatch_target_slot() -> *mut *mut u8 {
    FIRMWARE_SLOT as *mut *mut u8
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn global_dispatch_target_slot() -> *mut *mut u8 {
    core::ptr::addr_of_mut!(GLOBAL_DISPATCH_TARGET_SLOT)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn fixed_dispatch_target() -> *mut u8 {
    FIRMWARE_DISPATCH_TARGET as *mut u8
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fixed_dispatch_target() -> *mut u8 {
    core::ptr::addr_of_mut!(GLOBAL_DISPATCH_TARGET)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_dispatch_target_handler() -> ShutdownHandlerFn {
    unsafe { core::mem::transmute(FIRMWARE_HANDLER_WORD) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_global_dispatch_target_handler(_slot: *mut c_void) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn global_dispatch_target_handler() -> ShutdownHandlerFn {
    host_global_dispatch_target_handler
}

/// Publishes and returns the global dispatch-target slot.
///
/// # Safety
///
/// On target, the fixed firmware guard, slot, and dispatch target addresses
/// must remain valid. The returned slot is an ARM-layout word containing the
/// dispatch target pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_dispatch_target_get() -> *mut *mut u8 {
    let guard = unsafe { global_dispatch_target_guard() };
    let slot = unsafe { global_dispatch_target_slot() };
    if unsafe { core::ptr::read_volatile(guard) } & 1 == 0 && unsafe { cxa_guard_acquire(guard) } != 0 {
        unsafe {
            slot.write(fixed_dispatch_target());
            global_dispatch_target_cxa_atexit()(
                slot.cast::<c_void>(),
                global_dispatch_target_handler(),
                DSO_HANDLE,
            );
            global_dispatch_target_cxa_guard_release()(guard);
        }
    }
    slot
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

    static GLOBAL_DISPATCH_TARGET_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(),
            handler: host_global_dispatch_target_handler, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(node: *mut u8) {
        unsafe { drop(Box::from_raw(node.cast::<ShutdownNode>())) };
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = GLOBAL_DISPATCH_TARGET_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            GLOBAL_DISPATCH_TARGET_GUARD = 0;
            GLOBAL_DISPATCH_TARGET_SLOT = ptr::null_mut();
            GLOBAL_DISPATCH_TARGET = 0xa5;
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
            GLOBAL_DISPATCH_TARGET_GUARD = 0;
            GLOBAL_DISPATCH_TARGET_SLOT = ptr::null_mut();
        }
        drop(lock);
    }

    #[test]
    fn first_call_publishes_slot_and_registers_it() {
        let lock = reset();
        unsafe {
            let slot = global_dispatch_target_get();
            assert_eq!(slot, global_dispatch_target_slot());
            assert_eq!(slot.read(), fixed_dispatch_target());
            assert_eq!(GLOBAL_DISPATCH_TARGET_GUARD, 1);
            let registration = *shutdown_chain_head();
            assert!(!registration.is_null());
            assert_eq!((*registration).arg, slot.cast::<c_void>());
            assert_eq!((*registration).handler as usize, host_global_dispatch_target_handler as usize);
            assert_eq!((*registration).key, DSO_HANDLE);
            assert!((*registration).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn initialized_guard_preserves_existing_slot_without_registration() {
        let lock = reset();
        unsafe {
            let existing = ptr::addr_of_mut!(GLOBAL_DISPATCH_TARGET).cast::<u8>();
            GLOBAL_DISPATCH_TARGET_SLOT = existing;
            GLOBAL_DISPATCH_TARGET_GUARD = 3;
            assert_eq!(global_dispatch_target_get(), global_dispatch_target_slot());
            assert_eq!(GLOBAL_DISPATCH_TARGET_SLOT, existing);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }

    #[test]
    fn nonzero_bit_zero_clear_guard_is_refused_by_acquire() {
        let lock = reset();
        unsafe {
            GLOBAL_DISPATCH_TARGET_GUARD = 2;
            assert_eq!(global_dispatch_target_get(), global_dispatch_target_slot());
            assert!(GLOBAL_DISPATCH_TARGET_SLOT.is_null());
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }
}
