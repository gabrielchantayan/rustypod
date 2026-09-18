//! The transfer-slot buffer singleton accessor.
//!
//! Port: [`transfer_slot_buffer_get`] — original: `FUN_080f7e7c` @
//! `0x080f7e7c` (**112 bytes: 96 bytes of code plus its 16-byte literal pool;
//! 4 direct, unconditional `bl` instructions and zero predicated `bl`
//! instructions**). Raw ARM ends at `0x080f7ed8`; its literals at
//! `0x080f7edc..0x080f7ee8` identify the ready/guard state, fixed 160-byte
//! transfer-slot buffer, `__dso_handle`, and an interior shutdown-handler
//! address. The next real function starts at `0x080f7eec`.
//!
//! ## Algorithm
//!
//! Test the ADS guard bit, acquire it if clear, initialize the four 0x28-byte
//! transfer slots, register the initializer result with `cxa_atexit`, and
//! release the guard. Independently set the adjacent ready byte if it is
//! clear, then return the fixed buffer.
//!
//! ## Deliberate deviations
//!
//! Fixed firmware RAM is crate-static. The adjacent initializer at
//! `0x080f7eec` is retained as a raw-address target seam; its host model
//! performs its four observed byte clears. The registered handler literal
//! `0x080ed15c` is an interior instruction in a function beginning at
//! `0x080ed144`, so the Rust shutdown handler is deliberately inert.

use core::ffi::c_void;
use core::ptr;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

pub const TRANSFER_SLOT_BUFFER_SIZE: usize = 0xa0;
const TRANSFER_SLOT_BUFFER_INITIALIZE_ADDRESS: usize = 0x080f_7eec;
const DSO_HANDLE: i32 = 0x089c_a09c;

type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);
pub type TransferSlotBufferInitialize = unsafe extern "C" fn(*mut u8) -> *mut u8;

static mut TRANSFER_SLOT_BUFFER_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut TRANSFER_SLOT_BUFFER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[repr(C)]
struct TransferSlotBufferState {
    ready: u8,
    _padding: [u8; 3],
    guard: u32,
}

static mut TRANSFER_SLOT_BUFFER_STATE: TransferSlotBufferState = TransferSlotBufferState {
    ready: 0,
    _padding: [0; 3],
    guard: 0,
};

/// Fixed transfer-slot storage (original: `0x08ae47a8`).
pub static mut TRANSFER_SLOT_BUFFER: [u8; TRANSFER_SLOT_BUFFER_SIZE] = [0; TRANSFER_SLOT_BUFFER_SIZE];

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_transfer_slot_buffer_initialize(this: *mut u8) -> *mut u8 {
    let initialize: TransferSlotBufferInitialize = core::mem::transmute(TRANSFER_SLOT_BUFFER_INITIALIZE_ADDRESS);
    initialize(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_transfer_slot_buffer_initialize(this: *mut u8) -> *mut u8 {
    for offset in [0, 0x28, 0x50, 0x78] {
        ptr::write_volatile(this.add(offset), 0);
    }
    this
}

/// Initializer seam for `FUN_080f7eec` (`bl` at `0x080f7ec8`).
pub static mut TRANSFER_SLOT_BUFFER_INITIALIZE: TransferSlotBufferInitialize = {
    #[cfg(target_os = "none")]
    { firmware_transfer_slot_buffer_initialize }
    #[cfg(not(target_os = "none"))]
    { host_transfer_slot_buffer_initialize }
};

unsafe extern "C" fn transfer_slot_buffer_destructor(_object: *mut c_void) {}

#[inline(always)]
unsafe fn transfer_slot_buffer_initialize() -> TransferSlotBufferInitialize {
    ptr::read_volatile(ptr::addr_of!(TRANSFER_SLOT_BUFFER_INITIALIZE))
}

#[inline(always)]
unsafe fn transfer_slot_buffer_cxa_atexit() -> CxaAtexit {
    ptr::read_volatile(ptr::addr_of!(TRANSFER_SLOT_BUFFER_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn transfer_slot_buffer_cxa_guard_release() -> CxaGuardRelease {
    ptr::read_volatile(ptr::addr_of!(TRANSFER_SLOT_BUFFER_CXA_GUARD_RELEASE))
}

/// Lazily initializes and returns the fixed four-slot transfer buffer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.transfer_slot_buffer_get")]
pub unsafe extern "C" fn transfer_slot_buffer_get() -> *mut u8 {
    let state = ptr::addr_of_mut!(TRANSFER_SLOT_BUFFER_STATE);
    let guard = ptr::addr_of_mut!((*state).guard);
    let buffer = ptr::addr_of_mut!(TRANSFER_SLOT_BUFFER) as *mut u8;

    if (ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let initialized = transfer_slot_buffer_initialize()(buffer);
        transfer_slot_buffer_cxa_atexit()(initialized.cast::<c_void>(), transfer_slot_buffer_destructor, DSO_HANDLE);
        transfer_slot_buffer_cxa_guard_release()(guard);
    }
    if ptr::read_volatile(ptr::addr_of!((*state).ready)) == 0 {
        ptr::write_volatile(ptr::addr_of_mut!((*state).ready), 1);
    }
    buffer
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
    static mut INITIALIZE_CALLS: usize = 0;
    static mut INITIALIZE_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn modeled_initialize(this: *mut u8) -> *mut u8 {
        INITIALIZE_CALLS += 1;
        host_transfer_slot_buffer_initialize(this);
        ptr::read_volatile(ptr::addr_of!(INITIALIZE_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: transfer_slot_buffer_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn buffer() -> *mut u8 {
        ptr::addr_of_mut!(TRANSFER_SLOT_BUFFER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            TRANSFER_SLOT_BUFFER_STATE.ready = 0;
            TRANSFER_SLOT_BUFFER_STATE.guard = 0;
            for offset in 0..TRANSFER_SLOT_BUFFER_SIZE { buffer().add(offset).write(0xa5); }
            TRANSFER_SLOT_BUFFER_INITIALIZE = host_transfer_slot_buffer_initialize;
            TRANSFER_SLOT_BUFFER_CXA_ATEXIT = cxa_atexit;
            TRANSFER_SLOT_BUFFER_CXA_GUARD_RELEASE = cxa_guard_release;
            INITIALIZE_CALLS = 0;
            INITIALIZE_RESULT = buffer();
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
            TRANSFER_SLOT_BUFFER_INITIALIZE = host_transfer_slot_buffer_initialize;
            TRANSFER_SLOT_BUFFER_CXA_ATEXIT = cxa_atexit;
            TRANSFER_SLOT_BUFFER_CXA_GUARD_RELEASE = cxa_guard_release;
            TRANSFER_SLOT_BUFFER_STATE.ready = 0;
            TRANSFER_SLOT_BUFFER_STATE.guard = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_initializes_slots_registers_and_marks_ready() {
        let lock = reset();
        unsafe {
            TRANSFER_SLOT_BUFFER_INITIALIZE = modeled_initialize;
            assert_eq!(transfer_slot_buffer_get(), buffer());
            assert_eq!(INITIALIZE_CALLS, 1);
            assert_eq!(TRANSFER_SLOT_BUFFER_STATE.guard, 1);
            assert_eq!(TRANSFER_SLOT_BUFFER_STATE.ready, 1);
            for offset in [0, 0x28, 0x50, 0x78] { assert_eq!(buffer().add(offset).read(), 0); }
            let node = *shutdown_chain_head();
            assert!(!node.is_null());
            assert_eq!((*node).arg as *mut u8, buffer());
            assert_eq!((*node).handler as usize, transfer_slot_buffer_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn completed_guard_skips_initialization_and_registration() {
        let lock = reset();
        unsafe {
            TRANSFER_SLOT_BUFFER_INITIALIZE = modeled_initialize;
            TRANSFER_SLOT_BUFFER_STATE.guard = 1;
            assert_eq!(transfer_slot_buffer_get(), buffer());
            assert_eq!(INITIALIZE_CALLS, 0);
            assert_eq!(TRANSFER_SLOT_BUFFER_STATE.ready, 1);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }

    #[test]
    fn rejected_nonzero_guard_still_marks_ready() {
        let lock = reset();
        unsafe {
            TRANSFER_SLOT_BUFFER_INITIALIZE = modeled_initialize;
            TRANSFER_SLOT_BUFFER_STATE.guard = 2;
            assert_eq!(transfer_slot_buffer_get(), buffer());
            assert_eq!(INITIALIZE_CALLS, 0);
            assert_eq!(TRANSFER_SLOT_BUFFER_STATE.guard, 2);
            assert_eq!(TRANSFER_SLOT_BUFFER_STATE.ready, 1);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }

    #[test]
    fn returns_fixed_buffer_when_initializer_returns_another_pointer() {
        let lock = reset();
        unsafe {
            TRANSFER_SLOT_BUFFER_INITIALIZE = modeled_initialize;
            INITIALIZE_RESULT = buffer().add(4);
            assert_eq!(transfer_slot_buffer_get(), buffer());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, buffer().add(4));
        }
        restore(lock);
    }
}
