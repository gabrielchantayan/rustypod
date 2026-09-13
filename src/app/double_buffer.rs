//! The double-buffer singleton accessor.
//!
//! Port:
//! - [`double_buffer_get`] — original: `FUN_0820c338` @ `0x0820c338`
//!   (**104 bytes: 88 bytes of code plus its 16-byte literal pool; 7 direct
//!   `bl` call sites, all unconditional and zero predicated**).
//!
//! Raw ARM ends at the `pop {r4, pc}` at `0x0820c38c`. Its four literal-pool
//! words at `0x0820c390..0x0820c39c` identify the state (`0x08a09d2c`: ready
//! byte followed by guard word), fixed 64-byte object (`0x08adc768`),
//! `__dso_handle` (`0x089ca09c`), and the registered handler word
//! (`0x08201778`). The next function starts at `0x0820c3a0`; therefore the
//! raw extent is 104 bytes, not Ghidra's code-only 88 bytes.
//!
//! ## Algorithm
//!
//! This is the ADS function-local-static sequence: test guard bit 0, acquire
//! the guard when clear, construct the fixed double-buffer state, register the
//! constructor result with `cxa_atexit`, release the guard, set the adjacent
//! ready byte when clear, then reload and return the fixed object literal.
//! Raw branch decoding finds seven inbound calls, all plain `bl`; no caller
//! predicates this accessor.
//!
//! ## Deliberate deviations
//!
//! The fixed RAM state is represented by crate statics. The unported
//! constructor `FUN_0820c5dc` is a device seam to its verified raw entry; its
//! host default preserves zero-initialized storage so tests can install an
//! explicit model. The handler literal `0x08201778` decodes as an interior
//! instruction sequence using live caller registers, not a callable function
//! entry, so its Rust `cxa_atexit` handler is deliberately inert.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

/// The two 0x1c-byte slots and their 8-byte header finish at `this + 0x3c`.
pub const DOUBLE_BUFFER_SIZE: usize = 0x40;
const DOUBLE_BUFFER_CONSTRUCTOR_ADDRESS: usize = 0x0820_c5dc;
const DSO_HANDLE: i32 = 0x089c_a09c;

/// Volatile bindings preserve the ADS registration and release call boundaries.
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

static mut DOUBLE_BUFFER_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut DOUBLE_BUFFER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

/// Exact state layout at `0x08a09d2c`: ready byte followed by the ADS guard.
#[repr(C)]
struct DoubleBufferState {
    ready: u8,
    _padding: [u8; 3],
    guard: u32,
}

static mut DOUBLE_BUFFER_STATE: DoubleBufferState = DoubleBufferState {
    ready: 0,
    _padding: [0; 3],
    guard: 0,
};

/// Fixed double-buffer state storage (original: `0x08adc768`).
pub static mut DOUBLE_BUFFER: [u8; DOUBLE_BUFFER_SIZE] = [0; DOUBLE_BUFFER_SIZE];

/// ABI of the unported in-place ADS constructor `FUN_0820c5dc`.
pub type DoubleBufferConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_double_buffer_constructor(this: *mut u8) -> *mut u8 {
    let constructor: DoubleBufferConstructor = core::mem::transmute(DOUBLE_BUFFER_CONSTRUCTOR_ADDRESS);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_double_buffer_constructor(this: *mut u8) -> *mut u8 {
    this
}

/// Constructor seam for `FUN_0820c5dc` (`bl` at `0x0820c360`).
pub static mut DOUBLE_BUFFER_CTOR: DoubleBufferConstructor = {
    #[cfg(target_os = "none")]
    {
        firmware_double_buffer_constructor
    }
    #[cfg(not(target_os = "none"))]
    {
        host_double_buffer_constructor
    }
};

/// The stock handler word `0x08201778` is an interior sequence; see header.
unsafe extern "C" fn double_buffer_destructor(_object: *mut c_void) {}

#[inline(always)]
unsafe fn double_buffer_ctor() -> DoubleBufferConstructor {
    core::ptr::read_volatile(core::ptr::addr_of!(DOUBLE_BUFFER_CTOR))
}

#[inline(always)]
unsafe fn double_buffer_cxa_atexit() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(DOUBLE_BUFFER_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn double_buffer_cxa_guard_release() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(DOUBLE_BUFFER_CXA_GUARD_RELEASE))
}

/// double_buffer_get — original: `FUN_0820c338` @ `0x0820c338` (104 bytes:
/// 88 bytes of code plus 16-byte literal pool; 7 direct, unconditional `bl`
/// call sites, binary-verified by decoding every ARM B/BL word).
///
/// Lazily constructs and returns the fixed double-buffer state. A nonzero
/// guard with bit 0 clear enters the slow path but is refused by
/// `cxa_guard_acquire`; the ready byte is still set, matching the ARM code.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.double_buffer_get")]
pub unsafe extern "C" fn double_buffer_get() -> *mut u8 {
    let state = core::ptr::addr_of_mut!(DOUBLE_BUFFER_STATE);
    let guard = core::ptr::addr_of_mut!((*state).guard);
    let object = core::ptr::addr_of_mut!(DOUBLE_BUFFER) as *mut u8;

    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = double_buffer_ctor()(object);
        double_buffer_cxa_atexit()(this.cast::<c_void>(), double_buffer_destructor, DSO_HANDLE);
        double_buffer_cxa_guard_release()(guard);
    }
    if core::ptr::read_volatile(core::ptr::addr_of!((*state).ready)) == 0 {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).ready), 1);
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

    static DOUBLE_BUFFER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_CALLS: usize = 0;
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn modeled_constructor(this: *mut u8) -> *mut u8 {
        CTOR_CALLS += 1;
        this.write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: double_buffer_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(DOUBLE_BUFFER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = DOUBLE_BUFFER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            DOUBLE_BUFFER_STATE.ready = 0;
            DOUBLE_BUFFER_STATE.guard = 0;
            for offset in 0..DOUBLE_BUFFER_SIZE {
                storage().add(offset).write(0xa5);
            }
            DOUBLE_BUFFER_CTOR = host_double_buffer_constructor;
            DOUBLE_BUFFER_CXA_ATEXIT = cxa_atexit;
            DOUBLE_BUFFER_CXA_GUARD_RELEASE = cxa_guard_release;
            CTOR_CALLS = 0;
            CTOR_RESULT = storage();
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
            DOUBLE_BUFFER_CTOR = host_double_buffer_constructor;
            DOUBLE_BUFFER_CXA_ATEXIT = cxa_atexit;
            DOUBLE_BUFFER_CXA_GUARD_RELEASE = cxa_guard_release;
            DOUBLE_BUFFER_STATE.ready = 0;
            DOUBLE_BUFFER_STATE.guard = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_marks_ready_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            DOUBLE_BUFFER_CTOR = modeled_constructor;
            assert_eq!(double_buffer_get(), storage());
            assert_eq!(CTOR_CALLS, 1);
            assert_eq!(DOUBLE_BUFFER_STATE.guard, 1, "acquire publishes the guard");
            assert_eq!(DOUBLE_BUFFER_STATE.ready, 1, "the byte flag is set after initialization");
            assert_eq!(storage().read(), 0x5a);
            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut u8, storage(), "constructor return is registered");
            assert_eq!((*node).handler as usize, double_buffer_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn fast_path_preserves_state_and_does_not_register_twice() {
        let lock = reset();
        unsafe {
            DOUBLE_BUFFER_CTOR = modeled_constructor;
            double_buffer_get();
            storage().add(DOUBLE_BUFFER_SIZE - 1).write(0x31);
            assert_eq!(double_buffer_get(), storage());
            assert_eq!(CTOR_CALLS, 1);
            assert_eq!(storage().add(DOUBLE_BUFFER_SIZE - 1).read(), 0x31);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn nonzero_guard_without_bit_zero_skips_construction_but_marks_ready() {
        let lock = reset();
        unsafe {
            DOUBLE_BUFFER_CTOR = modeled_constructor;
            DOUBLE_BUFFER_STATE.guard = 2;
            assert_eq!(double_buffer_get(), storage());
            assert_eq!(CTOR_CALLS, 0, "guard acquire rejects a nonzero guard");
            assert_eq!(DOUBLE_BUFFER_STATE.guard, 2);
            assert_eq!(DOUBLE_BUFFER_STATE.ready, 1);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }

    #[test]
    fn getter_returns_fixed_storage_when_constructor_returns_another_pointer() {
        let lock = reset();
        unsafe {
            DOUBLE_BUFFER_CTOR = modeled_constructor;
            CTOR_RESULT = storage().add(4);
            assert_eq!(double_buffer_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(4));
        }
        restore(lock);
    }

    #[test]
    fn object_extent_matches_the_two_slot_constructor_writes() {
        assert_eq!(DOUBLE_BUFFER_SIZE, 0x40);
    }
}
