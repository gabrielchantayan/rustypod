//! The recording-buffer singleton accessor.
//!
//! Port:
//! - [`recording_buffer_get`] — original: `FUN_08167b54` @ `0x08167b54`
//!   (**116 bytes: 100 bytes of code plus its 16-byte literal pool; 9 direct
//!   `bl` call sites, all unconditional and zero predicated**).
//!
//! Raw ARM ends its code at `0x08167bb8`; the four pool words at
//! `0x08167bb8..0x08167bc8` name the private state (`0x089cfd44`: ready byte
//! and guard word at +4), fixed object (`0x08ad1c30`), `__dso_handle`
//! (`0x089ca09c`), and shutdown-handler word (`0x0815d38c`). The next function
//! begins at `0x08167bc8`, so the true extent is 116 bytes rather than
//! Ghidra's 100-byte code-only extent.
//!
//! The constructor's `MeCCA_RecordingBuffer` literal at `0x08168234` identifies
//! the fixed object as a recording buffer. Its final word store is at +0x33c,
//! establishing the 0x340-byte observed extent.
//!
//! ## Algorithm
//!
//! This is the ADS function-local-static sequence: test guard bit 0, acquire
//! the guard if clear, construct the fixed object, register the constructor's
//! return with `cxa_atexit`, release the guard, then invoke the independent
//! recording-buffer follow-up initializer if the adjacent ready byte is clear.
//! It always reloads and returns the fixed object literal, never the
//! constructor's return. All nine direct callers use plain `bl`; none are
//! predicated.
//!
//! ## Deliberate deviations
//!
//! The firmware RAM state and fixed object are crate statics. The constructor
//! (`FUN_081681a4`) and follow-up initializer (`FUN_08167e58`) remain unported
//! seams: device builds call their verified raw entries, while host tests
//! install models. The pool handler word `0x0815d38c` is a `bl` instruction in
//! the middle of a larger function, not a callable entry, so the Rust shutdown
//! handler is deliberately a no-op.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

/// The final word store in `FUN_081681a4` is at `this + 0x33c`.
pub const RECORDING_BUFFER_SIZE: usize = 0x340;
const RECORDING_BUFFER_CTOR_ADDRESS: usize = 0x0816_81a4;
const RECORDING_BUFFER_INITIALIZE_ADDRESS: usize = 0x0816_7e58;
const DSO_HANDLE: i32 = 0x089c_a09c;

/// Volatile bindings retain the ADS registration and release call boundaries.
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

static mut RECORDING_BUFFER_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut RECORDING_BUFFER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

/// Exact state layout at `0x089cfd44`: ready byte followed by the ADS guard.
#[repr(C)]
struct RecordingBufferState {
    ready: u8,
    _padding: [u8; 3],
    guard: u32,
}

static mut RECORDING_BUFFER_STATE: RecordingBufferState = RecordingBufferState {
    ready: 0,
    _padding: [0; 3],
    guard: 0,
};

/// Fixed recording-buffer storage (original: `0x08ad1c30`).
pub static mut RECORDING_BUFFER: [u8; RECORDING_BUFFER_SIZE] = [0; RECORDING_BUFFER_SIZE];

/// ABI of the unported in-place ADS constructor `FUN_081681a4`.
pub type RecordingBufferConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_recording_buffer_constructor(this: *mut u8) -> *mut u8 {
    let constructor: RecordingBufferConstructor = core::mem::transmute(RECORDING_BUFFER_CTOR_ADDRESS);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_recording_buffer_constructor(this: *mut u8) -> *mut u8 {
    this
}

/// Constructor seam for `FUN_081681a4` (`bl` at `0x08167b7c`).
pub static mut RECORDING_BUFFER_CTOR: RecordingBufferConstructor = {
    #[cfg(target_os = "none")]
    {
        firmware_recording_buffer_constructor
    }
    #[cfg(not(target_os = "none"))]
    {
        host_recording_buffer_constructor
    }
};

/// ABI of the independent, unported follow-up initializer `FUN_08167e58`.
pub type RecordingBufferInitialize = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_recording_buffer_initialize(this: *mut u8) {
    let initialize: RecordingBufferInitialize = core::mem::transmute(RECORDING_BUFFER_INITIALIZE_ADDRESS);
    initialize(this);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_recording_buffer_initialize(_this: *mut u8) {}

/// Follow-up initializer seam for `FUN_08167e58` (`bl` at `0x08167ba4`).
pub static mut RECORDING_BUFFER_INITIALIZE: RecordingBufferInitialize = {
    #[cfg(target_os = "none")]
    {
        firmware_recording_buffer_initialize
    }
    #[cfg(not(target_os = "none"))]
    {
        host_recording_buffer_initialize
    }
};

/// Deliberately inert replacement for the invalid pool handler at `0x0815d38c`.
unsafe extern "C" fn recording_buffer_destructor(_object: *mut c_void) {}

#[inline(always)]
unsafe fn recording_buffer_ctor() -> RecordingBufferConstructor {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORDING_BUFFER_CTOR))
}

#[inline(always)]
unsafe fn recording_buffer_initialize() -> RecordingBufferInitialize {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORDING_BUFFER_INITIALIZE))
}

#[inline(always)]
unsafe fn recording_buffer_cxa_atexit() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORDING_BUFFER_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn recording_buffer_cxa_guard_release() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORDING_BUFFER_CXA_GUARD_RELEASE))
}

/// recording_buffer_get — original: `FUN_08167b54` @ `0x08167b54` (116 bytes:
/// 100 bytes of code plus 16-byte literal pool; 9 direct, unconditional `bl`
/// call sites, binary-verified by decoding every ARM B/BL word).
///
/// Lazily constructs and returns the fixed recording buffer. A nonzero guard
/// with bit 0 clear takes the slow path but is refused by `cxa_guard_acquire`.
/// The ready-byte initializer still runs on that path when its byte is clear,
/// matching the ARM sequence.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.recording_buffer_get")]
pub unsafe extern "C" fn recording_buffer_get() -> *mut u8 {
    let state = core::ptr::addr_of_mut!(RECORDING_BUFFER_STATE);
    let guard = core::ptr::addr_of_mut!((*state).guard);
    let object = core::ptr::addr_of_mut!(RECORDING_BUFFER) as *mut u8;

    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = recording_buffer_ctor()(object);
        recording_buffer_cxa_atexit()(this.cast::<c_void>(), recording_buffer_destructor, DSO_HANDLE);
        recording_buffer_cxa_guard_release()(guard);
    }
    if core::ptr::read_volatile(core::ptr::addr_of!((*state).ready)) == 0 {
        recording_buffer_initialize()(object);
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
    use std::vec::Vec;

    static RECORDING_BUFFER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_CALLS: Vec<*mut u8> = Vec::new();
    static mut INITIALIZE_CALLS: Vec<*mut u8> = Vec::new();
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_buffer_constructor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_CALLS)).push(this);
        this.write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn recording_buffer_initializer(this: *mut u8) {
        (*ptr::addr_of_mut!(INITIALIZE_CALLS)).push(this);
        this.add(0x33f).write_volatile(0x3c);
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: recording_buffer_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(RECORDING_BUFFER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = RECORDING_BUFFER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RECORDING_BUFFER_STATE.ready = 0;
            RECORDING_BUFFER_STATE.guard = 0;
            for offset in 0..RECORDING_BUFFER_SIZE {
                storage().add(offset).write(0xa5);
            }
            RECORDING_BUFFER_CTOR = host_recording_buffer_constructor;
            RECORDING_BUFFER_INITIALIZE = host_recording_buffer_initialize;
            CTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CTOR_CALLS)).clear();
            (*ptr::addr_of_mut!(INITIALIZE_CALLS)).clear();
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
            RECORDING_BUFFER_CTOR = host_recording_buffer_constructor;
            RECORDING_BUFFER_INITIALIZE = host_recording_buffer_initialize;
            RECORDING_BUFFER_STATE.ready = 0;
            RECORDING_BUFFER_STATE.guard = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_initializes_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            RECORDING_BUFFER_CTOR = recording_buffer_constructor;
            RECORDING_BUFFER_INITIALIZE = recording_buffer_initializer;
            assert_eq!(recording_buffer_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_CALLS), std::vec![storage()]);
            assert_eq!(*ptr::addr_of!(INITIALIZE_CALLS), std::vec![storage()]);
            assert_eq!(RECORDING_BUFFER_STATE.guard, 1, "acquire publishes the guard");
            assert_eq!(RECORDING_BUFFER_STATE.ready, 1, "ready is set after initialization");
            assert_eq!(storage().add(0x33f).read(), 0x3c);
            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut u8, storage(), "constructor return is registered");
            assert_eq!((*node).handler as usize, recording_buffer_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn ready_fast_path_preserves_state_and_skips_both_unported_calls() {
        let lock = reset();
        unsafe {
            RECORDING_BUFFER_STATE.ready = 1;
            RECORDING_BUFFER_STATE.guard = 1;
            RECORDING_BUFFER_CTOR = recording_buffer_constructor;
            RECORDING_BUFFER_INITIALIZE = recording_buffer_initializer;
            storage().add(0x33f).write(0x91);
            assert_eq!(recording_buffer_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert!((*ptr::addr_of!(INITIALIZE_CALLS)).is_empty());
            assert_eq!(storage().add(0x33f).read(), 0x91);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }

    #[test]
    fn bit0_clear_nonzero_guard_skips_constructor_but_runs_ready_initializer() {
        let lock = reset();
        unsafe {
            RECORDING_BUFFER_STATE.guard = 2;
            RECORDING_BUFFER_CTOR = recording_buffer_constructor;
            RECORDING_BUFFER_INITIALIZE = recording_buffer_initializer;
            assert_eq!(recording_buffer_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty(), "acquire rejects nonzero guard");
            assert_eq!(*ptr::addr_of!(INITIALIZE_CALLS), std::vec![storage()]);
            assert_eq!(RECORDING_BUFFER_STATE.guard, 2);
            assert_eq!(RECORDING_BUFFER_STATE.ready, 1);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }

    #[test]
    fn getter_returns_fixed_storage_while_shutdown_carries_constructor_result() {
        let lock = reset();
        unsafe {
            RECORDING_BUFFER_CTOR = recording_buffer_constructor;
            CTOR_RESULT = storage().add(4);
            assert_eq!(recording_buffer_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(4));
        }
        restore(lock);
    }

    #[test]
    fn observed_extent_covers_constructor_final_word() {
        assert_eq!(RECORDING_BUFFER_SIZE, 0x340);
    }
}
