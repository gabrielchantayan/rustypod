//! The recording-controller singleton accessor.
//!
//! Port:
//! - [`recording_controller_get`] — original: `FUN_0827d6e4` @ `0x0827d6e4`
//!   (**116 bytes: 100 bytes of code plus its 16-byte literal pool; 8 direct
//!   `bl` call sites, all unconditional and zero predicated**).
//!
//! Raw ARM ends its code at `0x0827d748`; its literals at
//! `0x0827d748..0x0827d754` name the state block (`0x089cfd34`, ready byte
//! at +0 and C++ guard at +8), fixed controller (`0x08ad17c0`),
//! `__dso_handle` (`0x089ca09c`), and registered word (`0x08272fac`). The
//! next function begins at `0x0827d758`, so Ghidra's 100-byte extent omits
//! the literal pool.
//!
//! The object drives the recording buffer: its operation at `0x0827dbb4`
//! starts buffer capture and retains format/rate fields at +0x40..+0x48;
//! recording-buffer writes call this getter before the matching sync routine.
//! No class-name literal survives in this constructor, so
//! `recording_controller` names that observed role rather than inventing a
//! C++ identity. The constructor's final store is at +0x464 and its start
//! operation writes byte +0x468, establishing the 0x46c-byte observed extent.
//!
//! ## Algorithm
//!
//! Test guard bit 0; if clear and `cxa_guard_acquire` accepts the complete
//! word, construct the fixed controller, register the constructor result with
//! `cxa_atexit`, and release the guard. Independently, if the ready byte is
//! clear, call the one-time recording setup and set that byte. Every path
//! returns the fixed object literal, never the constructor result. All eight
//! callers use plain `bl`; none conditionally skips the accessor.
//!
//! ## Deliberate deviations
//!
//! The firmware's RAM state and object are crate statics. The constructor
//! (`FUN_0827de04`) and one-time setup (`FUN_0827ddb8`) remain replaceable
//! seams: target builds reach their raw entries and host tests install models.
//! The `cxa_atexit` handler word `0x08272fac` is not a function entry: raw
//! bytes there are the ASCII URL fragment `g/00/9/xmlsig#`. The Rust shutdown
//! handler is therefore deliberately inert rather than inventing a callee.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

/// The start operation writes byte `this + 0x468` at `0x0827dcc0`.
pub const RECORDING_CONTROLLER_SIZE: usize = 0x46c;
const RECORDING_CONTROLLER_CTOR_ADDRESS: usize = 0x0827_de04;
const RECORDING_CONTROLLER_SETUP_ADDRESS: usize = 0x0827_ddb8;
const DSO_HANDLE: i32 = 0x089c_a09c;

/// Volatile bindings retain the retail registration and release call boundaries.
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

static mut RECORDING_CONTROLLER_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut RECORDING_CONTROLLER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

/// Exact subset of the state block at `0x089cfd34` used by this accessor.
#[repr(C)]
struct RecordingControllerState {
    ready: u8,
    _padding: [u8; 7],
    guard: u32,
}

static mut RECORDING_CONTROLLER_STATE: RecordingControllerState = RecordingControllerState {
    ready: 0,
    _padding: [0; 7],
    guard: 0,
};

/// Fixed recording-controller storage (original: `0x08ad17c0`).
pub static mut RECORDING_CONTROLLER: [u8; RECORDING_CONTROLLER_SIZE] = [0; RECORDING_CONTROLLER_SIZE];

/// ABI of the unported in-place constructor `FUN_0827de04`.
pub type RecordingControllerConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_recording_controller_constructor(this: *mut u8) -> *mut u8 {
    let constructor: RecordingControllerConstructor = core::mem::transmute(RECORDING_CONTROLLER_CTOR_ADDRESS);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_recording_controller_constructor(this: *mut u8) -> *mut u8 {
    for offset in 0..RECORDING_CONTROLLER_SIZE {
        this.add(offset).write_volatile(0);
    }
    this
}

/// Constructor seam for `FUN_0827de04` (`bl` at `0x0827d70c`).
pub static mut RECORDING_CONTROLLER_CTOR: RecordingControllerConstructor = {
    #[cfg(target_os = "none")]
    {
        firmware_recording_controller_constructor
    }
    #[cfg(not(target_os = "none"))]
    {
        host_recording_controller_constructor
    }
};

/// ABI of the independent one-time setup `FUN_0827ddb8`.
pub type RecordingControllerSetup = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_recording_controller_setup(this: *mut u8) {
    let setup: RecordingControllerSetup = core::mem::transmute(RECORDING_CONTROLLER_SETUP_ADDRESS);
    setup(this);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_recording_controller_setup(_this: *mut u8) {}

/// One-time setup seam for `FUN_0827ddb8` (`bl` at `0x0827d734`).
pub static mut RECORDING_CONTROLLER_SETUP: RecordingControllerSetup = {
    #[cfg(target_os = "none")]
    {
        firmware_recording_controller_setup
    }
    #[cfg(not(target_os = "none"))]
    {
        host_recording_controller_setup
    }
};

/// Safe replacement for the non-entry word `0x08272fac` registered by ADS.
unsafe extern "C" fn recording_controller_destructor(_object: *mut c_void) {}

#[inline(always)]
unsafe fn recording_controller_cxa_atexit() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORDING_CONTROLLER_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn recording_controller_cxa_guard_release() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORDING_CONTROLLER_CXA_GUARD_RELEASE))
}

#[inline(always)]
unsafe fn recording_controller_ctor() -> RecordingControllerConstructor {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORDING_CONTROLLER_CTOR))
}

#[inline(always)]
unsafe fn recording_controller_setup() -> RecordingControllerSetup {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORDING_CONTROLLER_SETUP))
}

/// recording_controller_get — original: `FUN_0827d6e4` @ `0x0827d6e4`
/// (116 bytes: 100-byte code and 16-byte literal pool; 8 direct,
/// unconditional `bl` call sites, binary-verified by decoding every ARM B/BL
/// word).
///
/// Lazily constructs and returns the fixed recording controller. A nonzero
/// guard with bit 0 clear takes the slow path but is refused by
/// `cxa_guard_acquire`; the independent ready-byte setup still runs if needed,
/// exactly as the ARM sequence does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.recording_controller_get")]
pub unsafe extern "C" fn recording_controller_get() -> *mut u8 {
    let state = core::ptr::addr_of_mut!(RECORDING_CONTROLLER_STATE);
    let guard = core::ptr::addr_of_mut!((*state).guard);
    let object = core::ptr::addr_of_mut!(RECORDING_CONTROLLER) as *mut u8;

    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = recording_controller_ctor()(object);
        recording_controller_cxa_atexit()(this.cast::<c_void>(), recording_controller_destructor, DSO_HANDLE);
        recording_controller_cxa_guard_release()(guard);
    }
    if core::ptr::read_volatile(core::ptr::addr_of!((*state).ready)) == 0 {
        recording_controller_setup()(object);
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

    static RECORDING_CONTROLLER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_CALLS: Vec<*mut u8> = Vec::new();
    static mut SETUP_CALLS: Vec<*mut u8> = Vec::new();
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_constructor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_CALLS)).push(this);
        this.write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn recording_setup(this: *mut u8) {
        (*ptr::addr_of_mut!(SETUP_CALLS)).push(this);
        this.add(0x468).write_volatile(0x3c);
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: recording_controller_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(RECORDING_CONTROLLER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = RECORDING_CONTROLLER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RECORDING_CONTROLLER_STATE.ready = 0;
            RECORDING_CONTROLLER_STATE.guard = 0;
            for offset in 0..RECORDING_CONTROLLER_SIZE {
                storage().add(offset).write(0xa5);
            }
            RECORDING_CONTROLLER_CTOR = host_recording_controller_constructor;
            RECORDING_CONTROLLER_SETUP = host_recording_controller_setup;
            CTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CTOR_CALLS)).clear();
            (*ptr::addr_of_mut!(SETUP_CALLS)).clear();
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
            RECORDING_CONTROLLER_CTOR = host_recording_controller_constructor;
            RECORDING_CONTROLLER_SETUP = host_recording_controller_setup;
            RECORDING_CONTROLLER_STATE.ready = 0;
            RECORDING_CONTROLLER_STATE.guard = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_sets_up_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            RECORDING_CONTROLLER_CTOR = recording_constructor;
            RECORDING_CONTROLLER_SETUP = recording_setup;
            assert_eq!(recording_controller_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_CALLS), std::vec![storage()]);
            assert_eq!(*ptr::addr_of!(SETUP_CALLS), std::vec![storage()]);
            assert_eq!(RECORDING_CONTROLLER_STATE.guard, 1, "acquire publishes the guard");
            assert_eq!(RECORDING_CONTROLLER_STATE.ready, 1, "setup marks its ready byte");
            assert_eq!(storage().add(0x468).read(), 0x3c);
            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut u8, storage(), "constructor return is registered");
            assert_eq!((*node).handler as usize, recording_controller_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn fast_path_preserves_controller_state_and_does_not_repeat_setup() {
        let lock = reset();
        unsafe {
            RECORDING_CONTROLLER_CTOR = recording_constructor;
            RECORDING_CONTROLLER_SETUP = recording_setup;
            recording_controller_get();
            storage().add(0x464).write(0x31);
            assert_eq!(recording_controller_get(), storage());
            assert_eq!((*ptr::addr_of!(CTOR_CALLS)).len(), 1);
            assert_eq!((*ptr::addr_of!(SETUP_CALLS)).len(), 1);
            assert_eq!(storage().add(0x464).read(), 0x31);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn nonzero_guards_skip_construction_but_still_run_ready_setup() {
        let lock = reset();
        unsafe {
            RECORDING_CONTROLLER_CTOR = recording_constructor;
            RECORDING_CONTROLLER_SETUP = recording_setup;
            RECORDING_CONTROLLER_STATE.guard = 3;
            assert_eq!(recording_controller_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert_eq!(*ptr::addr_of!(SETUP_CALLS), std::vec![storage()]);
            assert_eq!(RECORDING_CONTROLLER_STATE.ready, 1);
            assert!(shutdown_chain_head().read().is_null());

            RECORDING_CONTROLLER_STATE.guard = 2;
            RECORDING_CONTROLLER_STATE.ready = 0;
            (*ptr::addr_of_mut!(SETUP_CALLS)).clear();
            recording_controller_get();
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty(), "acquire rejects every nonzero guard");
            assert_eq!(RECORDING_CONTROLLER_STATE.guard, 2);
            assert_eq!(*ptr::addr_of!(SETUP_CALLS), std::vec![storage()]);
        }
        restore(lock);
    }

    #[test]
    fn getter_returns_literal_while_shutdown_carries_constructor_result() {
        let lock = reset();
        unsafe {
            RECORDING_CONTROLLER_CTOR = recording_constructor;
            CTOR_RESULT = storage().add(4);
            assert_eq!(recording_controller_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(4));
        }
        restore(lock);
    }

    #[test]
    fn default_constructor_zeroes_observed_extent_and_shutdown_handler_is_inert() {
        let lock = reset();
        unsafe {
            recording_controller_get();
            assert!((0..RECORDING_CONTROLLER_SIZE).all(|offset| storage().add(offset).read() == 0));
            storage().add(0x468).write(0xa5);
            lib_shutdown_chain(0);
            assert_eq!(storage().add(0x468).read(), 0xa5, "data word handler is inert");
        }
        restore(lock);
    }

    #[test]
    fn object_extent_covers_the_last_observed_byte() {
        assert_eq!(RECORDING_CONTROLLER_SIZE, 0x46c);
    }
}
