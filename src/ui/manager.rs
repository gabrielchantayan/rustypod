//! Lazy initialization of the shared UI manager.
//!
//! Port: [`ui_manager_instance`] — original: `FUN_08005018` @ `0x08005018`
//! (**100 bytes of code; 9 direct `bl` call sites, all unconditional and zero
//! predicated forms, binary-verified by decoding every ARM B/BL word in
//! `osos.dec`**).
//!
//! Raw ARM returns at `0x08005078`; its four literal words occupy
//! `0x0800507c..0x08005088`. The independent veneer at `0x0800508c` confirms
//! the 16-byte pool belongs to this function, for a true 116-byte extent.
//!
//! ## Algorithm
//!
//! Test bit 0 of the C++ guard at `0x22008c9c`. If clear and
//! `cxa_guard_acquire` accepts the complete word, construct the fixed manager
//! at `0x220104e8`, register the constructor result with its literal destructor,
//! and release the guard. Independently, if byte `0x22008c95` is clear, run the
//! manager's one-time initialization and set that byte. Every path returns the
//! fixed manager address, never the constructor result.
//!
//! ## Deliberate deviations
//!
//! The constructor at `0x08005cb8` and one-time initializer at `0x08005448`
//! are not independently ported. Target builds cross direct retailOS seams;
//! host builds provide inert replaceable callbacks. The manager class and its
//! size remain unrecovered, so host storage represents only the pointer this
//! accessor passes to those callbacks. The literal destructor `0x22005cf4` is
//! passed unchanged on target and is inert on host.

use core::ffi::c_void;
use core::ptr;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const UI_MANAGER_ADDRESS: usize = 0x2201_04e8;
const UI_MANAGER_STATE_ADDRESS: usize = 0x2200_8c94;
const UI_MANAGER_DESTRUCTOR_ADDRESS: usize = 0x2200_5cf4;
const DSO_HANDLE: i32 = 0x089c_a09c;

/// ABI of the unported in-place constructor at `0x08005cb8`.
pub type UiManagerConstruct = unsafe extern "C" fn(manager: *mut u8) -> *mut u8;
/// ABI of the unported one-time initializer at `0x08005448`.
pub type UiManagerInitialize = unsafe extern "C" fn(manager: *mut u8);

/// Volatile bindings retain the retail `bl` boundaries for already-ported
/// shutdown registration and guard release.
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_ui_manager_construct(manager: *mut u8) -> *mut u8 {
    let construct: UiManagerConstruct = core::mem::transmute(0x0800_5cb8usize);
    construct(manager)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_ui_manager_construct(manager: *mut u8) -> *mut u8 {
    manager
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_ui_manager_initialize(manager: *mut u8) {
    let initialize: UiManagerInitialize = core::mem::transmute(0x0800_5448usize);
    initialize(manager)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_ui_manager_initialize(_manager: *mut u8) {}

static mut UI_MANAGER_CONSTRUCT: UiManagerConstruct = {
    #[cfg(target_os = "none")]
    {
        firmware_ui_manager_construct
    }
    #[cfg(not(target_os = "none"))]
    {
        host_ui_manager_construct
    }
};

static mut UI_MANAGER_INITIALIZE: UiManagerInitialize = {
    #[cfg(target_os = "none")]
    {
        firmware_ui_manager_initialize
    }
    #[cfg(not(target_os = "none"))]
    {
        host_ui_manager_initialize
    }
};

static mut UI_MANAGER_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut UI_MANAGER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[cfg(target_os = "none")]
fn ui_manager_destructor() -> ShutdownHandlerFn {
    unsafe { core::mem::transmute(UI_MANAGER_DESTRUCTOR_ADDRESS) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_ui_manager_destructor(_manager: *mut c_void) {}

#[cfg(not(target_os = "none"))]
fn ui_manager_destructor() -> ShutdownHandlerFn {
    host_ui_manager_destructor
}

/// The fixed state block at `0x22008c94`: flag byte +1 and guard word +8.
#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostUiManagerState {
    _unused: u8,
    initialized: u8,
    _padding: [u8; 6],
    guard: u32,
    manager: u8,
}

#[cfg(not(target_os = "none"))]
static mut HOST_UI_MANAGER_STATE: HostUiManagerState = HostUiManagerState {
    _unused: 0,
    initialized: 0,
    _padding: [0; 6],
    guard: 0,
    manager: 0,
};

unsafe fn ui_manager_state() -> (*mut u32, *mut u8, *mut u8) {
    #[cfg(target_os = "none")]
    {
        (
            (UI_MANAGER_STATE_ADDRESS + 8) as *mut u32,
            UI_MANAGER_ADDRESS as *mut u8,
            (UI_MANAGER_STATE_ADDRESS + 1) as *mut u8,
        )
    }

    #[cfg(not(target_os = "none"))]
    {
        let state = ptr::addr_of_mut!(HOST_UI_MANAGER_STATE);
        (
            ptr::addr_of_mut!((*state).guard),
            ptr::addr_of_mut!((*state).manager),
            ptr::addr_of_mut!((*state).initialized),
        )
    }
}

#[inline(always)]
fn ui_manager_construct() -> UiManagerConstruct {
    unsafe { ptr::read_volatile(ptr::addr_of!(UI_MANAGER_CONSTRUCT)) }
}

#[inline(always)]
fn ui_manager_initialize() -> UiManagerInitialize {
    unsafe { ptr::read_volatile(ptr::addr_of!(UI_MANAGER_INITIALIZE)) }
}

#[inline(always)]
fn ui_manager_cxa_atexit() -> CxaAtexit {
    unsafe { ptr::read_volatile(ptr::addr_of!(UI_MANAGER_CXA_ATEXIT)) }
}

#[inline(always)]
fn ui_manager_cxa_guard_release() -> CxaGuardRelease {
    unsafe { ptr::read_volatile(ptr::addr_of!(UI_MANAGER_CXA_GUARD_RELEASE)) }
}

/// ui_manager_instance — original: `FUN_08005018` @ `0x08005018` (100 bytes;
/// 9 direct, unconditional `bl` call sites and no predicated forms,
/// binary-verified by decoding every ARM B/BL word in `osos.dec`).
///
/// Lazily constructs and initializes the shared UI manager, returning its fixed
/// address. A nonzero guard with bit 0 clear reaches `cxa_guard_acquire`, which
/// refuses it; the independent initialized byte remains eligible.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_manager_instance")]
#[inline(never)]
pub unsafe extern "C" fn ui_manager_instance() -> *mut u8 {
    let (guard, manager, initialized) = ui_manager_state();
    if (ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = ui_manager_construct()(manager);
        ui_manager_cxa_atexit()(this.cast::<c_void>(), ui_manager_destructor(), DSO_HANDLE);
        ui_manager_cxa_guard_release()(guard);
    }
    if ptr::read_volatile(initialized) == 0 {
        ui_manager_initialize()(manager);
        ptr::write_volatile(initialized, 1);
    }
    manager
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{shutdown_chain_head, AllocFn, FreeFn, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE};
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    #[derive(Clone, Copy)]
    struct Mock {
        construct_calls: usize,
        construct_argument: usize,
        initialize_calls: usize,
        initialize_argument: usize,
        constructor_result: usize,
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static MOCK: Mutex<Mock> = Mutex::new(Mock {
        construct_calls: 0,
        construct_argument: 0,
        initialize_calls: 0,
        initialize_argument: 0,
        constructor_result: 0,
    });
    static mut CONSTRUCTOR_RESULT: u8 = 0;

    unsafe extern "C" fn recording_construct(manager: *mut u8) -> *mut u8 {
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        mock.construct_calls += 1;
        mock.construct_argument = manager as usize;
        mock.constructor_result as *mut u8
    }

    unsafe extern "C" fn recording_initialize(manager: *mut u8) {
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        mock.initialize_calls += 1;
        mock.initialize_argument = manager as usize;
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: host_ui_manager_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    struct Fixture {
        _lock: MutexGuard<'static, ()>,
        previous_construct: UiManagerConstruct,
        previous_initialize: UiManagerInitialize,
        previous_alloc: AllocFn,
        previous_free: FreeFn,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                let head = shutdown_chain_head();
                let mut node = head.read();
                while !node.is_null() {
                    let next = (*node).next;
                    drop(Box::from_raw(node));
                    node = next;
                }
                head.write(ptr::null_mut());
                UI_MANAGER_CONSTRUCT = self.previous_construct;
                UI_MANAGER_INITIALIZE = self.previous_initialize;
                SHUTDOWN_ALLOC = self.previous_alloc;
                SHUTDOWN_FREE = self.previous_free;
            }
        }
    }

    fn fixture(guard: u32, initialized: u8) -> Fixture {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous_construct = UI_MANAGER_CONSTRUCT;
            let previous_initialize = UI_MANAGER_INITIALIZE;
            let previous_alloc = SHUTDOWN_ALLOC;
            let previous_free = SHUTDOWN_FREE;
            let (guard_cell, _, initialized_cell) = ui_manager_state();
            guard_cell.write(guard);
            initialized_cell.write(initialized);
            CONSTRUCTOR_RESULT = 0;
            *MOCK.lock().unwrap_or_else(|error| error.into_inner()) = Mock {
                construct_calls: 0,
                construct_argument: 0,
                initialize_calls: 0,
                initialize_argument: 0,
                constructor_result: ptr::addr_of_mut!(CONSTRUCTOR_RESULT) as usize,
            };
            shutdown_chain_head().write(ptr::null_mut());
            UI_MANAGER_CONSTRUCT = recording_construct;
            UI_MANAGER_INITIALIZE = recording_initialize;
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            Fixture { _lock: lock, previous_construct, previous_initialize, previous_alloc, previous_free }
        }
    }

    fn manager() -> *mut u8 {
        unsafe { ui_manager_state().1 }
    }

    #[test]
    fn cold_start_constructs_registers_initializes_and_returns_manager() {
        let _fixture = fixture(0, 0);

        assert_eq!(unsafe { ui_manager_instance() }, manager());

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.construct_calls, 1);
        assert_eq!(mock.construct_argument, manager() as usize);
        assert_eq!(mock.initialize_calls, 1);
        assert_eq!(mock.initialize_argument, manager() as usize);
        let constructor_result = mock.constructor_result as *mut u8;
        drop(mock);
        unsafe {
            let (guard, _, initialized) = ui_manager_state();
            assert_eq!(guard.read(), 1, "cxa guard publishes before returning");
            assert_eq!(initialized.read(), 1, "initializer records its separate once flag");
            let node = shutdown_chain_head().read();
            assert!(!node.is_null(), "manager is registered for shutdown");
            assert_eq!((*node).arg, constructor_result.cast::<c_void>(), "registration receives constructor return");
            assert_eq!((*node).handler as usize, ui_manager_destructor() as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
    }

    #[test]
    fn bit_clear_nonzero_guard_refuses_registration_but_still_initializes() {
        let _fixture = fixture(2, 0);

        assert_eq!(unsafe { ui_manager_instance() }, manager());

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.construct_calls, 0, "cxa guard rejects the nonzero guard");
        assert_eq!(mock.initialize_calls, 1, "initialized byte is independent");
        unsafe {
            let (guard, _, initialized) = ui_manager_state();
            assert_eq!(guard.read(), 2, "refused guard remains unchanged");
            assert_eq!(initialized.read(), 1);
            assert!(shutdown_chain_head().read().is_null(), "refused registration creates no node");
        }
    }

    #[test]
    fn initialized_manager_has_no_repeat_side_effects() {
        let _fixture = fixture(1, 1);

        assert_eq!(unsafe { ui_manager_instance() }, manager());
        assert_eq!(unsafe { ui_manager_instance() }, manager());

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.construct_calls, 0);
        assert_eq!(mock.initialize_calls, 0);
        unsafe { assert!(shutdown_chain_head().read().is_null()) };
    }
}
