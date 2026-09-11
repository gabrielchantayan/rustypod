//! Lazy initialization of the event-handler source object.
//!
//! Port: [`event_handler_source`] — original: `FUN_08007470` @ `0x08007470`
//! (**100 bytes of code; 10 direct `bl` call sites, all unconditional and
//! zero predicated forms, binary-verified by decoding every ARM B/BL word in
//! `osos.dec`**).
//!
//! Raw ARM returns at `0x080074d0`; its five literal words occupy
//! `0x080074d4..0x080074e4`. The independently linked leaf beginning at
//! `0x080074e8` confirms the literal pool belongs to this function.
//!
//! ## Algorithm
//!
//! Test bit 0 of the C++ guard at `0x22008c84`. If clear and
//! `cxa_guard_acquire` accepts the complete word, register the fixed source
//! object at `0x22010318` with its literal destructor and release the guard.
//! Independently, if byte `0x2200aed4` is clear, call `FUN_08007e38` with that
//! source object and set the byte. Every path returns the fixed source address.
//!
//! ## Deliberate deviations
//!
//! `FUN_08007e38` has one caller (this function) but is not independently
//! ported or identified, so target builds cross a direct retailOS seam and host
//! builds use an inert replaceable callback. The object class is likewise
//! unrecovered; host storage represents only its address because this port does
//! not dereference it. The destructor literal `0x2200803c` is passed unchanged
//! on target and is inert on host.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const EVENT_HANDLER_SOURCE_ADDRESS: usize = 0x2201_0318;
const EVENT_HANDLER_SOURCE_GUARD_ADDRESS: usize = 0x2200_8c84;
const EVENT_HANDLER_SOURCE_READY_ADDRESS: usize = 0x2200_aed4;
const EVENT_HANDLER_SOURCE_DESTRUCTOR_ADDRESS: usize = 0x2200_803c;
const DSO_HANDLE: i32 = 0x089c_a09c;

/// The still-unidentified one-time source setup at `FUN_08007e38`.
pub type EventHandlerSourceSetup = unsafe extern "C" fn(source: *mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_event_handler_source_setup(source: *mut u8) {
    let setup: EventHandlerSourceSetup = core::mem::transmute(0x0800_7e38usize);
    setup(source)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_event_handler_source_setup(_source: *mut u8) {}

static mut EVENT_HANDLER_SOURCE_SETUP: EventHandlerSourceSetup = {
    #[cfg(target_os = "none")]
    {
        firmware_event_handler_source_setup
    }
    #[cfg(not(target_os = "none"))]
    {
        host_event_handler_source_setup
    }
};

#[cfg(target_os = "none")]
fn event_handler_source_destructor() -> ShutdownHandlerFn {
    unsafe { core::mem::transmute(EVENT_HANDLER_SOURCE_DESTRUCTOR_ADDRESS) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_event_handler_source_destructor(_object: *mut c_void) {}

#[cfg(not(target_os = "none"))]
fn event_handler_source_destructor() -> ShutdownHandlerFn {
    host_event_handler_source_destructor
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostEventHandlerSourceState {
    guard: u32,
    ready: u8,
    source: u8,
}

#[cfg(not(target_os = "none"))]
static mut HOST_EVENT_HANDLER_SOURCE_STATE: HostEventHandlerSourceState = HostEventHandlerSourceState {
    guard: 0,
    ready: 0,
    source: 0,
};

unsafe fn event_handler_source_state() -> (*mut u32, *mut u8, *mut u8) {
    #[cfg(target_os = "none")]
    {
        (
            EVENT_HANDLER_SOURCE_GUARD_ADDRESS as *mut u32,
            EVENT_HANDLER_SOURCE_ADDRESS as *mut u8,
            EVENT_HANDLER_SOURCE_READY_ADDRESS as *mut u8,
        )
    }

    #[cfg(not(target_os = "none"))]
    {
        let state = core::ptr::addr_of_mut!(HOST_EVENT_HANDLER_SOURCE_STATE);
        (
            core::ptr::addr_of_mut!((*state).guard),
            core::ptr::addr_of_mut!((*state).source),
            core::ptr::addr_of_mut!((*state).ready),
        )
    }
}

#[inline(always)]
fn event_handler_source_setup() -> EventHandlerSourceSetup {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_HANDLER_SOURCE_SETUP)) }
}

/// event_handler_source — original: `FUN_08007470` @ `0x08007470` (100 bytes;
/// 10 direct, unconditional `bl` call sites and no predicated forms,
/// binary-verified by decoding every ARM B/BL word in `osos.dec`).
///
/// Registers the fixed source object once under its C++ guard, then independently
/// executes its still-unidentified one-time setup and returns the fixed pointer.
/// A nonzero guard with bit 0 clear reaches `cxa_guard_acquire`, which refuses it;
/// the ready byte remains independently eligible.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.event_handler_source")]
#[inline(never)]
pub unsafe extern "C" fn event_handler_source() -> *mut u8 {
    let (guard, source, ready) = event_handler_source_state();
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        cxa_atexit(source.cast::<c_void>(), event_handler_source_destructor(), DSO_HANDLE);
        cxa_guard_release(guard);
    }
    if core::ptr::read_volatile(ready) == 0 {
        event_handler_source_setup()(source);
        core::ptr::write_volatile(ready, 1);
    }
    source
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::thunks::iram_event_handler_source_veneer;
    use crate::runtime::shutdown_chain::{shutdown_chain_head, AllocFn, FreeFn, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE};
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    #[derive(Clone, Copy)]
    struct Mock {
        setup_calls: usize,
        setup_argument: usize,
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static MOCK: Mutex<Mock> = Mutex::new(Mock { setup_calls: 0, setup_argument: 0 });

    unsafe extern "C" fn recording_setup(source: *mut u8) {
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        mock.setup_calls += 1;
        mock.setup_argument = source as usize;
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: host_event_handler_source_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    struct Fixture {
        _lock: MutexGuard<'static, ()>,
        previous_setup: EventHandlerSourceSetup,
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
                EVENT_HANDLER_SOURCE_SETUP = self.previous_setup;
                SHUTDOWN_ALLOC = self.previous_alloc;
                SHUTDOWN_FREE = self.previous_free;
            }
        }
    }

    fn fixture(guard: u32, ready: u8) -> Fixture {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous_setup = EVENT_HANDLER_SOURCE_SETUP;
            let previous_alloc = SHUTDOWN_ALLOC;
            let previous_free = SHUTDOWN_FREE;
            let (guard_cell, _, ready_cell) = event_handler_source_state();
            guard_cell.write(guard);
            ready_cell.write(ready);
            *MOCK.lock().unwrap_or_else(|error| error.into_inner()) = Mock { setup_calls: 0, setup_argument: 0 };
            shutdown_chain_head().write(ptr::null_mut());
            EVENT_HANDLER_SOURCE_SETUP = recording_setup;
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            Fixture { _lock: lock, previous_setup, previous_alloc, previous_free }
        }
    }

    fn source() -> *mut u8 {
        unsafe { event_handler_source_state().1 }
    }

    #[test]
    fn cold_start_registers_sets_up_and_returns_fixed_source() {
        let _fixture = fixture(0, 0);

        assert_eq!(unsafe { event_handler_source() }, source());

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.setup_calls, 1);
        assert_eq!(mock.setup_argument, source() as usize);
        drop(mock);
        unsafe {
            let (guard, _, ready) = event_handler_source_state();
            assert_eq!(guard.read(), 1, "cxa guard publishes before returning");
            assert_eq!(ready.read(), 1, "setup records its separate once flag");
            let node = shutdown_chain_head().read();
            assert!(!node.is_null(), "source object is registered for shutdown");
            assert_eq!((*node).arg, source().cast::<c_void>());
            assert_eq!((*node).handler as usize, event_handler_source_destructor() as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
    }

    #[test]
    fn iram_veneer_forwards_to_ported_source_initializer() {
        let _fixture = fixture(0, 0);

        assert_eq!(unsafe { iram_event_handler_source_veneer() }, source());
        assert_eq!(MOCK.lock().unwrap_or_else(|error| error.into_inner()).setup_calls, 1);
    }

    #[test]
    fn bit_clear_nonzero_guard_refuses_registration_but_still_sets_up() {
        let _fixture = fixture(2, 0);

        assert_eq!(unsafe { event_handler_source() }, source());

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.setup_calls, 1, "setup has an independent flag");
        unsafe {
            let (guard, _, ready) = event_handler_source_state();
            assert_eq!(guard.read(), 2, "cxa acquire preserves a refused guard");
            assert_eq!(ready.read(), 1);
            assert!(shutdown_chain_head().read().is_null(), "refused registration creates no node");
        }
    }

    #[test]
    fn initialized_source_has_no_repeat_side_effects() {
        let _fixture = fixture(1, 1);

        assert_eq!(unsafe { event_handler_source() }, source());
        assert_eq!(unsafe { event_handler_source() }, source());
        assert_eq!(MOCK.lock().unwrap_or_else(|error| error.into_inner()).setup_calls, 0);
        unsafe { assert!(shutdown_chain_head().read().is_null()) };
    }
}
