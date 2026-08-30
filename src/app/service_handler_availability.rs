//! Service-handler availability predicate.
//!
//! `service_handler_is_available` — original: `FUN_0818e624` @
//! 0x0818e624 (100 bytes: 24 instructions plus the trailing literal word @
//! 0x0818e684; the next function starts at 0x0818e688). The raw ARM body is
//! definitive; Ghidra's 96-byte extent omits that literal. A complete
//! binary scan of `osos.dec` decoding every ARM `B`/`BL` instruction finds
//! **32 direct, unconditional `bl` call sites** and no predicated calls.
//!
//! Algorithm: obtain the asserting service-manager singleton, require the
//! nonzero `+0x30` gate in the otherwise unnamed global @ 0x089ca8d0, and
//! require `selector < 3`; either failed precondition falls through to
//! `heap_panic`. It then asks the manager's `+4` handler-slot table for that
//! selector and asks the unported lifecycle predicate whether the same
//! selector's state byte is in 4..=6. It re-reads the global gate after both
//! calls, returning one only when that reloaded gate, the handler word, and
//! the lifecycle result are all nonzero.
//!
//! Deliberate deviation: the two unported direct callees
//! (`FUN_08194080` and `FUN_08138d8c`) use a volatile dispatch table for host
//! tests. Target defaults call their stock addresses, while the global gate
//! stays a direct volatile firmware load. The fatal path is not host-tested:
//! `heap_panic` does not return.

use crate::app::service_manager::service_manager_instance_veneer;
use crate::heap::veneers::heap_panic;
use core::ptr;
#[cfg(test)]
use crate::app::service_manager::SERVICE_MANAGER_INSTANCE;

const HANDLER_TABLE_OFFSET: usize = 4;
const HANDLER_SELECTOR_COUNT: u32 = 3;

/// The observed prefix of the otherwise unnamed global @ 0x089ca8d0.
///
/// Only its `+0x30` word is used here. The surrounding object has no
/// recovered identity, so the field is named for this predicate's role
/// rather than an invented class member name.
#[repr(C)]
struct ServiceHandlerAvailabilityGlobals {
    reserved_00: [u32; 12],
    handler_availability_gate: u32,
}

#[cfg(target_os = "none")]
const SERVICE_HANDLER_AVAILABILITY_GLOBALS: *const ServiceHandlerAvailabilityGlobals =
    0x089c_a8d0 as *const ServiceHandlerAvailabilityGlobals;

#[cfg(not(target_os = "none"))]
static mut HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS: ServiceHandlerAvailabilityGlobals =
    ServiceHandlerAvailabilityGlobals {
        reserved_00: [0; 12],
        handler_availability_gate: 0,
    };

#[inline(always)]
unsafe fn handler_availability_gate() -> u32 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(ptr::addr_of!((*SERVICE_HANDLER_AVAILABILITY_GLOBALS).handler_availability_gate))
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate))
    }
}

type HandlerAt = unsafe extern "C" fn(*mut u8, u32) -> u32;
type HandlerStateIsReady = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[derive(Clone, Copy)]
struct ServiceHandlerAvailabilityOps {
    handler_at: HandlerAt,
    handler_state_is_ready: HandlerStateIsReady,
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_at(table: *mut u8, selector: u32) -> u32 {
    let handler_at: HandlerAt = core::mem::transmute(0x0819_4080usize);
    handler_at(table, selector)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_state_is_ready(manager: *mut u8, selector: u32) -> u32 {
    let handler_state_is_ready: HandlerStateIsReady = core::mem::transmute(0x0813_8d8cusize);
    handler_state_is_ready(manager, selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_handler_at(_table: *mut u8, _selector: u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_handler_state_is_ready(_manager: *mut u8, _selector: u32) -> u32 {
    0
}

#[cfg(target_os = "none")]
static mut SERVICE_HANDLER_AVAILABILITY_OPS: ServiceHandlerAvailabilityOps =
    ServiceHandlerAvailabilityOps {
        handler_at: firmware_handler_at,
        handler_state_is_ready: firmware_handler_state_is_ready,
    };

#[cfg(not(target_os = "none"))]
static mut SERVICE_HANDLER_AVAILABILITY_OPS: ServiceHandlerAvailabilityOps =
    ServiceHandlerAvailabilityOps {
        handler_at: unavailable_handler_at,
        handler_state_is_ready: unavailable_handler_state_is_ready,
    };

#[inline(always)]
unsafe fn availability_ops() -> ServiceHandlerAvailabilityOps {
    ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_AVAILABILITY_OPS))
}

/// service_handler_is_available — original: `FUN_0818e624` @ 0x0818e624
/// (100 bytes including literal; 32 direct unconditional `bl` call sites).
///
/// Returns whether the selected service-manager handler is present and its
/// lifecycle state is ready. The gate at 0x089ca900 and selector range are
/// asserting preconditions; each failed condition calls [`heap_panic`]. The
/// gate is deliberately loaded again after the two callee calls, exactly as
/// the original's final `ldr r1,[r6,#0x30]` does.
///
/// # Safety
///
/// The service-manager singleton and its handler table must be initialized.
/// `selector` must be less than three; invalid selectors and a zero global
/// gate are fatal in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_is_available(selector: u32) -> u32 {
    let ops = availability_ops();
    let manager = service_manager_instance_veneer();

    if handler_availability_gate() == 0 || selector >= HANDLER_SELECTOR_COUNT {
        heap_panic();
    }

    let handler = (ops.handler_at)(manager.add(HANDLER_TABLE_OFFSET), selector);
    let state_is_ready = (ops.handler_state_is_ready)(manager, selector);

    (handler_availability_gate() != 0 && handler != 0 && state_is_ready != 0) as u32
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut MOCK_MANAGER: *mut u8 = ptr::null_mut();
    static mut MOCK_SELECTOR: u32 = 0;
    static mut MOCK_HANDLER: u32 = 0;
    static mut MOCK_STATE_READY: u32 = 0;
    static mut GATE_AFTER_HANDLER: u32 = 1;
    static mut CALLS: [u8; 2] = [0; 2];
    static mut CALL_COUNT: usize = 0;

    unsafe fn record_call(call: u8) {
        CALLS[CALL_COUNT] = call;
        CALL_COUNT += 1;
    }


    unsafe extern "C" fn mock_handler_at(table: *mut u8, selector: u32) -> u32 {
        assert_eq!(table, MOCK_MANAGER.add(HANDLER_TABLE_OFFSET));
        assert_eq!(selector, MOCK_SELECTOR);
        record_call(1);
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(GATE_AFTER_HANDLER);
        MOCK_HANDLER
    }

    unsafe extern "C" fn mock_handler_state_is_ready(manager: *mut u8, selector: u32) -> u32 {
        assert_eq!(manager, MOCK_MANAGER);
        assert_eq!(selector, MOCK_SELECTOR);
        record_call(2);
        MOCK_STATE_READY
    }

    unsafe fn install(
        manager: *mut u8,
        selector: u32,
        handler: u32,
        state_ready: u32,
        gate_after_handler: u32,
    ) -> ServiceHandlerAvailabilityOps {
        let previous = ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_AVAILABILITY_OPS));
        SERVICE_HANDLER_AVAILABILITY_OPS = ServiceHandlerAvailabilityOps {
            handler_at: mock_handler_at,
            handler_state_is_ready: mock_handler_state_is_ready,
        };
        MOCK_MANAGER = manager;
        MOCK_SELECTOR = selector;
        MOCK_HANDLER = handler;
        MOCK_STATE_READY = state_ready;
        GATE_AFTER_HANDLER = gate_after_handler;
        ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), manager);
        CALLS = [0; 2];
        CALL_COUNT = 0;
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(1);
        previous
    }

    unsafe fn restore(previous: ServiceHandlerAvailabilityOps) {
        SERVICE_HANDLER_AVAILABILITY_OPS = previous;
        MOCK_MANAGER = ptr::null_mut();
        ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut());
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(0);
    }

    #[test]
    fn accepts_both_edge_selectors_when_handler_and_state_are_nonzero() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];

        for selector in [0, HANDLER_SELECTOR_COUNT - 1] {
            let previous = unsafe { install(manager.as_mut_ptr().cast(), selector, 0x1000, 0x80, 1) };
            assert_eq!(unsafe { service_handler_is_available(selector) }, 1);
            unsafe {
                assert_eq!(CALL_COUNT, 2);
                assert_eq!(&CALLS[..CALL_COUNT], &[1, 2]);
                restore(previous);
            }
        }
    }

    #[test]
    fn calls_both_predicates_when_the_handler_is_absent() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];
        let previous = unsafe { install(manager.as_mut_ptr().cast(), 1, 0, 1, 1) };

        assert_eq!(unsafe { service_handler_is_available(1) }, 0);
        unsafe {
            assert_eq!(CALL_COUNT, 2, "both calls occur before the final AND");
            assert_eq!(&CALLS[..CALL_COUNT], &[1, 2]);
            restore(previous);
        }
    }

    #[test]
    fn reloads_the_global_gate_after_the_callees() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];
        let previous = unsafe { install(manager.as_mut_ptr().cast(), 1, 0x1000, 1, 0) };

        assert_eq!(unsafe { service_handler_is_available(1) }, 0);
        unsafe {
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(&CALLS[..CALL_COUNT], &[1, 2]);
            restore(previous);
        }
    }
}
