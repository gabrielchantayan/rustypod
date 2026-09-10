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
//! require `selector < 3`; either failed precondition calls `heap_panic`. It
//! then asks [`service_handler_at`] for the selected handler word and the
//! lifecycle predicate whether that selector's state byte is in
//! 4..=6. It re-reads the global gate after both calls, returning one only
//! when that reloaded gate, the handler word, and the lifecycle result are
//! all nonzero.
//!
//! The lifecycle predicate is ported below. Its firmware table has a host
//! fixture only because 0x08ad0f34 is a runtime-initialized RAM address;
//! firmware reads that table directly.
#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) static SERVICE_HANDLER_AVAILABILITY_OPS_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

use crate::app::service_manager::service_manager_instance_veneer;
#[cfg(target_os = "none")]
use crate::app::service_manager::service_handler_at;
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

/// service_handler_state_is_ready — original: `FUN_08138d8c` @
/// **0x08138d8c** (52 raw bytes: 12 ARM instructions plus the trailing table
/// literal @ 0x08138dbc; 0x08138dc0 begins the distinct next function).
/// Ghidra reports only the 48 instruction bytes. A complete decode of every
/// ARM `B`/`BL` word in `osos.dec` finds **12 direct, unconditional `bl` call
/// sites**, with no predicated `bl` or tail-branch callers.
///
/// Algorithm: reject signed selectors three and above through [`heap_panic`],
/// then ignore `manager`, read the signed state byte from selector's 0x114-byte
/// lifecycle record in the three-record table @ 0x08ad0f34, and return whether
/// its unsigned `(state - 4)` is at most two. Thus states 4, 5, and 6 return
/// one; every other signed byte returns zero.
///
/// Deliberate deviation: host builds replace the firmware RAM table with five
/// records and make its second record selector zero, so tests can safely
/// observe selector -1 as well as the three documented records.
#[repr(C)]
#[derive(Clone, Copy)]
struct ServiceHandlerLifecycleRecord {
    state: i8,
    _remaining: [u8; 0x113],
}

const SERVICE_HANDLER_LIFECYCLE_RECORD_COUNT: i32 = 3;

#[cfg(target_os = "none")]
const SERVICE_HANDLER_LIFECYCLE_RECORDS: *const ServiceHandlerLifecycleRecord =
    0x08ad_0f34 as *const ServiceHandlerLifecycleRecord;

#[cfg(not(target_os = "none"))]
static mut HOST_SERVICE_HANDLER_LIFECYCLE_RECORDS: [ServiceHandlerLifecycleRecord; 5] =
    [ServiceHandlerLifecycleRecord {
        state: 0,
        _remaining: [0; 0x113],
    }; 5];

#[cfg(test)]
pub(crate) static SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

#[inline(always)]
unsafe fn service_handler_lifecycle_records() -> *const ServiceHandlerLifecycleRecord {
    #[cfg(target_os = "none")]
    {
        SERVICE_HANDLER_LIFECYCLE_RECORDS
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of!(HOST_SERVICE_HANDLER_LIFECYCLE_RECORDS).cast::<ServiceHandlerLifecycleRecord>().add(1)
    }
}

/// # Safety
///
/// `selector` must name a readable lifecycle record at 0x08ad0f34. The
/// original's signed range check admits negative selectors, which therefore
/// address records before that table.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_state_is_ready(_manager: *mut u8, selector: i32) -> u32 {
    if selector >= SERVICE_HANDLER_LIFECYCLE_RECORD_COUNT {
        heap_panic();
    }

    let record = service_handler_lifecycle_records().wrapping_offset(selector as isize);
    let state = ptr::read_volatile(ptr::addr_of!((*record).state)) as i32;
    (((state - 4) as u32) <= 2) as u32
}

#[cfg(test)]
pub(crate) unsafe fn replace_service_handler_lifecycle_state(selector: i32, state: i8) -> i8 {
    let record = service_handler_lifecycle_records().wrapping_offset(selector as isize);
    let previous = ptr::read_volatile(ptr::addr_of!((*record).state));
    ptr::write_volatile(ptr::addr_of_mut!((*(record as *mut ServiceHandlerLifecycleRecord)).state), state);
    previous
}

type HandlerAt = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[derive(Clone, Copy)]
struct ServiceHandlerAvailabilityOps {
    handler_at: HandlerAt,
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_at(table: *mut u8, selector: u32) -> u32 {
    service_handler_at(table.cast(), selector as i32)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_handler_at(_table: *mut u8, _selector: u32) -> u32 {
    0
}

#[cfg(target_os = "none")]
static mut SERVICE_HANDLER_AVAILABILITY_OPS: ServiceHandlerAvailabilityOps =
    ServiceHandlerAvailabilityOps {
        handler_at: firmware_handler_at,
    };

#[cfg(not(target_os = "none"))]
static mut SERVICE_HANDLER_AVAILABILITY_OPS: ServiceHandlerAvailabilityOps =
    ServiceHandlerAvailabilityOps {
        handler_at: unavailable_handler_at,
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
    let state_is_ready = service_handler_state_is_ready(manager, selector as i32);

    (handler_availability_gate() != 0 && handler != 0 && state_is_ready != 0) as u32
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut MOCK_MANAGER: *mut u8 = ptr::null_mut();
    static mut MOCK_SELECTOR: u32 = 0;
    static mut MOCK_HANDLER: u32 = 0;
    static mut GATE_AFTER_HANDLER: u32 = 1;
    static mut HANDLER_CALLS: u32 = 0;

    unsafe extern "C" fn mock_handler_at(table: *mut u8, selector: u32) -> u32 {
        assert_eq!(table, MOCK_MANAGER.add(HANDLER_TABLE_OFFSET));
        assert_eq!(selector, MOCK_SELECTOR);
        HANDLER_CALLS += 1;
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(GATE_AFTER_HANDLER);
        MOCK_HANDLER
    }

    unsafe fn install(
        manager: *mut u8,
        selector: u32,
        handler: u32,
        state: i8,
        gate_after_handler: u32,
    ) -> (ServiceHandlerAvailabilityOps, i8) {
        let previous_ops = ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_AVAILABILITY_OPS));
        let previous_state = replace_service_handler_lifecycle_state(selector as i32, state);
        SERVICE_HANDLER_AVAILABILITY_OPS = ServiceHandlerAvailabilityOps {
            handler_at: mock_handler_at,
        };
        MOCK_MANAGER = manager;
        MOCK_SELECTOR = selector;
        MOCK_HANDLER = handler;
        GATE_AFTER_HANDLER = gate_after_handler;
        ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), manager);
        HANDLER_CALLS = 0;
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(1);
        (previous_ops, previous_state)
    }

    unsafe fn restore(previous_ops: ServiceHandlerAvailabilityOps, selector: u32, previous_state: i8) {
        SERVICE_HANDLER_AVAILABILITY_OPS = previous_ops;
        replace_service_handler_lifecycle_state(selector as i32, previous_state);
        MOCK_MANAGER = ptr::null_mut();
        ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut());
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(0);
    }

    #[test]
    fn lifecycle_predicate_accepts_only_the_three_ready_states() {
        let _guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        for (selector, state, expected) in [
            (-1, 6, 1),
            (0, -1, 0),
            (1, 3, 0),
            (2, 4, 1),
            (0, 5, 1),
            (1, 6, 1),
            (2, 7, 0),
        ] {
            let previous = unsafe { replace_service_handler_lifecycle_state(selector, state) };
            assert_eq!(
                unsafe { service_handler_state_is_ready(ptr::null_mut(), selector) },
                expected,
                "selector {selector}, state {state}",
            );
            unsafe {
                replace_service_handler_lifecycle_state(selector, previous);
            }
        }
    }

    #[test]
    fn accepts_both_edge_selectors_when_handler_and_state_are_nonzero() {
        let _ops_guard = SERVICE_HANDLER_AVAILABILITY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];

        for selector in [0, HANDLER_SELECTOR_COUNT - 1] {
            let (previous_ops, previous_state) =
                unsafe { install(manager.as_mut_ptr().cast(), selector, 0x1000, 6, 1) };
            assert_eq!(unsafe { service_handler_is_available(selector) }, 1);
            unsafe {
                assert_eq!(HANDLER_CALLS, 1);
                restore(previous_ops, selector, previous_state);
            }
        }
    }

    #[test]
    fn evaluates_lifecycle_state_when_handler_is_absent() {
        let _ops_guard = SERVICE_HANDLER_AVAILABILITY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];
        let (previous_ops, previous_state) =
            unsafe { install(manager.as_mut_ptr().cast(), 1, 0, 6, 1) };

        assert_eq!(unsafe { service_handler_is_available(1) }, 0);
        unsafe {
            assert_eq!(HANDLER_CALLS, 1, "handler access precedes the final AND");
            restore(previous_ops, 1, previous_state);
        }
    }

    #[test]
    fn reloads_the_global_gate_after_the_callees() {
        let _ops_guard = SERVICE_HANDLER_AVAILABILITY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];
        let (previous_ops, previous_state) =
            unsafe { install(manager.as_mut_ptr().cast(), 1, 0x1000, 4, 0) };

        assert_eq!(unsafe { service_handler_is_available(1) }, 0);
        unsafe {
            assert_eq!(HANDLER_CALLS, 1);
            restore(previous_ops, 1, previous_state);
        }
    }
}
