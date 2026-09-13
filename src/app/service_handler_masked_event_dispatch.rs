//! `service_handler_masked_event_dispatch` — original: `FUN_0818f800` @
//! `0x0818f800` (132 bytes, `0x0818f800..0x0818f884`; the next separately
//! linked function begins at `0x0818f884`).
//!
//! Raw ARM accepts only mask bits `0x1fbf`; any other bit takes the predicated
//! `blne 0x08030f44` fatal path. A zero mask returns. Otherwise it walks slots
//! 1 through 12, invokes vtable `+0x0c` for every selected handler with event
//! code 8 and the complete mask, then tail-dispatches the same context, slot,
//! event code 7, and mask to unported `FUN_0818f230`.
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` found exactly seven
//! inbound direct call sites, all unconditional plain `bl` (0x0818e734,
//! 0x0818fca4, 0x08191008, 0x081910bc, 0x0819265c, 0x08192a68, and
//! 0x08192d7c); there are no predicated direct calls or inbound tail branches.
//! `FUN_0818f230` remains unported, so host tests use a volatile tail-dispatch
//! seam while target builds call its fixed retail address. Host tests similarly
//! replace the target-only 32-bit vtable call with a seam because a host
//! function pointer cannot inhabit the firmware's four-byte vtable slot.
//! These seams do not alter target behavior.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;
use core::ptr;

use crate::app::service_manager::{service_manager_instance_veneer, service_manager_slot_handler_get};
use crate::heap::veneers::heap_panic;

const VALID_MASK: u32 = 0x1fbf;
const HANDLER_EVENT_CODE: u32 = 8;
const TAIL_EVENT_CODE: u32 = 7;
const RETAIL_MASKED_EVENT_TAIL: usize = 0x0818_f230;

/// ABI of a selected handler object's vtable `+0x0c` operation.
pub type ServiceHandlerEventDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

/// ABI of the unported continuation at `0x0818f230`.
pub type ServiceHandlerMaskedEventTail = unsafe extern "C" fn(*mut u8, u32, u32, u32);

/// Host replacement for the target-only handler vtable dispatch.
#[derive(Clone, Copy)]
pub struct ServiceHandlerEventDispatchOps {
    pub dispatch: ServiceHandlerEventDispatch,
}

/// Host replacement for the unported tail dispatcher.
#[derive(Clone, Copy)]
pub struct ServiceHandlerMaskedEventTailOps {
    pub dispatch: ServiceHandlerMaskedEventTail,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_handler_event_dispatch(handler: *mut u8, event_code: u32, mask: u32) {
    let vtable = unsafe { ptr::read(handler.cast::<u32>()) } as usize as *const u32;
    let dispatch: ServiceHandlerEventDispatch = unsafe { core::mem::transmute(ptr::read(vtable.add(3)) as usize) };
    unsafe { dispatch(handler, event_code, mask) };
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_masked_event_tail(context: *mut u8, slot: u32, event_code: u32, mask: u32) {
    let dispatch: ServiceHandlerMaskedEventTail = unsafe { core::mem::transmute(RETAIL_MASKED_EVENT_TAIL) };
    unsafe { dispatch(context, slot, event_code, mask) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handler_event_dispatch(_handler: *mut u8, _event_code: u32, _mask: u32) {
    panic!("install service-handler event dispatch host operations before calling this dispatcher")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_masked_event_tail(_context: *mut u8, _slot: u32, _event_code: u32, _mask: u32) {
    panic!("install service-handler masked-event tail host operations before calling this dispatcher")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_SERVICE_HANDLER_EVENT_DISPATCH_OPS: ServiceHandlerEventDispatchOps =
    ServiceHandlerEventDispatchOps { dispatch: missing_handler_event_dispatch };

#[cfg(not(target_os = "none"))]
pub const DEFAULT_SERVICE_HANDLER_MASKED_EVENT_TAIL_OPS: ServiceHandlerMaskedEventTailOps =
    ServiceHandlerMaskedEventTailOps { dispatch: missing_masked_event_tail };

/// Volatile host seam for the selected handler's vtable operation.
#[cfg(not(target_os = "none"))]
pub static mut SERVICE_HANDLER_EVENT_DISPATCH_OPS: ServiceHandlerEventDispatchOps =
    DEFAULT_SERVICE_HANDLER_EVENT_DISPATCH_OPS;

/// Volatile host seam for unported `FUN_0818f230`; target builds use its address.
#[cfg(not(target_os = "none"))]
pub static mut SERVICE_HANDLER_MASKED_EVENT_TAIL_OPS: ServiceHandlerMaskedEventTailOps =
    DEFAULT_SERVICE_HANDLER_MASKED_EVENT_TAIL_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_handler_event_dispatch(handler: *mut u8, event_code: u32, mask: u32) {
    let dispatch = unsafe { ptr::read_volatile(addr_of!(SERVICE_HANDLER_EVENT_DISPATCH_OPS.dispatch)) };
    unsafe { dispatch(handler, event_code, mask) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_masked_event_tail(context: *mut u8, slot: u32, event_code: u32, mask: u32) {
    let dispatch = unsafe { ptr::read_volatile(addr_of!(SERVICE_HANDLER_MASKED_EVENT_TAIL_OPS.dispatch)) };
    unsafe { dispatch(context, slot, event_code, mask) };
}

/// Notifies every selected service handler, then continues with event code 7.
///
/// # Safety
///
/// `context` and the published service-manager instance must be valid for the
/// unported continuation. Every selected slot must contain a valid handler
/// object whose vtable has a callable word at `+0x0c`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn service_handler_masked_event_dispatch(context: *mut u8, slot: u32, mask: u32) {
    if mask & !VALID_MASK != 0 {
        heap_panic();
    }
    if mask == 0 {
        return;
    }

    for handler_slot in 1..13u32 {
        if mask & (1u32 << handler_slot) != 0 {
            let manager = unsafe { service_manager_instance_veneer() };
            let handler = unsafe { service_manager_slot_handler_get(manager.add(4).cast(), handler_slot as i32) };
            #[cfg(target_os = "none")]
            unsafe { retail_handler_event_dispatch(handler, HANDLER_EVENT_CODE, mask) };
            #[cfg(not(target_os = "none"))]
            unsafe { host_handler_event_dispatch(handler, HANDLER_EVENT_CODE, mask) };
        }
    }

    #[cfg(target_os = "none")]
    unsafe { retail_masked_event_tail(context, slot, TAIL_EVENT_CODE, mask) };
    #[cfg(not(target_os = "none"))]
    unsafe { host_masked_event_tail(context, slot, TAIL_EVENT_CODE, mask) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::service_manager::{SERVICE_MANAGER_INSTANCE, SERVICE_MANAGER_INSTANCE_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut HANDLER_CALLS: [Option<(*mut u8, u32, u32)>; 12] = [None; 12];
    static mut HANDLER_CALL_COUNT: usize = 0;
    static mut TAIL_CALL: Option<(*mut u8, u32, u32, u32)> = None;

    unsafe extern "C" fn record_handler(handler: *mut u8, event_code: u32, mask: u32) {
        unsafe {
            HANDLER_CALLS[HANDLER_CALL_COUNT] = Some((handler, event_code, mask));
            HANDLER_CALL_COUNT += 1;
        };
    }

    unsafe extern "C" fn record_tail(context: *mut u8, slot: u32, event_code: u32, mask: u32) {
        unsafe { TAIL_CALL = Some((context, slot, event_code, mask)) };
    }

    unsafe fn install_recorders() {
        unsafe {
            HANDLER_CALLS = [None; 12];
            HANDLER_CALL_COUNT = 0;
            TAIL_CALL = None;
            addr_of_mut!(SERVICE_HANDLER_EVENT_DISPATCH_OPS).write(ServiceHandlerEventDispatchOps {
                dispatch: record_handler,
            });
            addr_of_mut!(SERVICE_HANDLER_MASKED_EVENT_TAIL_OPS).write(ServiceHandlerMaskedEventTailOps {
                dispatch: record_tail,
            });
        }
    }

    unsafe fn restore_defaults() {
        unsafe {
            addr_of_mut!(SERVICE_HANDLER_EVENT_DISPATCH_OPS).write(DEFAULT_SERVICE_HANDLER_EVENT_DISPATCH_OPS);
            addr_of_mut!(SERVICE_HANDLER_MASKED_EVENT_TAIL_OPS).write(DEFAULT_SERVICE_HANDLER_MASKED_EVENT_TAIL_OPS);
            addr_of_mut!(SERVICE_MANAGER_INSTANCE).write(ptr::null_mut());
        }
    }

    #[test]
    fn dispatches_selected_slots_in_order_then_forwards_event_seven() {
        let _ops_guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _instance_guard = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = try_map_u32_slab(hints::SERVICE_HANDLER_MASKED_EVENT_DISPATCH, 4096) else {
            note_missing_u32_fixture("service_handler_masked_event_dispatch");
            return;
        };
        let manager = slab;
        let handler_one = unsafe { slab.add(0x100) };
        let handler_five = unsafe { slab.add(0x200) };
        let handler_eight = unsafe { slab.add(0x300) };
        let handler_twelve = unsafe { slab.add(0x400) };
        let mask = 1 | (1 << 1) | (1 << 5) | (1 << 8) | (1 << 12);
        let mut context = [0u8; 4];

        unsafe {
            install_recorders();
            let table = manager.cast::<u32>();
            for (handler_slot, handler) in [(1usize, handler_one), (5, handler_five), (8, handler_eight), (12, handler_twelve)] {
                table.add(1 + 25 + handler_slot * 2).write(handler as usize as u32);
            }
            addr_of_mut!(SERVICE_MANAGER_INSTANCE).write(manager);
            service_handler_masked_event_dispatch(context.as_mut_ptr(), 2, mask);

            assert_eq!(HANDLER_CALL_COUNT, 4);
            assert_eq!(HANDLER_CALLS[..4], [
                Some((handler_one, HANDLER_EVENT_CODE, mask)),
                Some((handler_five, HANDLER_EVENT_CODE, mask)),
                Some((handler_eight, HANDLER_EVENT_CODE, mask)),
                Some((handler_twelve, HANDLER_EVENT_CODE, mask)),
            ]);
            assert_eq!(addr_of!(TAIL_CALL).read(), Some((context.as_mut_ptr(), 2, TAIL_EVENT_CODE, mask)));
            restore_defaults();
        }
    }

    #[test]
    fn zero_mask_returns_without_reading_manager_or_dispatching() {
        let _ops_guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _instance_guard = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            install_recorders();
            addr_of_mut!(SERVICE_MANAGER_INSTANCE).write(ptr::null_mut());
            service_handler_masked_event_dispatch(ptr::null_mut(), u32::MAX, 0);
            assert_eq!(HANDLER_CALL_COUNT, 0);
            assert_eq!(addr_of!(TAIL_CALL).read(), None);
            restore_defaults();
        }
    }
}
