//! Active service-handler readiness gate.
//!
//! `active_service_handler_is_ready` — original: `FUN_081946ec` @
//! **0x081946ec** (76 raw bytes: 18 ARM instructions plus the trailing global
//! literal @ 0x08194734; 0x08194738 begins the distinct next function). A
//! complete decode of every ARM `B`/`BL` word in `osos.dec` finds **14 direct,
//! unconditional `bl` call sites** and no predicated or tail-branch callers.
//!
//! Algorithm: load the active service-handler context pointer from
//! 0x089ccb5c; require its `+0x2d0` handler word to be nonzero and its `+0x2d4`
//! selector to compare below three as a signed value. Then obtain the
//! service-manager singleton through its stock veneer and return whether the
//! existing handler-state predicate reports that selector ready.
//!
//! Deliberate deviations: the runtime-initialized context slot is a host
//! fixture outside firmware builds. `FUN_08138d8c` remains unported, so this
//! port uses its established shared volatile dispatch seam rather than adding
//! another host stub. The original signed comparison admits negative selector
//! words; this port preserves that behavior and delegates them unchanged.
use crate::app::service_handler_availability::service_handler_state_is_ready;
use crate::app::service_manager::service_manager_instance_veneer;
use core::ptr;

const SERVICE_HANDLER_SELECTOR_LIMIT: i32 = 3;

/// Observed fields of the runtime-selected service-handler context.
///
/// The handler is only tested for nonzero here. Its object identity and the
/// surrounding context type have not survived, so names state only what this
/// predicate establishes.
#[repr(C)]
struct ActiveServiceHandlerContext {
    _before_active_handler: [u32; 0x2d0 / 4],
    active_handler: u32,
    selector: u32,
}

#[cfg(target_os = "none")]
const ACTIVE_SERVICE_HANDLER_CONTEXT_SLOT: *const *const ActiveServiceHandlerContext =
    0x089c_cb5c as *const *const ActiveServiceHandlerContext;

#[cfg(not(target_os = "none"))]
static mut HOST_ACTIVE_SERVICE_HANDLER_CONTEXT: *const ActiveServiceHandlerContext = ptr::null();

#[inline(always)]
unsafe fn active_service_handler_context() -> *const ActiveServiceHandlerContext {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(ACTIVE_SERVICE_HANDLER_CONTEXT_SLOT)
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_ACTIVE_SERVICE_HANDLER_CONTEXT))
    }
}

/// active_service_handler_is_ready — original: `FUN_081946ec` @ 0x081946ec
/// (76 bytes including its trailing literal; 14 direct unconditional `bl`
/// call sites).
///
/// Returns zero until the active context has a handler and a signed selector
/// below three. Otherwise invokes the service-manager accessor and the shared
/// lifecycle-state dispatch before normalizing its nonzero result to one.
///
/// # Safety
///
/// On firmware, 0x089ccb5c must contain either NULL or a valid context with
/// the two fields described by [`ActiveServiceHandlerContext`]. A valid path
/// also requires the service-manager singleton to have been initialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn active_service_handler_is_ready() -> u32 {
    let context = active_service_handler_context();
    if context.is_null() {
        return 0;
    }

    if ptr::read_volatile(ptr::addr_of!((*context).active_handler)) == 0 {
        return 0;
    }

    let selector = ptr::read_volatile(ptr::addr_of!((*context).selector));
    if (selector as i32) >= SERVICE_HANDLER_SELECTOR_LIMIT {
        return 0;
    }

    let manager = service_manager_instance_veneer();
    (service_handler_state_is_ready(manager, selector) != 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::service_handler_availability::{
        replace_handler_state_is_ready, HandlerStateIsReady,
        SERVICE_HANDLER_AVAILABILITY_OPS_LOCK,
    };
    use crate::app::service_manager::SERVICE_MANAGER_INSTANCE;

    static mut EXPECTED_MANAGER: *mut u8 = ptr::null_mut();
    static mut EXPECTED_SELECTOR: u32 = 0;
    static mut STATE_RESULT: u32 = 0;
    static mut STATE_CALLS: u32 = 0;

    unsafe extern "C" fn mock_handler_state_is_ready(manager: *mut u8, selector: u32) -> u32 {
        assert_eq!(manager, EXPECTED_MANAGER);
        assert_eq!(selector, EXPECTED_SELECTOR);
        STATE_CALLS += 1;
        STATE_RESULT
    }

    unsafe fn install(
        context: *const ActiveServiceHandlerContext,
        manager: *mut u8,
        selector: u32,
        state_result: u32,
    ) -> HandlerStateIsReady {
        let previous = replace_handler_state_is_ready(mock_handler_state_is_ready);
        HOST_ACTIVE_SERVICE_HANDLER_CONTEXT = context;
        ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), manager);
        EXPECTED_MANAGER = manager;
        EXPECTED_SELECTOR = selector;
        STATE_RESULT = state_result;
        STATE_CALLS = 0;
        previous
    }

    unsafe fn restore(previous: HandlerStateIsReady) {
        replace_handler_state_is_ready(previous);
        HOST_ACTIVE_SERVICE_HANDLER_CONTEXT = ptr::null();
        ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut());
        EXPECTED_MANAGER = ptr::null_mut();
    }

    #[test]
    fn missing_context_handler_or_high_selector_short_circuits() {
        let _guard = SERVICE_HANDLER_AVAILABILITY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 1];
        let mut context = ActiveServiceHandlerContext {
            _before_active_handler: [0; 0x2d0 / 4],
            active_handler: 1,
            selector: 0,
        };
        let previous = unsafe { install(ptr::null(), manager.as_mut_ptr().cast(), 0, 1) };

        assert_eq!(unsafe { active_service_handler_is_ready() }, 0);
        unsafe {
            assert_eq!(STATE_CALLS, 0);
            HOST_ACTIVE_SERVICE_HANDLER_CONTEXT = ptr::addr_of!(context);
            context.active_handler = 0;
        }
        assert_eq!(unsafe { active_service_handler_is_ready() }, 0);
        unsafe {
            assert_eq!(STATE_CALLS, 0);
            context.active_handler = 1;
            context.selector = SERVICE_HANDLER_SELECTOR_LIMIT as u32;
        }
        assert_eq!(unsafe { active_service_handler_is_ready() }, 0);
        unsafe {
            assert_eq!(STATE_CALLS, 0);
            restore(previous);
        }
    }

    #[test]
    fn delegates_valid_and_negative_selectors_then_normalizes_result() {
        let _guard = SERVICE_HANDLER_AVAILABILITY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 1];
        let mut context = ActiveServiceHandlerContext {
            _before_active_handler: [0; 0x2d0 / 4],
            active_handler: 0x1000,
            selector: 0,
        };

        for (selector, state_result) in [(0, 1), (2, 0), (u32::MAX, 0x80)] {
            context.selector = selector;
            let previous = unsafe {
                install(ptr::addr_of!(context), manager.as_mut_ptr().cast(), selector, state_result)
            };

            assert_eq!(unsafe { active_service_handler_is_ready() }, (state_result != 0) as u32);
            unsafe {
                assert_eq!(STATE_CALLS, 1);
                restore(previous);
            }
        }
    }
}
