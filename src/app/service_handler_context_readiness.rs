//! Service-handler context readiness gate.
//!
//! The otherwise unnamed runtime context slot at `0x089ccb50` supplies a
//! selector at `+0x2d0`; this module deliberately names only that established
//! role.

#[cfg(test)]
extern crate std;

use crate::app::service_handler_availability::service_handler_state_is_ready;
use crate::app::service_manager::service_manager_instance_veneer;
use core::ptr;

const SERVICE_HANDLER_SELECTOR_LIMIT: i32 = 3;

/// Observed prefix of the runtime-selected service-handler context.
#[repr(C)]
struct ServiceHandlerContext {
    _unknown: [u8; 0x2d0],
    selector: i32,
}

const _: [u8; 0x2d0] = [0; core::mem::offset_of!(ServiceHandlerContext, selector)];

#[cfg(target_os = "none")]
const SERVICE_HANDLER_CONTEXT_SLOT: *const *const ServiceHandlerContext =
    0x089c_cb50 as *const *const ServiceHandlerContext;

#[cfg(not(target_os = "none"))]
static mut HOST_SERVICE_HANDLER_CONTEXT: *const ServiceHandlerContext = ptr::null();

#[inline(always)]
unsafe fn service_handler_context() -> *const ServiceHandlerContext {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(SERVICE_HANDLER_CONTEXT_SLOT)
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_SERVICE_HANDLER_CONTEXT))
    }
}

/// service_handler_context_is_ready — original: `FUN_081d7540` @
/// **0x081d7540** (68 raw bytes: 16 ARM instructions plus the trailing
/// context-slot literal). The next real function begins at 0x081d7584;
/// 0x081d7580 is the literal.
/// A complete decode of every ARM `B`/`BL` word in `osos.dec` finds
/// **three inbound direct, unconditional `bl` call sites** and no predicated
/// calls or tail branches. The body has two unconditional outbound `bl`
/// instructions, to the service-manager veneer and lifecycle predicate.
///
/// Algorithm: load the context pointer from 0x089ccb50. If it is NULL, or its
/// signed selector is at least three, return zero. Otherwise obtain the
/// service-manager singleton through its veneer, pass the reloaded selector to
/// [`service_handler_state_is_ready`], and normalize a nonzero result to one.
/// The signed comparison deliberately admits negative selectors, exactly as
/// the ARM `cmpne`/`bge` sequence does.
///
/// Deliberate deviation: host builds model the firmware's runtime-initialized
/// pointer slot with [`HOST_SERVICE_HANDLER_CONTEXT`]. The service-manager and
/// lifecycle-table ports provide the remaining host fixtures. LLVM tail-calls
/// the already-normalized lifecycle predicate after the singleton call, so the
/// generated ARM omits stock's redundant compare/move normalization.
///
/// # Safety
///
/// On firmware, 0x089ccb50 must hold either NULL or a pointer to a context
/// with a readable signed selector at `+0x2d0`. A non-NULL, in-range path also
/// requires the service-manager singleton to have been initialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_context_is_ready() -> u32 {
    let context = service_handler_context();
    if context.is_null() || (*context).selector >= SERVICE_HANDLER_SELECTOR_LIMIT {
        return 0;
    }

    let manager = service_manager_instance_veneer();
    (service_handler_state_is_ready(manager, (*context).selector) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::service_handler_availability::{
        replace_service_handler_lifecycle_state, SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK,
    };
    use crate::app::service_manager::{SERVICE_MANAGER_INSTANCE, SERVICE_MANAGER_INSTANCE_TEST_LOCK};

    #[test]
    fn context_presence_selector_boundary_and_lifecycle_state_control_readiness() {
        let _manager_lock = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock();
        let _lifecycle_lock = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap();
        let manager = 1usize as *mut u8;
        let old_manager = unsafe { SERVICE_MANAGER_INSTANCE };
        let old_context = unsafe { HOST_SERVICE_HANDLER_CONTEXT };
        let old_state_minus_one = unsafe { replace_service_handler_lifecycle_state(-1, 4) };
        let old_state_zero = unsafe { replace_service_handler_lifecycle_state(0, 4) };
        let mut context = ServiceHandlerContext {
            _unknown: [0; 0x2d0],
            selector: 0,
        };

        unsafe {
            SERVICE_MANAGER_INSTANCE = manager;
            HOST_SERVICE_HANDLER_CONTEXT = ptr::null();
            assert_eq!(service_handler_context_is_ready(), 0);

            HOST_SERVICE_HANDLER_CONTEXT = &mut context;
            assert_eq!(service_handler_context_is_ready(), 1);

            context.selector = 3;
            assert_eq!(service_handler_context_is_ready(), 0);

            context.selector = -1;
            assert_eq!(service_handler_context_is_ready(), 1);

            context.selector = 0;
            replace_service_handler_lifecycle_state(0, 3);
            assert_eq!(service_handler_context_is_ready(), 0);

            replace_service_handler_lifecycle_state(-1, old_state_minus_one);
            replace_service_handler_lifecycle_state(0, old_state_zero);
            HOST_SERVICE_HANDLER_CONTEXT = old_context;
            SERVICE_MANAGER_INSTANCE = old_manager;
        }
    }
}
