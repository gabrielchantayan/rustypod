//! Readiness of the service-handler context selected at 0x089ccc18.
use crate::app::service_handler_availability::service_handler_state_is_ready;
use crate::app::service_manager::service_manager_instance_veneer;
use core::ptr;

#[repr(C)]
struct SelectedServiceHandlerContext {
    _prefix: [u32; 0x2d0 / 4],
    handler: u32,
    selector: i32,
}

#[cfg(not(target_os = "none"))]
static mut HOST_SELECTED_CONTEXT: *const SelectedServiceHandlerContext = ptr::null();

#[inline(always)]
unsafe fn selected_context() -> *const SelectedServiceHandlerContext {
    #[cfg(target_os = "none")]
    { ptr::read_volatile(0x089c_cc18 as *const *const SelectedServiceHandlerContext) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(HOST_SELECTED_CONTEXT)) }
}

/// selected_service_handler_is_ready — FUN_08209088 @ 0x08209088.
/// True extent: 76 bytes, ending at the next function's push @ 0x082090d4;
/// 72 code bytes and the 0x089ccc18 literal @ 0x082090d0. Raw-word decoding
/// verifies two plain outbound BLs, zero predicated BLs, and two plain inbound
/// BLs (0x08208f68, 0x082092f4), zero predicated inbound BLs.
///
/// Return zero for a null context, zero handler word, or signed selector >=3.
/// Otherwise obtain the service-manager singleton, reload the selected context
/// and its selector, and normalize the lifecycle-readiness predicate to 0/1.
/// Negative selectors are deliberately admitted, matching the signed ARM BGE.
/// Incoming registers are not arguments: the body overwrites r0 and r1.
/// Deliberate deviation: host builds use a native-pointer slot fixture instead
/// of firmware RAM; firmware reads the original slot directly. Existing manager
/// and lifecycle ports retain their documented singleton/table adaptations.
///
/// # Safety
/// The slot must hold null or a readable context. On the admitted path it must
/// remain nonnull across the manager call, the manager must be initialized, and
/// the reloaded selector must address a readable lifecycle record (including
/// pre-table records for negative selectors).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selected_service_handler_is_ready() -> u32 {
    let context = selected_context();
    if context.is_null() { return 0; }
    if ptr::read_volatile(ptr::addr_of!((*context).handler)) == 0 { return 0; }
    if ptr::read_volatile(ptr::addr_of!((*context).selector)) >= 3 { return 0; }
    let manager = service_manager_instance_veneer();
    let context = selected_context();
    let selector = ptr::read_volatile(ptr::addr_of!((*context).selector));
    (service_handler_state_is_ready(manager, selector) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::service_handler_availability::{
        replace_service_handler_lifecycle_state, SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK,
    };
    use crate::app::service_manager::{SERVICE_MANAGER_INSTANCE, SERVICE_MANAGER_INSTANCE_TEST_LOCK};

    #[test]
    fn gates_before_manager_and_preserves_signed_selector_and_state_boundaries() {
        let _manager_guard = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock();
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut context = SelectedServiceHandlerContext {
            _prefix: [0; 0x2d0 / 4], handler: 0, selector: 0,
        };
        unsafe {
            let old_manager = ptr::read_volatile(ptr::addr_of!(SERVICE_MANAGER_INSTANCE));
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut());
            assert_eq!(selected_service_handler_is_ready(), 0);
            HOST_SELECTED_CONTEXT = ptr::addr_of!(context);
            assert_eq!(selected_service_handler_is_ready(), 0);
            context.handler = 1;
            for selector in [3, 4, i32::MAX] {
                context.selector = selector;
                assert_eq!(selected_service_handler_is_ready(), 0);
            }
            let mut manager = [0u32; 0xe8 / 4];
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), manager.as_mut_ptr().cast());
            for selector in [-1, 0, 1, 2] {
                context.selector = selector;
                for state in i8::MIN..=i8::MAX {
                    let old_state = replace_service_handler_lifecycle_state(selector, state);
                    let actual = selected_service_handler_is_ready();
                    replace_service_handler_lifecycle_state(selector, old_state);
                    assert_eq!(actual, (4..=6).contains(&state) as u32,
                        "selector={selector}, state={state}");
                }
            }
            HOST_SELECTED_CONTEXT = ptr::null();
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), old_manager);
        }
    }
}
