//! Readiness gate for the iAP packet context held at 0x089ccbd8.
use crate::app::service_handler_availability::service_handler_state_is_ready;
use crate::app::service_manager::service_manager_instance_veneer;
use core::ptr;

#[repr(C)]
struct IapPacketContext {
    _prefix: [u32; 0x2d0 / 4],
    handler: u32,
    selector: i32,
}

#[cfg(not(target_os = "none"))]
static mut HOST_PACKET_CONTEXT: *const IapPacketContext = ptr::null();

#[inline(always)]
unsafe fn packet_context() -> *const IapPacketContext {
    #[cfg(target_os = "none")]
    { ptr::read_volatile(0x089c_cbd8 as *const *const IapPacketContext) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(HOST_PACKET_CONTEXT)) }
}

/// iap_packet_context_is_ready — FUN_08164090 @ 0x08164090.
/// True extent: 76 bytes, 72 instruction bytes plus literal 0x089ccbd4 at
/// 0x081640d8; the next function starts at 0x081640dc. Raw-word decoding
/// verifies two plain outbound BLs and zero predicated BLs; two plain inbound
/// BLs at 0x08163be4 and 0x0816468c, zero predicated inbound BLs.
///
/// Reject a null context, zero handler word, or signed selector >=3. Otherwise
/// obtain the service manager, reload the context and selector, and normalize
/// the existing lifecycle-readiness predicate to 0/1. Negative selectors pass
/// the signed guard. Incoming r0/r1 are overwritten, not arguments.
/// Deliberate deviations: host builds use a native-pointer context fixture;
/// firmware reads the original RAM slot. Existing manager and lifecycle ports
/// retain their documented singleton/table adaptations.
///
/// # Safety
/// The slot must hold null or a readable context. On the admitted path it must
/// remain nonnull across the manager call, the manager must be initialized,
/// and the reloaded selector must address a readable lifecycle record,
/// including pre-table records for negative selectors.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_packet_context_is_ready() -> u32 {
    let context = packet_context();
    if context.is_null() { return 0; }
    if ptr::read_volatile(ptr::addr_of!((*context).handler)) == 0 { return 0; }
    if ptr::read_volatile(ptr::addr_of!((*context).selector)) >= 3 { return 0; }
    let manager = service_manager_instance_veneer();
    let context = packet_context();
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
    fn rejects_before_manager_access_and_matches_signed_lifecycle_boundaries() {
        let _manager_guard = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock();
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut context = IapPacketContext {
            _prefix: [0; 0x2d0 / 4], handler: 0, selector: 0,
        };
        unsafe {
            let old_manager = ptr::read_volatile(ptr::addr_of!(SERVICE_MANAGER_INSTANCE));
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut());
            assert_eq!(iap_packet_context_is_ready(), 0);
            HOST_PACKET_CONTEXT = ptr::addr_of!(context);
            for selector in [i32::MIN, -1, 0, 2, 3, i32::MAX] {
                context.selector = selector;
                assert_eq!(iap_packet_context_is_ready(), 0,
                    "zero handler must reject selector={selector} before manager access");
            }
            context.handler = u32::MAX;
            for selector in [3, 4, i32::MAX] {
                context.selector = selector;
                assert_eq!(iap_packet_context_is_ready(), 0);
            }
            let mut manager = [0u32; 0xe8 / 4];
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), manager.as_mut_ptr().cast());
            for selector in [-1, 0, 1, 2] {
                context.selector = selector;
                for state in i8::MIN..=i8::MAX {
                    let old_state = replace_service_handler_lifecycle_state(selector, state);
                    let actual = iap_packet_context_is_ready();
                    replace_service_handler_lifecycle_state(selector, old_state);
                    assert_eq!(actual, (4..=6).contains(&state) as u32,
                        "selector={selector}, state={state}");
                }
            }
            HOST_PACKET_CONTEXT = ptr::null();
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), old_manager);
        }
    }
}
