//! Owned UI operation cleanup, retailOS `FUN_0819c30c` at `0x0819c30c`.
//!
//! True extent: 40 bytes, ending with pop at `0x0819c330`; the next real
//! function starts at `0x0819c334`. Two outbound plain BLs (operation destroy
//! at `0x0819c320`, operator delete at `0x0819c324`), no predicated BLs.
//! Whole-image A32 decoding finds two inbound plain BLs at `0x0819c5f4` and
//! `0x081b5780`, and no predicated BL callers.
//!
//! Load the owned operation at +0x30. If non-NULL, destroy it and tag-2-delete
//! the destructor's returned allocation. Clear the slot unconditionally,
//! after both calls. No target behavior deviations. Host builds widen only
//! the operation pointer and expose replaceable boundaries for the two
//! already-ported callees; the unknown owner prefix remains twelve words.

use crate::ui::operation_destroy::{ui_operation_destroy, UiOperationPrefix};
use crate::heap::veneers::operator_delete;

#[repr(C)]
pub struct UiOperationOwner {
    pub unresolved_00_2c: [u32; 12],
    pub operation: *mut UiOperationPrefix,
}

#[cfg(not(target_os = "none"))]
static mut DESTROY: unsafe extern "C" fn(*mut UiOperationPrefix) -> *mut UiOperationPrefix = ui_operation_destroy;
#[cfg(not(target_os = "none"))]
static mut DELETE: unsafe extern "C" fn(*mut u8) = operator_delete;

/// Destroy and release the owner's nullable operation, then clear ownership.
///
/// # Safety
/// `owner` must be writable through its operation field. A non-NULL operation
/// must satisfy `ui_operation_destroy`'s contract and its returned pointer must
/// be accepted by `operator_delete`. Callees must not invalidate the owner.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_owner_clear_operation(owner: *mut UiOperationOwner) {
    let operation = (*owner).operation;
    if !operation.is_null() {
        #[cfg(target_os = "none")]
        let allocation = ui_operation_destroy(operation);
        #[cfg(not(target_os = "none"))]
        let allocation = DESTROY(operation);
        #[cfg(target_os = "none")]
        operator_delete(allocation.cast());
        #[cfg(not(target_os = "none"))]
        DELETE(allocation.cast());
    }
    (*owner).operation = core::ptr::null_mut();
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut OWNER: *mut UiOperationOwner = core::ptr::null_mut();
    static mut RESULT: *mut UiOperationPrefix = core::ptr::null_mut();
    static mut EVENTS: u32 = 0;

    unsafe extern "C" fn destroy(operation: *mut UiOperationPrefix) -> *mut UiOperationPrefix {
        assert_eq!(operation, (*OWNER).operation);
        assert_eq!(EVENTS, 0);
        EVENTS = 1;
        RESULT
    }

    unsafe extern "C" fn delete(allocation: *mut u8) {
        assert_eq!(allocation, RESULT.cast());
        assert!(!(*OWNER).operation.is_null());
        assert_eq!(EVENTS, 1);
        EVENTS = 2;
        // The final store must also clear a slot changed during teardown.
        (*OWNER).operation = RESULT;
    }

    #[test]
    fn nullable_cleanup_preserves_prefix_and_clears_after_delete() {
        let _lock = LOCK.lock();
        unsafe {
            let saved_destroy = DESTROY;
            let saved_delete = DELETE;
            DESTROY = destroy;
            DELETE = delete;
            let mut operation = [0u32; 32];
            let mut returned = [0u32; 32];
            for populated in [false, true] {
                for null_result in [false, true] {
                    let mut owner = UiOperationOwner {
                        unresolved_00_2c: [0xa5a5_5a5a; 12],
                        operation: if populated { operation.as_mut_ptr().cast() } else { core::ptr::null_mut() },
                    };
                    OWNER = &mut owner;
                    RESULT = if null_result { core::ptr::null_mut() } else { returned.as_mut_ptr().cast() };
                    EVENTS = 0;
                    ui_owner_clear_operation(&mut owner);
                    assert!(owner.operation.is_null());
                    assert_eq!(owner.unresolved_00_2c, [0xa5a5_5a5a; 12]);
                    assert_eq!(EVENTS, if populated { 2 } else { 0 });
                    ui_owner_clear_operation(&mut owner);
                    assert_eq!(EVENTS, if populated { 2 } else { 0 });
                }
            }
            DESTROY = saved_destroy;
            DELETE = saved_delete;
        }
    }
}
