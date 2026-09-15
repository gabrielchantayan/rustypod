//! `registration_handle_current_status_is_nonzero` — original: `FUN_0820d598`
//! @ `0x0820d598` (84 bytes, `0x0820d598..0x0820d5ec`; the separately linked
//! next function begins at `0x0820d5ec`).
//!
//! Raw ARM has three unconditional direct `bl` instructions in its body:
//! `registration_handle_wrapper_init`, `current_record_handle_from_owner`, and
//! `registration_handle_wrapper_destroy`; its vtable `+0x28` call is `blx r1`.
//! Whole-image ARM B/BL-immediate decoding finds five inbound plain,
//! unconditional `bl` calls (0x0820cfd0, 0x0820d17c, 0x0820d470, 0x0820d558,
//! and 0x0820d658), with zero predicated direct `bl` calls.
//!
//! # Algorithm
//!
//! Build a stack registration-handle wrapper from the context stored in the
//! first word of `context_source` and two selector words, obtain its current
//! record handle, and return whether the handle is absent or its vtable `+0x28`
//! status method returns nonzero. The wrapper is destroyed on both branches.
//! No stronger identity is assigned to that virtual method.
//!
//! Deliberate host deviation: `RegistrationHandle` contains a widened host
//! owner pointer, so its target-width current-record cursor layout cannot be
//! addressed through the wrapper. Host builds calculate the same target word
//! address from the named owner and slot fields; firmware builds retain the
//! existing target-layout accessor.
//!
#[cfg(target_os = "none")]
use crate::app::current_record_handle::{
    current_record_handle_from_owner, CurrentRecordCursorOwner,
};

use crate::app::registration_handle_wrapper::{
    registration_handle_wrapper_destroy, registration_handle_wrapper_init, RegistrationHandleWrapper,
};

/// An object whose status callback is at vtable byte offset `+0x28` on ARM.
#[repr(C)]
pub struct CurrentRegistrationTarget {
    pub vtable: *const CurrentRegistrationTargetVtable,
}

/// Recovered portion of [`CurrentRegistrationTarget`]'s vtable.
#[repr(C)]
pub struct CurrentRegistrationTargetVtable {
    pub preceding_slots: [usize; 10],
    pub status: unsafe extern "C" fn(*mut CurrentRegistrationTarget) -> i32,
}

#[inline(always)]
unsafe fn current_target_status_is_nonzero(target: *mut CurrentRegistrationTarget) -> bool {
    ((*(*target).vtable).status)(target) != 0
}

/// registration_handle_current_status_is_nonzero — original: `FUN_0820d598` @
/// `0x0820d598` (84 bytes; five unconditional direct `bl` call sites).
///
/// Loads the context from `context_source`, initializes a temporary registration
/// wrapper, then returns whether its current record is absent or its vtable
/// `+0x28` status callback is nonzero. `selector_second` reaches the wrapper
/// initializer in `r3`, although this function otherwise does not inspect it.
///
/// # Safety
///
/// `context_source` must identify a readable first word. The resulting context
/// and its `+0xa0c` registration owner must meet
/// [`registration_handle_wrapper_init`]'s requirements. A selected record must
/// contain a valid target-width pointer at `owner + slot * 0x14 + 4` to an
/// object whose vtable and `+0x28` callback are valid. RetailOS performs no
/// validation of those pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_handle_current_status_is_nonzero(
    context_source: *const *mut u8,
    selector_first: u32,
    selector_second: u32,
) -> i32 {
    let mut wrapper = core::mem::MaybeUninit::<RegistrationHandleWrapper>::uninit();
    let context = context_source.read();
    registration_handle_wrapper_init(
        wrapper.as_mut_ptr(),
        context,
        selector_first,
        selector_second,
    );
    let wrapper = wrapper.assume_init_mut();

    #[cfg(target_os = "none")]
    let target = current_record_handle_from_owner(
        wrapper as *mut RegistrationHandleWrapper as *const CurrentRecordCursorOwner,
    ) as usize as *mut CurrentRegistrationTarget;
    #[cfg(not(target_os = "none"))]
    let target = if wrapper.registration.slot_index == -1 {
        core::ptr::null_mut()
    } else {
        let record = (wrapper.registration.owner as usize)
            .wrapping_add((wrapper.registration.slot_index as usize).wrapping_mul(0x14));
        (record.wrapping_add(4) as *const u32).read() as usize as *mut CurrentRegistrationTarget
    };

    let result = if target.is_null() || current_target_status_is_nonzero(target) {
        1
    } else {
        0
    };
    registration_handle_wrapper_destroy(wrapper);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn status_zero(_target: *mut CurrentRegistrationTarget) -> i32 { 0 }
    unsafe extern "C" fn status_nonzero(_target: *mut CurrentRegistrationTarget) -> i32 { 7 }

    #[test]
    fn null_stored_context_has_no_current_record_regardless_of_selectors() {
        let context = core::ptr::null_mut();
        assert_eq!(unsafe {
            registration_handle_current_status_is_nonzero(&context, 0, 0)
        }, 1);
        assert_eq!(unsafe {
            registration_handle_current_status_is_nonzero(&context, u32::MAX, 0xfeed_face)
        }, 1);
    }

    #[test]
    fn status_callback_zero_is_the_only_false_result() {
        let zero_vtable = CurrentRegistrationTargetVtable {
            preceding_slots: [0; 10],
            status: status_zero,
        };
        let nonzero_vtable = CurrentRegistrationTargetVtable {
            preceding_slots: [0; 10],
            status: status_nonzero,
        };
        let mut zero_target = CurrentRegistrationTarget { vtable: &zero_vtable };
        let mut nonzero_target = CurrentRegistrationTarget { vtable: &nonzero_vtable };

        assert!(!unsafe { current_target_status_is_nonzero(&mut zero_target) });
        assert!(unsafe { current_target_status_is_nonzero(&mut nonzero_target) });
    }
}
