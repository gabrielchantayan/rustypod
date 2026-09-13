//! `registration_handle_wrapper_destroy` — original: `FUN_081c87c4` @
//! `0x081c87c4` (24 bytes of code; its 4-byte vtable literal is at
//! `0x081c87dc`, and the separately linked next function begins at
//! `0x081c87e0`).
//!
//! Restores the wrapper's vtable, then destroys its embedded
//! [`RegistrationHandle`] through [`registration_handle_destroy`]. The base
//! destructor reinstalls its own vtable, releases the claimed slot unless it
//! is `-1`, and returns the embedded object; this wrapper subtracts the base
//! subobject displacement and returns the wrapper address.
//!
//! **15 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`; there
//! are no direct `b` tail callers. The call sites are 0x0820cff4, 0x0820d04c,
//! 0x0820d05c, 0x0820d338, 0x0820d350, 0x0820d360, 0x0820d3b8, 0x0820d3cc,
//! 0x0820d42c, 0x0820d47c, 0x0820d4e0, 0x0820d58c, 0x0820d5dc, 0x0820d620,
//! and 0x0820d66c.
//!
//! Deliberate deviation: `RegistrationHandleWrapper` nests a real
//! [`RegistrationHandle`] rather than addressing the base with a literal
//! `+4` byte offset. `#[repr(C)]` preserves the target base offset (+4) while
//! allowing the host's pointer-widened base object to remain naturally aligned.

//! `registration_handle_wrapper_init` — original: `FUN_081c877c` @
//! `0x081c877c` (68 bytes total: 64 bytes of code at
//! `0x081c877c..0x081c87bc`, followed by its `0x089a74ac` vtable literal at
//! `0x081c87c0`; the separately linked sibling begins at `0x081c87c4`).
//!
//! Installs the wrapper vtable, copies two selector words to a stack pair, and
//! initializes the embedded registration handle using selector kind two. A
//! non-NULL context becomes the registration owner at context `+0xa0c`;
//! NULL remains NULL. The original copies both selector words even though kind
//! two consumes only the first.
//!
//! **7 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`; there
//! are no direct `b` tail callers. The call sites are 0x0820cf64, 0x0820d0c0,
//! 0x0820d388, 0x0820d414, 0x0820d4a8, 0x0820d5b0, and 0x0820d608.
//!
//! Deliberate deviation: the target's `+4` embedded-base pointer becomes the
//! named `registration` field, keeping ARM's target layout while allowing the
//! owner pointer to widen naturally on the host.

use crate::app::registration_handle::{
    registration_handle_destroy, registration_handle_init, RegistrationHandle,
};

/// Vtable restored before destroying the embedded registration handle.
pub const REGISTRATION_HANDLE_WRAPPER_VTABLE: u32 = 0x089a_74ac;

/// A polymorphic wrapper whose registration-handle base begins at +0x04 on
/// the 32-bit target.
#[repr(C)]
pub struct RegistrationHandleWrapper {
    pub vtable: u32,
    pub registration: RegistrationHandle,
}

/// Installs the wrapper and initializes its embedded registration handle.
///
/// # Safety
///
/// `wrapper` must be valid and aligned. When `context` is non-NULL, the
/// `0xa0c` byte-offset owner it denotes must satisfy
/// [`registration_handle_init`]'s owner requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_handle_wrapper_init(
    wrapper: *mut RegistrationHandleWrapper,
    context: *mut u8,
    selector_first: u32,
    selector_second: u32,
) -> *mut RegistrationHandleWrapper {
    (*wrapper).vtable = REGISTRATION_HANDLE_WRAPPER_VTABLE;
    let selector = [selector_first, selector_second];
    let owner = if context.is_null() {
        core::ptr::null_mut()
    } else {
        context.add(0xa0c)
    };
    registration_handle_init(&mut (*wrapper).registration, owner, 2, selector.as_ptr());
    wrapper
}

/// Restores the wrapper vtable and destroys its embedded registration handle.
///
/// # Safety
///
/// `wrapper` must be valid and aligned. Its embedded registration must meet
/// [`registration_handle_destroy`]'s requirements, including its unguarded
/// owner requirement when `slot_index != -1`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_handle_wrapper_destroy(
    wrapper: *mut RegistrationHandleWrapper,
) -> *mut RegistrationHandleWrapper {
    (*wrapper).vtable = REGISTRATION_HANDLE_WRAPPER_VTABLE;
    registration_handle_destroy(&mut (*wrapper).registration);
    wrapper
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;


    #[test]
    fn init_with_null_context_restores_wrapper_and_base_sentinels() {
        let mut wrapper = RegistrationHandleWrapper {
            vtable: 0xdead_beef,
            registration: RegistrationHandle {
                vtable: 0xcafe_babe,
                owner: 1usize as *mut u8,
                slot_index: 27,
            },
        };

        let returned = unsafe {
            registration_handle_wrapper_init(
                &mut wrapper,
                core::ptr::null_mut(),
                31,
                0xfeed_face,
            )
        };

        assert!(core::ptr::eq(returned, &mut wrapper));
        assert_eq!(wrapper.vtable, REGISTRATION_HANDLE_WRAPPER_VTABLE);
        assert_eq!(
            wrapper.registration.vtable,
            crate::app::registration_handle::REGISTRATION_HANDLE_VTABLE,
        );
        assert!(wrapper.registration.owner.is_null());
        assert_eq!(wrapper.registration.slot_index, -1);
    }
    #[test]
    fn minus_one_restores_both_vtables_and_returns_wrapper() {
        let mut wrapper = RegistrationHandleWrapper {
            vtable: 0xdead_beef,
            registration: RegistrationHandle {
                vtable: 0xcafe_babe,
                owner: core::ptr::null_mut(),
                slot_index: -1,
            },
        };

        let returned = unsafe { registration_handle_wrapper_destroy(&mut wrapper) };

        assert!(core::ptr::eq(returned, &mut wrapper));
        assert_eq!(wrapper.vtable, REGISTRATION_HANDLE_WRAPPER_VTABLE);
        assert_eq!(
            wrapper.registration.vtable,
            crate::app::registration_handle::REGISTRATION_HANDLE_VTABLE,
        );
    }
}
