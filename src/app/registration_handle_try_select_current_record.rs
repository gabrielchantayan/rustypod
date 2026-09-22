//! `registration_handle_try_select_current_record` — original: `FUN_0820d5ec`
//! @ `0x0820d5ec` (**140 bytes**, `0x0820d5ec..0x0820d678`; the next real
//! function begins at `0x0820d678`).
//!
//! Raw ARM decoding finds **3 plain, unconditional inbound `bl` calls**
//! (0x0820a10c, 0x0820a16c, and 0x0821bf94) and **0 predicated direct `bl`
//! calls**. The body has six unconditional direct `bl` instructions (wrapper
//! initialization, current-record lookup, either of two wrapper destructions,
//! `registration_handle_current_status_is_nonzero`, and the status helper)
//! plus one indirect `blx` through vtable slot `+0x20`.
//!
//! # Algorithm
//!
//! Initialize a temporary registration-handle wrapper from the context word and
//! two selector words. A missing current record returns one. Otherwise invoke
//! the record's slot `+0x20` command with the caller's third argument and mode
//! one. A nonzero command result invokes the status wrapper with its final
//! selector forced to zero and returns one; a zero result invokes the
//! registration-maintenance helper, destroys the wrapper, and returns zero.
//! Deliberate deviation: the target's vtable slot is represented by a typed
//! host vtable field. `#[repr(C)]` keeps its ARM offset at `+0x20`; on a
//! 64-bit host the preceding slots widen together, preserving semantic slot
//! selection without assuming host pointer byte offsets.

#[cfg(target_os = "none")]
use crate::app::current_record_handle::{current_record_handle_from_owner, CurrentRecordCursorOwner};
use crate::app::registration_handle_current_status::registration_handle_current_status_is_nonzero;
use crate::app::registration_handle_wrapper::{
    registration_handle_wrapper_destroy, registration_handle_wrapper_init, RegistrationHandleWrapper,
};

/// Recovered vtable prefix for the current registration record.
#[repr(C)]
pub struct RegistrationSelectionTargetVtable {
    pub preceding_slots: [usize; 8],
    pub command: unsafe extern "C" fn(*mut RegistrationSelectionTarget, u32, u32) -> i32,
}

/// A current registration record whose command is at vtable byte offset `+0x20`.
#[repr(C)]
pub struct RegistrationSelectionTarget {
    pub vtable: *const RegistrationSelectionTargetVtable,
}

#[inline(always)]
unsafe fn registration_selection_command(
    target: *mut RegistrationSelectionTarget,
    command: u32,
) -> i32 {
    ((*(*target).vtable).command)(target, command, 1)
}
#[cfg(target_os = "none")]
unsafe fn registration_maintenance(context: *mut u8) {
    let maintenance: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x081c_869cusize);
    maintenance(context);
}

#[cfg(not(target_os = "none"))]
unsafe fn registration_maintenance(_context: *mut u8) {
    // The direct retailOS helper at 0x081c869c is not host-linkable.
}


/// registration_handle_try_select_current_record — original: `FUN_0820d5ec` @
/// `0x0820d5ec` (140 bytes; 3 unconditional direct `bl` call sites, 0
/// predicated direct `bl` call sites).
///
/// Attempts the current record's mode-one command. Returns zero only when a
/// current record accepts `command`; all other paths return one. `selector_second`
/// is forwarded in r3 to wrapper initialization exactly as in the original.
///
/// # Safety
///
/// `context_source` must identify a readable context pointer. A non-NULL
/// context and any selected record must satisfy the unchecked pointer and
/// vtable requirements of the called retailOS helpers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_handle_try_select_current_record(
    context_source: *const *mut u8,
    selector_first: u32,
    command: u32,
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
    ) as usize as *mut RegistrationSelectionTarget;
    #[cfg(not(target_os = "none"))]
    let target = if wrapper.registration.slot_index == -1 {
        core::ptr::null_mut()
    } else {
        let record = (wrapper.registration.owner as usize)
            .wrapping_add((wrapper.registration.slot_index as usize).wrapping_mul(0x14));
        (record.wrapping_add(4) as *const u32).read() as usize as *mut RegistrationSelectionTarget
    };

    if target.is_null() {
        registration_handle_wrapper_destroy(wrapper);
        return 1;
    }

    if registration_selection_command(target, command) != 0 {
        registration_handle_current_status_is_nonzero(context_source, selector_first, 0);
        registration_handle_wrapper_destroy(wrapper);
        return 1;
    }

    registration_maintenance(context);
    registration_handle_wrapper_destroy(wrapper);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut OBSERVED_TARGET: *mut RegistrationSelectionTarget = core::ptr::null_mut();
    static mut OBSERVED_COMMAND: u32 = 0;
    static mut OBSERVED_MODE: u32 = 0;

    unsafe extern "C" fn recording_command(
        target: *mut RegistrationSelectionTarget,
        command: u32,
        mode: u32,
    ) -> i32 {
        OBSERVED_TARGET = target;
        OBSERVED_COMMAND = command;
        OBSERVED_MODE = mode;
        0
    }

    #[test]
    fn missing_current_record_returns_one_for_any_selector_and_command() {
        let context = core::ptr::null_mut();
        assert_eq!(unsafe {
            registration_handle_try_select_current_record(&context, 0, 0, 0)
        }, 1);
        assert_eq!(unsafe {
            registration_handle_try_select_current_record(&context, u32::MAX, 0xfeed_face, 7)
        }, 1);
    }

    #[test]
    fn command_dispatch_uses_slot_20_and_mode_one() {
        let vtable = RegistrationSelectionTargetVtable {
            preceding_slots: [0; 8],
            command: recording_command,
        };
        let mut target = RegistrationSelectionTarget { vtable: &vtable };
        unsafe {
            OBSERVED_TARGET = core::ptr::null_mut();
            OBSERVED_COMMAND = 0;
            OBSERVED_MODE = 0;
            assert_eq!(registration_selection_command(&mut target, 0xfeed_face), 0);
            assert!(core::ptr::eq(OBSERVED_TARGET, &mut target));
            assert_eq!(OBSERVED_COMMAND, 0xfeed_face);
            assert_eq!(OBSERVED_MODE, 1);
        }
    }
}
