//! Selects a directional-resource provider and constructs matching records.
//!
//! # Original
//!
//! `FUN_08184794` @ 0x08184794 is exactly 104 bytes
//! (`0x08184794..0x081847fb`); `push {r4-r8,lr}` at 0x081847fc starts the next
//! separately linked function. Raw ARM contains two unconditional direct `bl`,
//! one indirect `blx`, and one unconditional plain-`b` tail call: three call
//! instructions total, with no predicated calls. It selects the controller's
//! provider through vtable slot +0xe4, downcasts it to class 0x1700, resolves a
//! command record, then constructs directional-resource records in both that
//! record and the controller's +0x88 record.
//!
//! # Deliberate deviations
//!
//! The selector's virtual callee has no recovered semantic identity. Device
//! builds preserve its target-width vtable dispatch; host tests use the narrow
//! `DIRECTIONAL_PROVIDER_SELECTOR` seam. The final ARM tail branch is an
//! ordinary Rust call, retaining its returned pointer.

use crate::app::controller_pending_command::{command_record_resolve_or_allocate, AppControllerPendingCommand};
#[cfg(test)]
use crate::app::controller_pending_command::PendingCommandRecord;
use crate::app::directional_resource_record_construct::{directional_resource_record_construct, DirectionalResourceProvider, DirectionalResourceRecord};
use crate::app::registry::object_cast_to_class;

const PROVIDER_CLASS: u32 = 0x1700;
type SelectDirectionalProvider = unsafe extern "C" fn(*mut u32) -> *mut DirectionalResourceProvider;

#[cfg(target_os = "none")]
unsafe extern "C" fn select_directional_provider(controller: *mut u32) -> *mut DirectionalResourceProvider {
    let object = *controller.add(0x34 / 4) as *mut *const u32;
    let dispatch: unsafe extern "C" fn(*mut *const u32) -> *mut DirectionalResourceProvider =
        core::mem::transmute(*(*object).add(0xe4 / 4) as usize);
    dispatch(object)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_directional_provider_selector(_: *mut u32) -> *mut DirectionalResourceProvider {
    panic!("host tests must install the directional-provider selector seam")
}

#[cfg(not(target_os = "none"))]
pub static mut DIRECTIONAL_PROVIDER_SELECTOR: SelectDirectionalProvider = missing_directional_provider_selector;

#[cfg(not(target_os = "none"))]
unsafe fn select_directional_provider(controller: *mut u32) -> *mut DirectionalResourceProvider {
    core::ptr::read_volatile(core::ptr::addr_of!(DIRECTIONAL_PROVIDER_SELECTOR))(controller)
}

/// controller_directional_command — original: `FUN_08184794` @ `0x08184794`.
///
/// # Safety
///
/// `controller` must be valid through +0x88 and +0x34. When the selected
/// provider and `command` are non-NULL, the provider must implement class
/// 0x1700 and all record-construction dependencies must accept their inputs.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_directional_command(
    controller: *mut AppControllerPendingCommand,
    command: u32,
    argument: u32,
) -> *mut DirectionalResourceRecord {
    let provider = select_directional_provider(controller.cast());
    if provider.is_null() || command == 0 {
        return provider.cast();
    }
    let provider = object_cast_to_class(provider.cast(), PROVIDER_CLASS).cast::<DirectionalResourceProvider>();
    if provider.is_null() {
        return core::ptr::null_mut();
    }
    let record = command_record_resolve_or_allocate(controller, command, argument, 1)
        .cast::<DirectionalResourceRecord>();
    directional_resource_record_construct(record, provider, 0, 0);
    directional_resource_record_construct(
        core::ptr::addr_of_mut!((*controller).pending_command).cast::<DirectionalResourceRecord>(),
        provider,
        0,
        0,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static SELECTOR_LOCK: Mutex<()> = Mutex::new(());
    static mut SELECTED: *mut DirectionalResourceProvider = ptr::null_mut();
    static mut SELECTOR_CALLS: usize = 0;

    unsafe extern "C" fn select(_: *mut u32) -> *mut DirectionalResourceProvider {
        SELECTOR_CALLS += 1;
        SELECTED
    }

    fn controller() -> AppControllerPendingCommand {
        AppControllerPendingCommand {
            opaque_00_3b: [0; 15], record_map_word: 0, opaque_40_87: [0; 18],
            pending_command: PendingCommandRecord { arg2: 1, arg3: 2, state: 3, aux: 4 },
        }
    }

    #[test]
    fn null_selected_provider_returns_null_without_resolving_command() {
        let _guard = SELECTOR_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            SELECTED = ptr::null_mut(); SELECTOR_CALLS = 0;
            DIRECTIONAL_PROVIDER_SELECTOR = select;
            assert!(controller_directional_command(&mut controller(), 0x1234, 0).is_null());
            assert_eq!(SELECTOR_CALLS, 1);
            DIRECTIONAL_PROVIDER_SELECTOR = missing_directional_provider_selector;
        }
    }

    #[test]
    fn zero_command_returns_selected_provider_without_constructing_records() {
        let _guard = SELECTOR_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut provider_words = [0u32; 1];
        unsafe {
            SELECTED = provider_words.as_mut_ptr().cast(); SELECTOR_CALLS = 0;
            DIRECTIONAL_PROVIDER_SELECTOR = select;
            assert_eq!(controller_directional_command(&mut controller(), 0, 0xfeed), SELECTED.cast());
            assert_eq!(SELECTOR_CALLS, 1);
            DIRECTIONAL_PROVIDER_SELECTOR = missing_directional_provider_selector;
        }
    }
}
