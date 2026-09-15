//! Controller-history selection helper — original `FUN_08292d1c` at
//! `0x08292d1c` (60 bytes: 56 code bytes plus its resource-id literal).
//!
//! # Verified call sites
//!
//! A complete raw ARM B/BL scan finds four unconditional `bl` callers
//! (`0x0813456c`, `0x0813f4bc`, `0x081a3fe4`, `0x081b4be8`) and one `blne`
//! caller (`0x0815cb50`); two sibling wrapper tail branches are not calls.
//!
//! # Algorithm
//!
//! If the selected resource is private controller history `0x0dad073a`, set
//! application-controller mode +0x80 to 6. Then forward all three arguments
//! to the adjacent selection body at `0x08292bd4`.
//!
//! # Deliberate deviations
//!
//! The adjacent body is unported. ARM builds call it through a literal veneer
//! rather than the retail tail branch; host builds use replaceable seams.

use crate::app::controller_history_select::CONTROLLER_HISTORY_RESOURCE_ID;

pub type ControllerHistorySelectCore = unsafe extern "C" fn(u32, u32, u32);
pub type AppControllerGet = unsafe extern "C" fn() -> *mut u8;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_controller_history_select_core(_: u32, _: u32, _: u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_app_controller_get() -> *mut u8 { core::ptr::null_mut() }

#[cfg(not(target_arch = "arm"))]
pub static mut CONTROLLER_HISTORY_SELECT_CORE: ControllerHistorySelectCore = missing_controller_history_select_core;
#[cfg(not(target_arch = "arm"))]
pub static mut APP_CONTROLLER_GET: AppControllerGet = missing_app_controller_get;

#[cfg(target_arch = "arm")]
extern "C" {
    fn app_controller_get() -> *mut u8;
    fn retail_controller_history_select_core(resource_id: u32, history_flag: u32, skip_callback: u32);
}

/// Selects a controller resource and optionally installs its history callback.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_history_select(resource_id: u32, history_flag: u32, skip_callback: u32) {
    if resource_id == CONTROLLER_HISTORY_RESOURCE_ID {
        #[cfg(target_arch = "arm")]
        let controller = app_controller_get();
        #[cfg(not(target_arch = "arm"))]
        let controller = core::ptr::read_volatile(core::ptr::addr_of!(APP_CONTROLLER_GET))();
        core::ptr::write(controller.add(0x80) as *mut u16, 6);
    }
    #[cfg(target_arch = "arm")]
    retail_controller_history_select_core(resource_id, history_flag, skip_callback);
    #[cfg(not(target_arch = "arm"))]
    core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_HISTORY_SELECT_CORE))(resource_id, history_flag, skip_callback);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
retail_controller_history_select_core:
    ldr pc, [pc, #-4]
    .word 0x08292bd4
"#);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED: Option<(u32, u32, u32)> = None;
    static mut CONTROLLER: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn controller_get() -> *mut u8 { CONTROLLER }
    unsafe extern "C" fn record_core(resource: u32, history: u32, skip: u32) {
        FORWARDED = Some((resource, history, skip));
    }

    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                CONTROLLER_HISTORY_SELECT_CORE = missing_controller_history_select_core;
                APP_CONTROLLER_GET = missing_app_controller_get;
                FORWARDED = None;
                CONTROLLER = ptr::null_mut();
            }
        }
    }

    #[test]
    fn private_history_sets_mode_and_forwards_flags() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;
        let mut controller = [0u8; 0x82];
        unsafe {
            CONTROLLER = controller.as_mut_ptr();
            APP_CONTROLLER_GET = controller_get;
            CONTROLLER_HISTORY_SELECT_CORE = record_core;
            controller_history_select(CONTROLLER_HISTORY_RESOURCE_ID, 1, 0);
            assert_eq!(ptr::read_unaligned(controller.as_ptr().add(0x80) as *const u16), 6);
            assert_eq!(FORWARDED, Some((CONTROLLER_HISTORY_RESOURCE_ID, 1, 0)));
        }
    }

    #[test]
    fn other_resource_preserves_mode_and_forwards_arguments() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;
        let mut controller = [0xa5u8; 0x82];
        unsafe {
            CONTROLLER = controller.as_mut_ptr();
            APP_CONTROLLER_GET = controller_get;
            CONTROLLER_HISTORY_SELECT_CORE = record_core;
            controller_history_select(0x1234_5678, 0, 1);
            assert_eq!(ptr::read_unaligned(controller.as_ptr().add(0x80) as *const u16), 0xa5a5);
            assert_eq!(FORWARDED, Some((0x1234_5678, 0, 1)));
        }
    }
}
