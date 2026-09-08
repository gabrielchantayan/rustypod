//! `app_controller_dispatch_layout` — original: `FUN_0821754c` @
//! `0x0821754c` (48 bytes; next entry `0x0821757c`; **20** unconditional
//! `bl` call sites and no plain-`b` or predicated call sites, verified by
//! decoding every ARM B/BL word in `work/firmware/osos.dec`).
//!
//! # Algorithm
//!
//! Retrieves the process-wide application controller, writes the halfword
//! value `5` at its `+0x80` mode field, then dispatches the caller-supplied
//! controller's vtable slot `+0x11c` with `(controller, layout)`. The incoming
//! controller is deliberately not replaced with the singleton: the raw ARM
//! retains it in `r4` while `app_controller_get` returns the separate object
//! whose mode it changes.
//!
//! # Deliberate deviations
//!
//! Firmware vtable words are 32-bit pointers. The host model gives the vtable
//! a structural pointer representation so its `+0x11c` slot stays separately
//! callable on 64-bit hosts; target-width assertions retain the firmware
//! offsets. The dynamic slot's identity is not recoverable from the static
//! image, so it is dispatched through the supplied object's vtable.

use crate::app::singletons::app_controller_get;

/// Application-controller view needed by [`app_controller_dispatch_layout`].
#[repr(C)]
pub struct AppController {
    /// +0x00: runtime vtable pointer.
    pub vtable: *const AppControllerVtable,
    /// +0x04..+0x7f: fields not touched by this wrapper.
    pub opaque_04_7f: [u8; 0x7c],
    /// +0x80: mode set to `5` before the layout dispatch.
    pub mode: u16,
}

/// Application-controller vtable portion observed by this wrapper.
#[repr(C)]
pub struct AppControllerVtable {
    /// Slots +0x00..+0x118, not dispatched here.
    pub unresolved_00_118: [usize; 71],
    /// +0x11c: receives the controller and the selected layout.
    pub dispatch_layout: unsafe extern "C" fn(*mut AppController, *mut u8),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x80] = [0; core::mem::offset_of!(AppController, mode)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x11c] = [0; core::mem::offset_of!(AppControllerVtable, dispatch_layout)];

/// app_controller_dispatch_layout — original: `FUN_0821754c` @ `0x0821754c`
/// (48 bytes; 20 unconditional `bl` call sites, binary-scanned).
///
/// Sets the process-wide controller's mode field to `5`, then dispatches
/// `controller` through vtable slot `+0x11c` with `layout`. Neither raw ARM
/// dereference has a NULL guard.
///
/// # Safety
///
/// `app_controller_get()` must return a valid [`AppController`], and
/// `controller` must have a readable vtable whose `+0x11c` entry accepts this
/// ABI. `layout` is passed through without validation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_controller_dispatch_layout(
    controller: *mut AppController,
    layout: *mut u8,
) {
    let global_controller = app_controller_get().cast::<AppController>();
    (*global_controller).mode = 5;

    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*controller).vtable));
    (vtable.as_ref().unwrap_unchecked().dispatch_layout)(controller, layout);
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::MutexGuard;

    static mut SEEN_CONTROLLER: *mut AppController = ptr::null_mut();
    static mut SEEN_LAYOUT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn record_layout_dispatch(controller: *mut AppController, layout: *mut u8) {
        SEEN_CONTROLLER = controller;
        SEEN_LAYOUT = layout;
    }

    static VTABLE: AppControllerVtable = AppControllerVtable {
        unresolved_00_118: [0; 71],
        dispatch_layout: record_layout_dispatch,
    };

    fn controller(vtable: *const AppControllerVtable, mode: u16) -> AppController {
        AppController { vtable, opaque_04_7f: [0xa5; 0x7c], mode }
    }

    fn lock_singletons() -> MutexGuard<'static, ()> {
        crate::app::singletons::SINGLETON_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    #[test]
    fn updates_the_global_mode_and_dispatches_the_supplied_controller() {
        let _guard = lock_singletons();
        let mut global = controller(ptr::null(), 0xbeef);
        let mut supplied = controller(&VTABLE, 0x1234);
        let mut layout = [0x5a; 3];

        unsafe {
            crate::app::singletons::APP_CONTROLLER = (&mut global as *mut AppController).cast();
            SEEN_CONTROLLER = ptr::null_mut();
            SEEN_LAYOUT = ptr::null_mut();

            app_controller_dispatch_layout(&mut supplied, layout.as_mut_ptr());

            assert_eq!(global.mode, 5, "the getter result receives the mode store");
            assert_eq!(supplied.mode, 0x1234, "the supplied controller is only dispatched");
            assert_eq!(SEEN_CONTROLLER, ptr::addr_of_mut!(supplied));
            assert_eq!(SEEN_LAYOUT, layout.as_mut_ptr());
            crate::app::singletons::APP_CONTROLLER = ptr::null_mut();
        }
    }
}
