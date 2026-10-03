//! Restore the internal display's layer 5 and deactivate an optional layout.
//!
//! `FUN_0821f460` @ 0x0821f460: 60 bytes, through 0x0821f498;
//! the independent `bx lr` at 0x0821f49c is the next function boundary.
//! Raw ARM decoding: five plain BLs, zero predicated BLs, one BNE tail
//! transfer. Incoming calls: two plain BLs, zero predicated BLs.
//! Fetch display 0, enable layer 5, fetch display 0 again and refresh it,
//! then load the layout pointer at +0xc8 and deactivate it if non-NULL.
//! Ghidra incorrectly inlines the tail callee. Deliberate deviations:
//! host pointer fields use native width; the target retains offset +0xc8.
//! The unported refresh operation stays a firmware seam at 0x081d8af8.

use crate::drivers::display::{display_get, display_get_layer, Display};
use crate::drivers::display_layer::layer_enable;
use crate::app::layout_state::deactivate_layout_state;

#[repr(C)]
pub struct DisplayLayoutContext {
    pub unresolved_00_c7: [u32; 50],
    pub layout: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xc8] = [0; core::mem::offset_of!(DisplayLayoutContext, layout)];

unsafe extern "C" fn firmware_display_refresh(display: *mut Display) {
    #[cfg(target_os = "none")]
    {
        let refresh: unsafe extern "C" fn(*mut Display) = unsafe { core::mem::transmute(0x081d8af8usize) };
        unsafe { refresh(display) };
    }
    #[cfg(not(target_os = "none"))]
    { let _ = display; panic!("display refresh requires firmware 0x081d8af8"); }
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    get: unsafe extern "C" fn(u32) -> *mut Display,
    layer: unsafe extern "C" fn(*mut Display, u32) -> *mut u8,
    enable: unsafe extern "C" fn(*mut u8),
    refresh: unsafe extern "C" fn(*mut Display),
    deactivate: unsafe extern "C" fn(*mut u8),
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    get: display_get, layer: display_get_layer, enable: layer_enable,
    refresh: firmware_display_refresh, deactivate: deactivate_layout_state,
};

/// # Safety
/// `context` must be valid throughout all callbacks; its non-NULL layout must
/// satisfy `deactivate_layout_state`'s contract. Display/layer services must
/// be initialized. The layout is deliberately read only after refresh.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn restore_display_layout(context: *mut DisplayLayoutContext) {
    #[cfg(target_os = "none")]
    let (get, layer, enable, refresh, deactivate) = (
        display_get, display_get_layer, layer_enable,
        firmware_display_refresh, deactivate_layout_state,
    );
    #[cfg(not(target_os = "none"))]
    let HostOps { get, layer, enable, refresh, deactivate } = unsafe { HOST_OPS };
    unsafe {
        enable(layer(get(0), 5));
        refresh(get(0));
        let layout = core::ptr::addr_of!((*context).layout).read();
        if !layout.is_null() { deactivate(layout); }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONTEXT: *mut DisplayLayoutContext = core::ptr::null_mut();
    static mut REPLACEMENT: *mut u8 = core::ptr::null_mut();
    static mut ENABLED: bool = false;
    static mut REFRESHED: bool = false;
    static mut DEACTIVATED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn get(id: u32) -> *mut Display {
        assert_eq!(id, 0);
        core::ptr::null_mut()
    }
    unsafe extern "C" fn layer(_: *mut Display, index: u32) -> *mut u8 {
        assert_eq!(index, 5);
        core::ptr::null_mut()
    }
    unsafe extern "C" fn enable(_: *mut u8) { unsafe { ENABLED = true; } }
    unsafe extern "C" fn refresh(_: *mut Display) {
        unsafe {
            assert!(ENABLED);
            (*CONTEXT).layout = REPLACEMENT;
            REFRESHED = true;
        }
    }
    unsafe extern "C" fn deactivate(layout: *mut u8) {
        unsafe { assert!(REFRESHED); DEACTIVATED = layout; }
    }

    // A refresh callback can replace or remove the current layout. Loading
    // +0xc8 early would deactivate a stale object, or miss the new one.
    #[test]
    fn refresh_replacement_and_removal_control_deactivation() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut old = [0u8; 128];
        let mut new = [0u8; 128];
        unsafe {
            let saved = HOST_OPS;
            HOST_OPS = HostOps { get, layer, enable, refresh, deactivate };
            for (initial, replacement) in [
                (core::ptr::null_mut(), new.as_mut_ptr()),
                (old.as_mut_ptr(), new.as_mut_ptr()),
                (old.as_mut_ptr(), core::ptr::null_mut()),
                (core::ptr::null_mut(), core::ptr::null_mut()),
            ] {
                let mut context = DisplayLayoutContext { unresolved_00_c7: [0; 50], layout: initial };
                CONTEXT = &mut context;
                REPLACEMENT = replacement;
                ENABLED = false;
                REFRESHED = false;
                DEACTIVATED = core::ptr::null_mut();
                restore_display_layout(&mut context);
                assert!(ENABLED && REFRESHED);
                assert_eq!(DEACTIVATED, replacement);
            }
            HOST_OPS = saved;
            CONTEXT = core::ptr::null_mut();
        }
    }
}
