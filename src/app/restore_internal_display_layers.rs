//! Restore internal-display layer state, `FUN_0821c500` @ 0x0821c500.
//! True extent: 196 bytes, 0x0821c500..0x0821c5c4; the next routine
//! begins with `cmp r1,#0`. Raw A32 decoding finds two incoming plain
//! BLs (0x0821d168, 0x0821df6c), no incoming predicated BLs; the body
//! contains 18 plain BLs, one BLNE, and a tail B to 0x081d8af8.
//! Return without display changes when volume-controller byte +0x90 is
//! nonzero. Otherwise acquire layers 0,1,2,3,5 in order, select pixel-alpha
//! blend for layer 0, make layer 5 opaque, enable layers 1..3, optionally
//! enable layer 0, then reacquire display 0 and refresh it.
//! Deviations: tail refresh uses the existing verified firmware seam;
//! existing singleton/display ports retain their documented initialization
//! limitations. Host-only operations substitute initialized objects.

use crate::app::singletons::volume_controller_get;
use crate::app::volume_controller_byte_at_90::volume_controller_byte_at_90;
use crate::app::restore_display_layout::firmware_display_refresh;
use crate::drivers::display::{display_get, display_get_layer, Display};
use crate::drivers::display_layer::{layer_enable, layer_set_alpha, layer_set_pixel_alpha_blend};

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    volume: unsafe extern "C" fn() -> *mut u8,
    display: unsafe extern "C" fn(u32) -> *mut Display,
    layer: unsafe extern "C" fn(*mut Display, u32) -> *mut u8,
    enable: unsafe extern "C" fn(*mut u8),
    refresh: unsafe extern "C" fn(*mut Display),
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    volume: volume_controller_get, display: display_get, layer: display_get_layer,
    enable: layer_enable, refresh: firmware_display_refresh,
};

/// # Safety
/// Singleton, display, and layer services must be initialized and return valid
/// objects for their respective operations. `context` is unused, including NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn restore_internal_display_layers(_context: *mut u8, enable_base: u32) {
    #[cfg(target_os = "none")]
    let (volume, display, layer, enable, refresh) = (
        volume_controller_get, display_get, display_get_layer, layer_enable, firmware_display_refresh,
    );
    #[cfg(not(target_os = "none"))]
    let HostOps { volume, display, layer, enable, refresh } = unsafe { HOST_OPS };
    unsafe {
        if volume_controller_byte_at_90(volume()) != 0 { return; }
        let base = layer(display(0), 0);
        let first = layer(display(0), 1);
        let second = layer(display(0), 2);
        let third = layer(display(0), 3);
        let overlay = layer(display(0), 5);
        layer_set_pixel_alpha_blend(base);
        layer_set_alpha(overlay, 255);
        enable(first);
        enable(second);
        enable(third);
        if enable_base != 0 { enable(base); }
        refresh(display(0));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut VOLUME: [u8; 0x91] = [0; 0x91];
    static mut LAYERS: [[u8; 0x1d8]; 6] = [[0; 0x1d8]; 6];
    static mut REFRESHES: u32 = 0;
    unsafe extern "C" fn volume() -> *mut u8 { core::ptr::addr_of_mut!(VOLUME).cast() }
    unsafe extern "C" fn display(id: u32) -> *mut Display {
        assert_eq!(id, 0);
        core::ptr::null_mut()
    }
    unsafe extern "C" fn layer(_: *mut Display, index: u32) -> *mut u8 {
        unsafe { core::ptr::addr_of_mut!(LAYERS).cast::<u8>().add(index as usize * 0x1d8) }
    }
    unsafe extern "C" fn enable(layer: *mut u8) {
        unsafe { layer.add(0x41).write(0); layer.add(0x43).write(1); layer.add(0x1bc).write(1); }
    }
    unsafe extern "C" fn refresh(_: *mut Display) { unsafe { REFRESHES += 1; } }

    #[test]
    fn inhibition_and_optional_base_preserve_unrelated_layers() {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = HOST_OPS;
            HOST_OPS = HostOps { volume, display, layer, enable, refresh };
            for inhibited in [0, 1, 2, 255] {
                for enable_base in [0, 1, 0x80000000, u32::MAX] {
                    VOLUME = [0; 0x91];
                    VOLUME[0x90] = inhibited;
                    LAYERS = [[0x5a; 0x1d8]; 6];
                    REFRESHES = 0;
                    let mut expected = [[0x5a; 0x1d8]; 6];
                    if inhibited == 0 {
                        expected[0][0x49] = 2;
                        expected[0][0x1bc] = 1;
                        expected[5][0x48] = 255;
                        expected[5][0x1bc] = 1;
                        for index in 0..4 {
                            if index != 0 || enable_base != 0 {
                                expected[index][0x41] = 0;
                                expected[index][0x43] = 1;
                                expected[index][0x1bc] = 1;
                            }
                        }
                    }
                    restore_internal_display_layers(core::ptr::null_mut(), enable_base);
                    assert_eq!(core::ptr::addr_of!(LAYERS).read(), expected);
                    assert_eq!(core::ptr::addr_of!(REFRESHES).read(), u32::from(inhibited == 0));
                }
            }
            HOST_OPS = saved;
        }
    }
}
