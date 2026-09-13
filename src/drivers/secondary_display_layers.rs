//! Secondary-display layer setup — `FUN_082058e0` @ `0x082058e0`.
//!
//! Raw `osos.dec` establishes a 204-byte extent: 200 instruction bytes from
//! `0x082058e0..0x082059a8`, followed by the `0x00108080` literal consumed by
//! the `ldr` at `0x0820595c`; the separately linked configuration copier opens
//! at `0x082059ac`. Ghidra's reported 200 bytes omits that literal-pool word.
//! Decoding every ARM `BL` immediate finds seven direct callers, all plain
//! unconditional `bl` (none predicated): `0x08147b94`, `0x08147cd8`,
//! `0x08147e40`, `0x0815ed84`, `0x081a26ac`, `0x081b9fc0`, and `0x081fb360`.
//!
//! It obtains secondary-display layers 0 and 5, initializes a 64-byte surface
//! descriptor for each, applies the format inputs embedded in `setup`, clears
//! the display to `0x00108080`, commits pending nibbles `(1, 15, 0, 0, 0)`,
//! and selects global-alpha blending on both layers.
//!
//! # Deliberate deviation
//!
//! `FUN_081d8d0c` is absent from `names.yaml`. Its verified ABI is reused from
//! `ui/display_pending_nibbles`: target builds reach its exact address through
//! that module's established seam, while host tests install a recorder.

use core::mem::MaybeUninit;

use super::{
    display::{display_get, display_get_layer, display_set_clear_color, SECONDARY_DISPLAY_ID},
    display_layer::{layer_apply_config, layer_set_global_alpha_blend},
    surface::surface_config_init,
};
use crate::ui::display_pending_nibbles::set_display_pending_nibbles;

/// The format byte at `input + 8`, the only input field this routine reads.
#[repr(C)]
pub struct LayerFormatInput {
    reserved_0_7: [u8; 8],
    pixel_format: u8,
}

/// Owner layout read and written by [`configure_secondary_display_layers`].
///
/// Named pointer fields retain their four-byte target spacing without making
/// 64-bit host fixtures overlap. `surface_width` and `surface_height` are
/// copied to both layer descriptors rather than being read from either input.
#[repr(C)]
pub struct SecondaryDisplayLayerSetup {
    reserved_0_17: [u8; 0x18],
    layer5_input: *const LayerFormatInput,
    layer0_input: *const LayerFormatInput,
    pub layer0: *mut u8,
    pub layer5: *mut u8,
    surface_width: u32,
    surface_height: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(SecondaryDisplayLayerSetup, layer5_input)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(SecondaryDisplayLayerSetup, layer0_input)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(SecondaryDisplayLayerSetup, layer0)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::offset_of!(SecondaryDisplayLayerSetup, layer5)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(SecondaryDisplayLayerSetup, surface_width)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x2c] = [0; core::mem::offset_of!(SecondaryDisplayLayerSetup, surface_height)];

/// Reproduces the separately linked `FUN_082059ac` inline, avoiding a second
/// exported port for a helper used only to prepare this routine's descriptors.
#[inline(always)]
unsafe fn copy_layer_format(input: *const LayerFormatInput, setup: *const SecondaryDisplayLayerSetup, config: *mut u8) {
    let pixel_format = core::ptr::addr_of!((*input).pixel_format).read_volatile();
    let width = core::ptr::addr_of!((*setup).surface_width).read_volatile();
    let height = core::ptr::addr_of!((*setup).surface_height).read_volatile();

    config.write_volatile(pixel_format);
    config.add(1).write_volatile(3);
    match pixel_format {
        0 => {
            config.add(0x30).write_volatile(0x10);
            config.add(0x31).write_volatile(0);
            config.add(0x32).write_volatile(0);
        }
        2 => (config.add(0x30) as *mut u16).write_volatile(0x1f),
        3 => (config.add(0x30) as *mut u32).write_volatile(0),
        _ => {}
    }
    (config.add(0x10) as *mut u32).write_volatile(height);
    (config.add(0x0c) as *mut u32).write_volatile(width);
    (config.add(0x18) as *mut u32).write_volatile(height);
    (config.add(0x14) as *mut u32).write_volatile(width);
    (config.add(0x28) as *mut u32).write_volatile(0);
    (config.add(0x24) as *mut u32).write_volatile(0);
    (config.add(4) as *mut u32).write_volatile(0);
    (config.add(8) as *mut u32).write_volatile(0);
}

/// configure_secondary_display_layers — original: `FUN_082058e0` @
/// `0x082058e0` (204 bytes including its literal-pool word; **7 direct,
/// unconditional `bl` call sites and no predicated calls**).
///
/// Configures secondary-display layers 0 and 5 from the two format inputs in
/// `setup`, retaining their returned pointers, then requests the fixed clear
/// color and pending-nibble state.
///
/// # Safety
///
/// `setup`, its two inputs, and the secondary display/layer objects must be
/// live. As in ARM, there are no NULL or bounds checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn configure_secondary_display_layers(setup: *mut SecondaryDisplayLayerSetup) {
    let display = display_get(SECONDARY_DISPLAY_ID as u32);
    let layer0 = display_get_layer(display, 0);
    core::ptr::addr_of_mut!((*setup).layer0).write_volatile(layer0);
    let layer5 = display_get_layer(display, 5);
    core::ptr::addr_of_mut!((*setup).layer5).write_volatile(layer5);

    let mut layer0_config = MaybeUninit::<[u8; 64]>::uninit();
    let mut layer5_config = MaybeUninit::<[u8; 64]>::uninit();
    let layer0_config = layer0_config.as_mut_ptr().cast::<u8>();
    let layer5_config = layer5_config.as_mut_ptr().cast::<u8>();
    surface_config_init(layer0_config);
    surface_config_init(layer5_config);
    copy_layer_format((*setup).layer0_input, setup, layer0_config);
    copy_layer_format((*setup).layer5_input, setup, layer5_config);
    layer_apply_config(layer0, layer0_config);
    layer_apply_config(layer5, layer5_config);
    display_set_clear_color(display, 0x0010_8080);
    let pending_nibbles = [15, 0, 0, 0];
    set_display_pending_nibbles(display, 1, pending_nibbles.as_ptr());
    layer_set_global_alpha_blend(layer5);
    layer_set_global_alpha_blend(layer0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::display::{Display, SECONDARY_DISPLAY, SECONDARY_DISPLAY_GUARD};
    use crate::kernel::sync_mutex::Mutex;
    use crate::ui::display_pending_nibbles::{DisplaySetPendingNibbles, DISPLAY_PENDING_NIBBLES_TEST_LOCK, DISPLAY_SET_PENDING_NIBBLES};
    use std::sync::MutexGuard;

    const LAYER_PIXEL_FORMAT: usize = 0x0a;
    const LAYER_WIDTH: usize = 0x1c;
    const LAYER_HEIGHT: usize = 0x20;
    const LAYER_BUFFER_HEIGHT: usize = 0x2c;
    const LAYER_BUFFER_WIDTH: usize = 0x30;
    const LAYER_OPAQUE: usize = 0x3c;
    const LAYER_BLEND_MODE: usize = 0x49;
    const LAYER_DIRTY: usize = 0x1bc;

    #[repr(align(8))]
    struct Layer([u8; 0x1d8]);

    static mut PENDING_NIBBLES: Option<(*mut Display, u8, [u8; 4])> = None;

    unsafe extern "C" fn record_pending_nibbles(display: *mut Display, selector: u8, nibbles: *const u8) {
        PENDING_NIBBLES = Some((display, selector, [
            nibbles.read_volatile(), nibbles.add(1).read_volatile(),
            nibbles.add(2).read_volatile(), nibbles.add(3).read_volatile(),
        ]));
    }

    unsafe fn word(bytes: *const u8, offset: usize) -> u32 {
        (bytes.add(offset) as *const u32).read_volatile()
    }

    #[test]
    fn configures_secondary_layers_and_commits_fixed_display_state() {
        let display_guard = crate::drivers::display::DISPLAY_TEST_LOCK.lock();
        let pending_guard: MutexGuard<'static, ()> = DISPLAY_PENDING_NIBBLES_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut layer0 = Layer([0; 0x1d8]);
        let mut layer5 = Layer([0; 0x1d8]);
        let mut layer0_input = LayerFormatInput { reserved_0_7: [0; 8], pixel_format: 0 };
        let mut layer5_input = LayerFormatInput { reserved_0_7: [0; 8], pixel_format: 2 };
        let mut setup = SecondaryDisplayLayerSetup {
            reserved_0_17: [0; 0x18], layer5_input: &layer5_input, layer0_input: &layer0_input,
            layer0: core::ptr::null_mut(), layer5: core::ptr::null_mut(), surface_width: 320, surface_height: 240,
        };

        unsafe {
            let display = core::ptr::addr_of_mut!(SECONDARY_DISPLAY);
            (*display).layers = [core::ptr::null_mut(); 6];
            (*display).layers[0] = layer0.0.as_mut_ptr();
            (*display).layers[5] = layer5.0.as_mut_ptr();
            (*display).clear_pending = 0;
            (*display).clear_color = 0;
            (*display).mutex = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };
            SECONDARY_DISPLAY_GUARD = 1;
            let saved: DisplaySetPendingNibbles = core::ptr::read_volatile(core::ptr::addr_of!(DISPLAY_SET_PENDING_NIBBLES));
            DISPLAY_SET_PENDING_NIBBLES = record_pending_nibbles;
            PENDING_NIBBLES = None;

            configure_secondary_display_layers(&mut setup);

            assert_eq!(setup.layer0, layer0.0.as_mut_ptr());
            assert_eq!(setup.layer5, layer5.0.as_mut_ptr());
            assert_eq!(PENDING_NIBBLES, Some((display, 1, [15, 0, 0, 0])));
            assert_eq!((*display).clear_pending, 1);
            assert_eq!((*display).clear_color, 0x0010_8080);
            assert_eq!(layer0.0[LAYER_PIXEL_FORMAT], 0);
            assert_eq!(word(layer0.0.as_ptr(), LAYER_WIDTH), 320);
            assert_eq!(word(layer0.0.as_ptr(), LAYER_HEIGHT), 240);
            assert_eq!(word(layer0.0.as_ptr(), LAYER_BUFFER_WIDTH), 320);
            assert_eq!(word(layer0.0.as_ptr(), LAYER_BUFFER_HEIGHT), 240);
            assert_eq!(word(layer0.0.as_ptr(), LAYER_OPAQUE), 0x10);
            assert_eq!(layer5.0[LAYER_PIXEL_FORMAT], 2);
            assert_eq!(word(layer5.0.as_ptr(), LAYER_OPAQUE), 0x1f);
            assert_eq!(layer0.0[LAYER_BLEND_MODE], 1);
            assert_eq!(layer5.0[LAYER_BLEND_MODE], 1);
            assert_eq!(layer0.0[LAYER_DIRTY], 1);
            assert_eq!(layer5.0[LAYER_DIRTY], 1);

            layer0_input.pixel_format = 3;
            layer5_input.pixel_format = 0xff;
            configure_secondary_display_layers(&mut setup);
            assert_eq!(layer0.0[LAYER_PIXEL_FORMAT], 3);
            assert_eq!(word(layer0.0.as_ptr(), LAYER_OPAQUE), 0);
            assert_eq!(layer5.0[LAYER_PIXEL_FORMAT], 0xff);
            assert_eq!(word(layer5.0.as_ptr(), LAYER_OPAQUE), 0);

            DISPLAY_SET_PENDING_NIBBLES = saved;
            (*display).layers = [core::ptr::null_mut(); 6];
            (*display).clear_pending = 0;
            (*display).clear_color = 0;
            SECONDARY_DISPLAY_GUARD = 0;
        }
        drop(pending_guard);
        drop(display_guard);
    }

    #[test]
    fn setup_layout_matches_32_bit_firmware_fields() {
        #[cfg(target_pointer_width = "32")]
        assert_eq!(core::mem::size_of::<SecondaryDisplayLayerSetup>(), 0x30);
    }
}
