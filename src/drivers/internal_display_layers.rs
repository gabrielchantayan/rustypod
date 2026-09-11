//! Internal-display layer setup — `FUN_081f5c2c` @ `0x081f5c2c`.
//!
//! The 176-byte function is `0x081f5c2c..0x081f5cdc`: 44 instruction
//! words ending in `pop {r4,r5,pc}`; the separate configuration copier starts
//! at `0x081f5cdc`. Every ARM `bl` in `osos.dec` finds nine incoming calls,
//! all unconditional (0x0810dcfc, 0x0810ecf4, 0x08110218, 0x0811e6a0,
//! 0x08130728, 0x08144350, 0x081589d8, 0x0816dedc, 0x081df66c).
//!
//! It acquires internal display layers 1 and 5, builds a temporary
//! [`surface_config_init`]-shaped descriptor for each input at `this + 0x1c`
//! and `this + 0x18`, respectively, applies them, clears the display, sets
//! the display's unported `(3, 5)` pending parameters, and selects global
//! alpha blending on both layers. The stack descriptors deliberately retain
//! the initializer's unwritten bytes, just as the ARM stack locals do.
//!
//! # Deviation
//!
//! `FUN_081d9138` is not yet ported. Target builds call it through a volatile
//! function pointer to its verified load address; host tests replace that one
//! unported boundary with a recorder. The other six callees are already
//! ported and are called directly.

use core::mem::MaybeUninit;

use super::{
    display::{display_get, display_get_layer, display_set_clear_color, Display},
    display_layer::{layer_apply_config, layer_set_global_alpha_blend},
    surface::surface_config_init,
};

/// The input record at `this + 0x18` / `this + 0x1c`.
///
/// Both input words have established byte offsets but not an established
/// domain meaning. The configuration copier swaps them into the descriptor's
/// width/height pairs, so names preserve their observed locations.
#[repr(C)]
pub struct LayerConfigInput {
    reserved_0_7: [u8; 8],
    pixel_format: u8,
    reserved_9_b: [u8; 3],
    word_c: u32,
    word_10: u32,
}

/// The owner layout read and written by [`configure_internal_display_layers`].
///
/// Named pointer fields retain their four-byte target spacing without making
/// a 64-bit host fixture overlap them.
#[repr(C)]
pub struct InternalDisplayLayerSetup {
    reserved_0_17: [u8; 0x18],
    layer5_input: *const LayerConfigInput,
    layer1_input: *const LayerConfigInput,
    pub layer1: *mut u8,
    pub layer5: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(InternalDisplayLayerSetup, layer5_input)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(InternalDisplayLayerSetup, layer1_input)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(InternalDisplayLayerSetup, layer1)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::offset_of!(InternalDisplayLayerSetup, layer5)];

/// `FUN_081d9138` @ `0x081d9138`: stores its two byte arguments at display
/// `+0x54/+0x55` and raises the pending byte at `+0x24`.
type DisplayPendingParameters = unsafe extern "C" fn(*mut Display, u8, u8);

#[cfg(target_os = "none")]
static mut DISPLAY_PENDING_PARAMETERS_ADDRESS: usize = 0x081d_9138;

#[cfg(not(target_os = "none"))]
static mut DISPLAY_PENDING_PARAMETERS: DisplayPendingParameters = display_pending_parameters_stub;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn display_pending_parameters_stub(_display: *mut Display, _first: u8, _second: u8) {}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn set_display_pending_parameters(display: *mut Display, first: u8, second: u8) {
    let address = core::ptr::read_volatile(core::ptr::addr_of!(DISPLAY_PENDING_PARAMETERS_ADDRESS));
    let set: DisplayPendingParameters = core::mem::transmute(address);
    set(display, first, second);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn set_display_pending_parameters(display: *mut Display, first: u8, second: u8) {
    let set = core::ptr::read_volatile(core::ptr::addr_of!(DISPLAY_PENDING_PARAMETERS));
    set(display, first, second);
}

/// Reproduces the separately linked `FUN_081f5cdc` inline, avoiding a second
/// exported port for the helper that only prepares this function's stack
/// descriptors.
#[inline(always)]
unsafe fn copy_layer_config(input: *const LayerConfigInput, config: *mut u8) {
    let pixel_format = core::ptr::addr_of!((*input).pixel_format).read_volatile();
    let word_c = core::ptr::addr_of!((*input).word_c).read_volatile();
    let word_10 = core::ptr::addr_of!((*input).word_10).read_volatile();

    config.write_volatile(pixel_format);
    config.add(1).write_volatile(3);
    match pixel_format {
        0 => {
            config.add(0x30).write_volatile(0x10);
            config.add(0x31).write_volatile(0);
            config.add(0x32).write_volatile(0xff);
        }
        2 => (config.add(0x30) as *mut u16).write_volatile(0x1f),
        3 => (config.add(0x30) as *mut u32).write_volatile(0),
        _ => {}
    }
    (config.add(0x10) as *mut u32).write_volatile(word_c);
    (config.add(0x0c) as *mut u32).write_volatile(word_10);
    (config.add(0x18) as *mut u32).write_volatile(word_c);
    (config.add(0x14) as *mut u32).write_volatile(word_10);
    (config.add(0x28) as *mut u32).write_volatile(0);
    (config.add(0x24) as *mut u32).write_volatile(0);
    (config.add(4) as *mut u32).write_volatile(0);
    (config.add(8) as *mut u32).write_volatile(0);
}

/// configure_internal_display_layers — original: `FUN_081f5c2c` @
/// `0x081f5c2c` (176 bytes, `0x081f5c2c..0x081f5cdc`; **9 `bl` call sites,
/// all unconditional**).
///
/// Configures the internal LCD's layers 1 and 5 from the two descriptor inputs
/// embedded in `setup`, retaining their returned layer pointers, then clears
/// the display and requests the `(3, 5)` pending display state.
///
/// # Safety
///
/// `setup`, its two inputs, and the internal display/layer objects must be
/// live. As in ARM, there are no NULL or bounds checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn configure_internal_display_layers(setup: *mut InternalDisplayLayerSetup) {
    let display = display_get(0);
    let layer1 = display_get_layer(display, 1);
    core::ptr::addr_of_mut!((*setup).layer1).write_volatile(layer1);
    let layer5 = display_get_layer(display, 5);
    core::ptr::addr_of_mut!((*setup).layer5).write_volatile(layer5);

    let mut layer5_config = MaybeUninit::<[u8; 64]>::uninit();
    let mut layer1_config = MaybeUninit::<[u8; 64]>::uninit();
    let layer5_config = layer5_config.as_mut_ptr().cast::<u8>();
    let layer1_config = layer1_config.as_mut_ptr().cast::<u8>();
    surface_config_init(layer5_config);
    surface_config_init(layer1_config);
    copy_layer_config((*setup).layer1_input, layer1_config);
    copy_layer_config((*setup).layer5_input, layer5_config);
    layer_apply_config(layer1, layer1_config);
    layer_apply_config(layer5, layer5_config);
    display_set_clear_color(display, 0);
    set_display_pending_parameters(display, 3, 5);
    layer_set_global_alpha_blend(layer5);
    layer_set_global_alpha_blend(layer1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::display::{Display, DISPLAY_OBJECT_SIZE, INTERNAL_DISPLAY, INTERNAL_DISPLAY_GUARD};
    use std::sync::{Mutex as HostMutex, MutexGuard};

    const LAYER_PIXEL_FORMAT: usize = 0x0a;
    const LAYER_WIDTH: usize = 0x1c;
    const LAYER_HEIGHT: usize = 0x20;
    const LAYER_BUFFER_HEIGHT: usize = 0x2c;
    const LAYER_BUFFER_WIDTH: usize = 0x30;
    const LAYER_OPAQUE: usize = 0x3c;
    const LAYER_BLEND_MODE: usize = 0x49;
    const LAYER_DIRTY: usize = 0x1bc;
    use crate::kernel::sync_mutex::Mutex;

    static PENDING_PARAMETERS_LOCK: HostMutex<()> = HostMutex::new(());
    static mut PENDING_PARAMETERS: Option<(*mut Display, u8, u8)> = None;

    unsafe extern "C" fn record_pending_parameters(display: *mut Display, first: u8, second: u8) {
        PENDING_PARAMETERS = Some((display, first, second));
    }

    fn install_pending_parameters_recorder() -> MutexGuard<'static, ()> {
        let guard = PENDING_PARAMETERS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPLAY_PENDING_PARAMETERS = record_pending_parameters;
            PENDING_PARAMETERS = None;
        }
        guard
    }

    fn restore_pending_parameters_recorder(guard: MutexGuard<'static, ()>) {
        unsafe { DISPLAY_PENDING_PARAMETERS = display_pending_parameters_stub };
        drop(guard);
    }

    unsafe fn word(bytes: *const u8, offset: usize) -> u32 {
        (bytes.add(offset) as *const u32).read_volatile()
    }

    #[test]
    fn configures_both_layers_and_preserves_format_specific_opaque_words() {
        let display_guard = crate::drivers::display::DISPLAY_TEST_LOCK.lock();
        let pending_guard = install_pending_parameters_recorder();
        let mut layer1 = [0u8; 0x1d8];
        let mut layer5 = [0u8; 0x1d8];
        let mut layer1_input = LayerConfigInput {
            reserved_0_7: [0; 8], pixel_format: 0, reserved_9_b: [0; 3], word_c: 50, word_10: 20,
        };
        let mut layer5_input = LayerConfigInput {
            reserved_0_7: [0; 8], pixel_format: 2, reserved_9_b: [0; 3], word_c: 90, word_10: 30,
        };
        let mut setup = InternalDisplayLayerSetup {
            reserved_0_17: [0; 0x18], layer5_input: &layer5_input, layer1_input: &layer1_input,
            layer1: core::ptr::null_mut(), layer5: core::ptr::null_mut(),
        };

        unsafe {
            let display = core::ptr::addr_of_mut!(INTERNAL_DISPLAY);
            (*display).layers = [core::ptr::null_mut(); 6];
            (*display).layers[1] = layer1.as_mut_ptr();
            (*display).layers[5] = layer5.as_mut_ptr();
            (*display).clear_pending = 0;
            (*display).mutex = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };
            (*display).clear_color = 0xffff_ffff;
            INTERNAL_DISPLAY_GUARD = 1;

            configure_internal_display_layers(&mut setup);

            assert_eq!(setup.layer1, layer1.as_mut_ptr());
            assert_eq!(setup.layer5, layer5.as_mut_ptr());
            assert_eq!(PENDING_PARAMETERS, Some((display, 3, 5)));
            assert_eq!((*display).clear_pending, 1);
            assert_eq!((*display).clear_color, 0);
            assert_eq!(layer1[LAYER_PIXEL_FORMAT], 0);
            assert_eq!(word(layer1.as_ptr(), LAYER_WIDTH), 20);
            assert_eq!(word(layer1.as_ptr(), LAYER_HEIGHT), 50);
            assert_eq!(word(layer1.as_ptr(), LAYER_BUFFER_WIDTH), 20);
            assert_eq!(word(layer1.as_ptr(), LAYER_BUFFER_HEIGHT), 50);
            assert_eq!(word(layer1.as_ptr(), LAYER_OPAQUE), 0x00ff_0010);
            assert_eq!(layer5[LAYER_PIXEL_FORMAT], 2);
            assert_eq!(word(layer5.as_ptr(), LAYER_OPAQUE), 0x1f);
            assert_eq!(layer1[LAYER_BLEND_MODE], 1);
            assert_eq!(layer5[LAYER_BLEND_MODE], 1);
            assert_eq!(layer1[LAYER_DIRTY], 1);
            assert_eq!(layer5[LAYER_DIRTY], 1);

            layer1_input.pixel_format = 3;
            layer5_input.pixel_format = 0xff;
            configure_internal_display_layers(&mut setup);
            assert_eq!(layer1[LAYER_PIXEL_FORMAT], 3);
            assert_eq!(word(layer1.as_ptr(), LAYER_OPAQUE), 0);
            assert_eq!(layer5[LAYER_PIXEL_FORMAT], 0xff);
            assert_eq!(word(layer5.as_ptr(), LAYER_OPAQUE), 0, "non-0/2/3 leaves surface_config_init's zero");

            (*display).layers = [core::ptr::null_mut(); 6];
            (*display).clear_pending = 0;
            (*display).clear_color = 0;
            INTERNAL_DISPLAY_GUARD = 0;
        }
        restore_pending_parameters_recorder(pending_guard);
        drop(display_guard);
    }

    #[test]
    fn setup_layout_matches_32_bit_firmware_fields() {
        assert_eq!(DISPLAY_OBJECT_SIZE, 0xa8);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(core::mem::size_of::<InternalDisplayLayerSetup>(), 0x28);
    }
}
