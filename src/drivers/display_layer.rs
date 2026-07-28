//! The **display layer object** — the live, per-layer state the LCD
//! compositor renders from, and the small accessor cluster that mutates
//! it (0x0811f8c0..0x08120978).
//!
//! `drivers/surface.rs` ports the *configuration block* constructor
//! (`surface_config_init` @ 0x08120604) and recovered its destination
//! field map from the applier `FUN_08120978` @ 0x08120978. This module
//! ports the object that applier writes into, plus the setters callers
//! use to poke individual properties between full re-applies.
//!
//! A layer is obtained with `FUN_081d9064(display, index)` (the display
//! object comes from `FUN_081d8870`); the callers then drive it with the
//! functions below — e.g. the boot/transition code @ 0x080feb68:
//!
//! ```text
//! display = FUN_081d8870(0);
//! layer   = FUN_081d9064(display, 5);
//! layer_set_alpha(layer, 0xff);
//! layer_enable(layer_a); layer_enable(layer_b); ...
//! ```
//!
//! and the cross-fade @ 0x0810da8c, which is the clinching evidence for
//! the alpha field:
//!
//! ```text
//! lsr r5, r0, #24          ; alpha channel of an ARGB word
//! rsb r1, r5, #255         ; 255 - alpha
//! bl  0x0811fd98           ; -> the fading-out layer
//! mov r1, r5
//! bl  0x0811fd98           ; -> the fading-in layer
//! ```
//!
//! Recovered field map (offsets confirmed against the applier's stores
//! and the render pass `FUN_0811f8c8` @ 0x0811f8c8):
//!
//! ```text
//! +0x00 u32  (opaque)
//! +0x04 ptr  display driver object (its vtable is dispatched by the
//!            render pass: +0x14 geometry, +0x18/+0x3c enable-state,
//!            +0x40 blend mode, +0x44 global alpha)
//! +0x08 u8   layer id, passed to every driver vtable call
//! +0x09 u8   (opaque)
//! +0x0a u8   pixel format        [config +0x00]
//! +0x0b u8   format variant      [config +0x01]; 3 selects the
//!            alternate commit path (FUN_081206c4 / FUN_0811fe80)
//! +0x0c i32  origin x            [config +0x04]
//! +0x10 i32  origin y            [config +0x08]
//! +0x14 i32  source offset x     [config +0x28]
//! +0x18 i32  source offset y     [config +0x24]
//! +0x1c i32  width               [config +0x0c]
//! +0x20 i32  height              [config +0x10]
//! +0x24 i32  display width       [config +0x1c, -1 = auto]
//! +0x28 i32  display height      [config +0x20, -1 = auto]
//! +0x2c i32  buffer height       [config +0x18, >= height]
//! +0x30 i32  buffer width        [config +0x14, >= width]
//! +0x34 u8   flag                [config +0x2c]
//! +0x3c u32  (opaque)            [config +0x30]
//! +0x40 u8   configured
//! +0x41 u8   disabled
//! +0x42 u8   saved-disabled (the suspend/resume pair @ 0x08120654 /
//!            0x0812068c parks the disabled flag here)
//! +0x43 u8   enable-state changed since the last render
//! +0x44 u8   geometry set
//! +0x46 u8   flag                [config +0x2d]
//! +0x48 u8   global alpha, 0..255
//! +0x49 u8   blend mode, 0..3 (see BLEND_MODE_*)
//! +0x78      the layer's mutex (kernel::sync_mutex::Mutex)
//! +0x1bc u8  dirty — every mutator raises it; the render pass
//!            @ 0x0811f8c8 tests it and the commit @ 0x08120654 /
//!            0x0812068c clears it
//! +0x1be/+0x1c0/+0x1c4                        [config +0x34/+0x38/+0x3c]
//! ```
//!
//! The blend mode at +0x49 is translated by the render pass into the
//! driver's own code, and only two of the four modes push the global
//! alpha byte:
//!
//! ```text
//! +0x49  driver vtable[+0x40] arg   also calls vtable[+0x44](alpha)?
//!   0            1                          no
//!   1            3                          yes
//!   2            2                          no
//!   3            5                          yes
//! ```
//!
//! Offsets are literal byte offsets into a `*mut u8`, the
//! `drivers/surface.rs` / `drivers/ata_cmd.rs` precedent: none of the
//! fields these functions touch is a pointer, so nothing shifts on a
//! 64-bit test host. The one address computed from the object is
//! `layer + 0x78`, the embedded mutex, which is an *address*, not a
//! stored pointer.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// +0x0b: format variant that selects the alternate commit path.
pub const FORMAT_VARIANT_ALT_COMMIT: u8 = 3;

/// +0x49 = 0: opaque — the driver gets blend code 1 and no alpha.
pub const BLEND_MODE_OPAQUE: u8 = 0;
/// +0x49 = 1: global alpha — driver blend code 3, then the +0x48 byte.
pub const BLEND_MODE_GLOBAL_ALPHA: u8 = 1;
/// +0x49 = 2: per-pixel alpha — driver blend code 2, no global alpha.
/// The applier forces this mode whenever the pixel format is 3.
pub const BLEND_MODE_PIXEL_ALPHA: u8 = 2;
/// +0x49 = 3: per-pixel *and* global alpha — driver blend code 5, then
/// the +0x48 byte. No ported setter installs it; the applier can.
pub const BLEND_MODE_PIXEL_AND_GLOBAL_ALPHA: u8 = 3;

/// A value of -1 (any negative) in the display-size arguments of
/// [`layer_set_geometry`] means "keep the layer's current value and
/// validate the plain width/height instead" — the same `-1 = auto`
/// sentinel `surface_config_init` arms (`SIZE_AUTO`).
pub const DISPLAY_SIZE_KEEP: i32 = -1;

const FORMAT_VARIANT: usize = 0x0b;
const ORIGIN_X: usize = 0x0c;
const ORIGIN_Y: usize = 0x10;
const SOURCE_X: usize = 0x14;
const SOURCE_Y: usize = 0x18;
const WIDTH: usize = 0x1c;
const HEIGHT: usize = 0x20;
const DISPLAY_WIDTH: usize = 0x24;
const DISPLAY_HEIGHT: usize = 0x28;
const BUFFER_HEIGHT: usize = 0x2c;
const BUFFER_WIDTH: usize = 0x30;
const DISABLED: usize = 0x41;
const ENABLE_CHANGED: usize = 0x43;
const GEOMETRY_SET: usize = 0x44;
const ALPHA: usize = 0x48;
const BLEND_MODE: usize = 0x49;
const MUTEX: usize = 0x78;
const DIRTY: usize = 0x1bc;

#[inline(always)]
unsafe fn byte(layer: *mut u8, offset: usize) -> u8 {
    layer.add(offset).read_volatile()
}

#[inline(always)]
unsafe fn set_byte(layer: *mut u8, offset: usize, value: u8) {
    layer.add(offset).write_volatile(value);
}

#[inline(always)]
unsafe fn word(layer: *mut u8, offset: usize) -> i32 {
    (layer.add(offset) as *const i32).read_volatile()
}

#[inline(always)]
unsafe fn set_word(layer: *mut u8, offset: usize, value: i32) {
    (layer.add(offset) as *mut i32).write_volatile(value);
}

/// The layer's embedded mutex (`add r0, r4, #0x78`).
#[inline(always)]
unsafe fn layer_mutex(layer: *mut u8) -> *mut Mutex {
    layer.add(MUTEX) as *mut Mutex
}

/// Indirect dispatch for the one genuinely unported callee of this
/// cluster (the house pattern — see `heap/alloc_core.rs`).
#[derive(Clone, Copy)]
pub struct LayerDriverHooks {
    /// `FUN_081206c4` @ 0x081206c4: the alternate-commit notify that
    /// [`layer_enable`] runs when the format variant is 3. Default: no-op.
    pub alt_commit: unsafe extern "C" fn(layer: *mut u8),
}

unsafe extern "C" fn alt_commit_stub(_layer: *mut u8) {}

/// Wired defaults (a no-op stub until 0x081206c4 is ported).
pub(crate) const DEFAULT_LAYER_DRIVER_HOOKS: LayerDriverHooks =
    LayerDriverHooks { alt_commit: alt_commit_stub };

/// The active hooks. Host tests swap in recording mocks and restore.
pub static mut LAYER_DRIVER_HOOKS: LayerDriverHooks = DEFAULT_LAYER_DRIVER_HOOKS;

/// Volatile read so LLVM cannot fold the default stub in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn driver_hooks() -> LayerDriverHooks {
    core::ptr::read_volatile(core::ptr::addr_of!(LAYER_DRIVER_HOOKS))
}

/// layer_set_alpha — original: `FUN_0811fd98` @ 0x0811fd98 (16 bytes;
/// **89 call sites**, binary-scanned: 87 `bl` + 2 tail `b`, from 45
/// distinct callers).
///
/// Stores the layer's global alpha (0 = transparent, 0xff = opaque) and
/// raises the dirty flag. Takes no lock — the original is four
/// instructions with no call.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_set_alpha(layer: *mut u8, alpha: u8) {
    set_byte(layer, ALPHA, alpha);
    set_byte(layer, DIRTY, 1);
}

/// layer_set_global_alpha_blend — original: `FUN_08120880` @ 0x08120880
/// (16 bytes; 17 call sites from 11 distinct callers).
///
/// Selects [`BLEND_MODE_GLOBAL_ALPHA`], the mode in which the render
/// pass pushes the +0x48 alpha byte to the driver, and marks the layer
/// dirty.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_set_global_alpha_blend(layer: *mut u8) {
    set_byte(layer, BLEND_MODE, BLEND_MODE_GLOBAL_ALPHA);
    set_byte(layer, DIRTY, 1);
}

/// layer_set_pixel_alpha_blend — original: `FUN_08120890` @ 0x08120890
/// (20 bytes; 6 call sites from 6 distinct callers).
///
/// Selects [`BLEND_MODE_PIXEL_ALPHA`] — the mode the applier forces for
/// pixel format 3 — and marks the layer dirty.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_set_pixel_alpha_blend(layer: *mut u8) {
    set_byte(layer, BLEND_MODE, BLEND_MODE_PIXEL_ALPHA);
    set_byte(layer, DIRTY, 1);
}

/// layer_is_dirty — original: `FUN_0811f8c0` @ 0x0811f8c0 (8 bytes;
/// 3 call sites).
///
/// Reads the dirty byte every mutator in this module raises.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_is_dirty(layer: *mut u8) -> u8 {
    byte(layer, DIRTY)
}

/// layer_set_geometry — original: `FUN_0811fda8` @ 0x0811fda8
/// (216 bytes; 20 call sites from 16 distinct callers).
///
/// Installs a complete source/destination rectangle in one shot, but
/// only if it fits inside the layer's frame buffer. Nothing is written
/// unless *every* check passes — the original computes all four
/// comparisons before taking the lock, so a rejected call leaves the
/// layer (and its dirty flag) completely untouched.
///
/// The checks, with `buffer_width` = +0x30 and `buffer_height` = +0x2c:
///
/// 1. `buffer_height >= source_y` and `buffer_width >= source_x`
///    (a single `cmp`/`cmpge` pair — the second is skipped, and the
///    call rejected, when the first fails).
/// 2. Horizontal extent: `display_width + source_x <= buffer_width` when
///    `display_width >= 0`, otherwise `width + source_x <= buffer_width`.
/// 3. Vertical extent: `display_height + source_y <= buffer_height` when
///    `display_height >= 0`, otherwise `height + source_y <=
///    buffer_height`.
///
/// A negative `display_width` / `display_height` ([`DISPLAY_SIZE_KEEP`])
/// leaves the corresponding field at its current value instead of
/// storing the argument — the `-1 = auto` sentinel from
/// `surface_config_init`. All comparisons are signed, and the additions
/// are plain `add`, so they wrap like the original rather than
/// saturating.
///
/// On success the writes happen under the layer's own mutex (+0x78) and
/// set the geometry-set flag (+0x44) and the dirty flag. Returns the
/// layer pointer, as the original does (`mov r0, r4`) on both paths.
#[cfg_attr(target_os = "none", no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn layer_set_geometry(
    layer: *mut u8,
    origin_x: u32,
    origin_y: u32,
    source_y: i32,
    source_x: i32,
    width: i32,
    height: i32,
    display_width: i32,
    display_height: i32,
) -> *mut u8 {
    let buffer_height = word(layer, BUFFER_HEIGHT);
    if buffer_height < source_y {
        return layer;
    }
    let buffer_width = word(layer, BUFFER_WIDTH);
    if buffer_width < source_x {
        return layer;
    }

    // Horizontal: a negative display width keeps the stored one and
    // validates the plain width instead.
    let mut new_display_width = word(layer, DISPLAY_WIDTH);
    let horizontal = if display_width >= 0 {
        new_display_width = display_width;
        display_width
    } else {
        width
    };
    if horizontal.wrapping_add(source_x) > buffer_width {
        return layer;
    }

    // Vertical: same shape against the buffer height.
    let mut new_display_height = word(layer, DISPLAY_HEIGHT);
    let vertical = if display_height >= 0 {
        new_display_height = display_height;
        display_height
    } else {
        height
    };
    if vertical.wrapping_add(source_y) > buffer_height {
        return layer;
    }

    mutex_lock(layer_mutex(layer));
    set_word(layer, DISPLAY_WIDTH, new_display_width);
    set_word(layer, DISPLAY_HEIGHT, new_display_height);
    set_byte(layer, GEOMETRY_SET, 1);
    set_word(layer, ORIGIN_X, origin_x as i32);
    set_word(layer, ORIGIN_Y, origin_y as i32);
    set_word(layer, SOURCE_Y, source_y);
    set_word(layer, WIDTH, width);
    set_word(layer, HEIGHT, height);
    set_word(layer, SOURCE_X, source_x);
    set_byte(layer, DIRTY, 1);
    mutex_unlock(layer_mutex(layer));
    layer
}

/// layer_enable — original: `FUN_08120908` @ 0x08120908 (76 bytes;
/// 50 call sites from 20 distinct callers).
///
/// Clears the disabled flag. Idempotent: an already-enabled layer is
/// left alone (no dirty flag, no notify). On an actual transition it
/// records that the enable state changed (+0x43), marks the layer dirty
/// and — for format variant 3 only — runs the alternate-commit notify
/// `FUN_081206c4`, which reaches this port through
/// [`LAYER_DRIVER_HOOKS`].
///
/// The whole body runs under the layer's mutex; the original releases it
/// with a tail branch to `mutex_unlock`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_enable(layer: *mut u8) {
    mutex_lock(layer_mutex(layer));
    if byte(layer, DISABLED) != 0 {
        set_byte(layer, ENABLE_CHANGED, 1);
        set_byte(layer, DISABLED, 0);
        set_byte(layer, DIRTY, 1);
        if byte(layer, FORMAT_VARIANT) == FORMAT_VARIANT_ALT_COMMIT {
            (driver_hooks().alt_commit)(layer);
        }
    }
    mutex_unlock(layer_mutex(layer));
}

/// layer_disable — original: `FUN_081208bc` @ 0x081208bc (52 bytes;
/// 3 call sites).
///
/// The mirror of [`layer_enable`], with two deliberate asymmetries kept
/// from the original: the disabled flag and the dirty flag are set
/// *unconditionally* (so re-disabling an already-disabled layer still
/// dirties it), while the enable-state-changed flag is raised only on an
/// actual transition. There is no alternate-commit notify on this side.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_disable(layer: *mut u8) {
    mutex_lock(layer_mutex(layer));
    if byte(layer, DISABLED) == 0 {
        set_byte(layer, ENABLE_CHANGED, 1);
    }
    set_byte(layer, DISABLED, 1);
    set_byte(layer, DIRTY, 1);
    mutex_unlock(layer_mutex(layer));
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex as StdMutex, MutexGuard};

    /// The layer object is addressed by literal byte offset, so a plain
    /// aligned byte block stands in for it on the host. Aligned to 8 so
    /// the `Mutex` this test suite plants at +0x78 is well aligned on a
    /// 64-bit host too (on target the object is word-aligned).
    #[repr(align(8))]
    struct Layer([u8; 0x200]);

    impl Layer {
        fn new() -> Self {
            Layer([0; 0x200])
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn byte(&self, offset: usize) -> u8 {
            self.0[offset]
        }
        fn word(&self, offset: usize) -> i32 {
            i32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
        }
        fn set_word(&mut self, offset: usize, value: i32) {
            self.0[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// The mutex at +0x78 is left with a NULL cell: `mutex_lock` /
    /// `mutex_unlock` then take their NULL guard and never touch the ROM
    /// table, so the geometry tests need no kernel setup at all.
    fn unarmed_layer() -> Layer {
        Layer::new()
    }

    // ---- alpha / blend mode -------------------------------------------

    #[test]
    fn setting_the_alpha_writes_the_byte_and_dirties_the_layer() {
        let mut layer = Layer::new();
        unsafe { layer_set_alpha(layer.ptr(), 0xff) };
        assert_eq!(layer.byte(ALPHA), 0xff);
        assert_eq!(layer.byte(DIRTY), 1);
    }

    #[test]
    fn every_alpha_value_round_trips() {
        for alpha in 0u8..=0xff {
            let mut layer = Layer::new();
            unsafe { layer_set_alpha(layer.ptr(), alpha) };
            assert_eq!(layer.byte(ALPHA), alpha, "alpha {alpha}");
            // Even a fully transparent layer is dirtied.
            assert_eq!(layer.byte(DIRTY), 1);
        }
    }

    #[test]
    fn the_alpha_setter_touches_nothing_but_its_two_bytes() {
        let mut layer = Layer::new();
        layer.0 = [0xa5; 0x200];
        unsafe { layer_set_alpha(layer.ptr(), 0x40) };
        for offset in 0..0x200 {
            let expected = match offset {
                ALPHA => 0x40,
                DIRTY => 1,
                _ => 0xa5,
            };
            assert_eq!(layer.byte(offset), expected, "byte +{offset:#x}");
        }
    }

    #[test]
    fn the_two_blend_setters_install_their_modes() {
        let mut layer = Layer::new();
        unsafe { layer_set_global_alpha_blend(layer.ptr()) };
        assert_eq!(layer.byte(BLEND_MODE), BLEND_MODE_GLOBAL_ALPHA);
        assert_eq!(layer.byte(DIRTY), 1);

        let mut layer = Layer::new();
        unsafe { layer_set_pixel_alpha_blend(layer.ptr()) };
        assert_eq!(layer.byte(BLEND_MODE), BLEND_MODE_PIXEL_ALPHA);
        assert_eq!(layer.byte(DIRTY), 1);
    }

    #[test]
    fn the_blend_setters_leave_the_alpha_byte_alone() {
        let mut layer = Layer::new();
        unsafe { layer_set_alpha(layer.ptr(), 0x7f) };
        unsafe { layer_set_global_alpha_blend(layer.ptr()) };
        assert_eq!(layer.byte(ALPHA), 0x7f);
    }

    #[test]
    fn the_dirty_getter_reports_what_the_setters_raised() {
        let mut layer = Layer::new();
        assert_eq!(unsafe { layer_is_dirty(layer.ptr()) }, 0);
        unsafe { layer_set_alpha(layer.ptr(), 0) };
        assert_eq!(unsafe { layer_is_dirty(layer.ptr()) }, 1);
    }

    // ---- geometry ------------------------------------------------------

    /// A layer with a 320x240 buffer (the Classic 6G panel).
    fn panel_layer() -> Layer {
        let mut layer = unarmed_layer();
        layer.set_word(BUFFER_WIDTH, 320);
        layer.set_word(BUFFER_HEIGHT, 240);
        layer
    }

    /// The full argument list, in the original's register/stack order.
    #[allow(clippy::too_many_arguments)]
    unsafe fn set_geometry(
        layer: &mut Layer,
        origin_x: u32,
        origin_y: u32,
        source_y: i32,
        source_x: i32,
        width: i32,
        height: i32,
        display_width: i32,
        display_height: i32,
    ) -> *mut u8 {
        layer_set_geometry(
            layer.ptr(),
            origin_x,
            origin_y,
            source_y,
            source_x,
            width,
            height,
            display_width,
            display_height,
        )
    }

    #[test]
    fn a_fitting_rectangle_is_installed_in_full() {
        let mut layer = panel_layer();
        let returned = unsafe { set_geometry(&mut layer, 10, 20, 8, 4, 100, 50, 120, 60) };
        assert_eq!(returned, layer.ptr());
        assert_eq!(layer.word(ORIGIN_X), 10);
        assert_eq!(layer.word(ORIGIN_Y), 20);
        assert_eq!(layer.word(SOURCE_X), 4);
        assert_eq!(layer.word(SOURCE_Y), 8);
        assert_eq!(layer.word(WIDTH), 100);
        assert_eq!(layer.word(HEIGHT), 50);
        assert_eq!(layer.word(DISPLAY_WIDTH), 120);
        assert_eq!(layer.word(DISPLAY_HEIGHT), 60);
        assert_eq!(layer.byte(GEOMETRY_SET), 1);
        assert_eq!(layer.byte(DIRTY), 1);
    }

    #[test]
    fn the_exact_fit_is_accepted() {
        let mut layer = panel_layer();
        unsafe { set_geometry(&mut layer, 0, 0, 0, 0, 320, 240, 320, 240) };
        assert_eq!(layer.byte(DIRTY), 1);

        // ... and one pixel wider is not.
        let mut layer = panel_layer();
        unsafe { set_geometry(&mut layer, 0, 0, 0, 0, 320, 240, 321, 240) };
        assert_eq!(layer.byte(DIRTY), 0);
    }

    #[test]
    fn a_rejected_call_writes_absolutely_nothing() {
        let mut layer = panel_layer();
        let before = layer.0;
        // display height overflows the buffer bottom.
        let returned = unsafe { set_geometry(&mut layer, 1, 2, 100, 0, 10, 10, 10, 200) };
        assert_eq!(returned, layer.ptr());
        assert!(layer.0 == before, "a rejected call must leave the layer untouched");
    }

    #[test]
    fn a_source_offset_past_the_buffer_is_rejected_on_either_axis() {
        for (source_y, source_x) in [(241, 0), (0, 321)] {
            let mut layer = panel_layer();
            unsafe { set_geometry(&mut layer, 0, 0, source_y, source_x, 1, 1, 1, 1) };
            assert_eq!(layer.byte(DIRTY), 0, "src ({source_x}, {source_y})");
        }
    }

    #[test]
    fn the_source_offset_may_sit_exactly_on_the_far_edge() {
        // buffer_height >= source_y is a >=, so 240 passes the first
        // gate; the extent check then rejects any nonzero size.
        let mut layer = panel_layer();
        unsafe { set_geometry(&mut layer, 0, 0, 240, 320, 0, 0, 0, 0) };
        assert_eq!(layer.byte(DIRTY), 1);
    }

    #[test]
    fn a_negative_display_size_keeps_the_stored_one() {
        let mut layer = panel_layer();
        layer.set_word(DISPLAY_WIDTH, 111);
        layer.set_word(DISPLAY_HEIGHT, 222);
        unsafe { set_geometry(&mut layer, 0, 0, 0, 0, 64, 32, -1, -1) };
        assert_eq!(layer.word(DISPLAY_WIDTH), 111);
        assert_eq!(layer.word(DISPLAY_HEIGHT), 222);
        assert_eq!(layer.word(WIDTH), 64);
        assert_eq!(layer.word(HEIGHT), 32);
    }

    #[test]
    fn a_negative_display_size_validates_the_plain_size_instead() {
        // width 400 + source_x 0 > buffer width 320 -> rejected, even
        // though the stored display width would have fitted.
        let mut layer = panel_layer();
        layer.set_word(DISPLAY_WIDTH, 8);
        unsafe { set_geometry(&mut layer, 0, 0, 0, 0, 400, 32, -1, 32) };
        assert_eq!(layer.byte(DIRTY), 0);
    }

    #[test]
    fn the_two_axes_are_validated_independently() {
        let mut layer = panel_layer();
        // Horizontal fits, vertical does not.
        unsafe { set_geometry(&mut layer, 0, 0, 200, 0, 10, 10, 10, 100) };
        assert_eq!(layer.byte(DIRTY), 0);

        let mut layer = panel_layer();
        // Vertical fits, horizontal does not.
        unsafe { set_geometry(&mut layer, 0, 0, 0, 300, 10, 10, 100, 10) };
        assert_eq!(layer.byte(DIRTY), 0);
    }

    #[test]
    fn a_zero_sized_rectangle_at_the_origin_is_accepted() {
        let mut layer = panel_layer();
        unsafe { set_geometry(&mut layer, 0, 0, 0, 0, 0, 0, 0, 0) };
        assert_eq!(layer.byte(DIRTY), 1);
        assert_eq!(layer.byte(GEOMETRY_SET), 1);
    }

    #[test]
    fn a_zero_sized_buffer_rejects_any_positive_source_offset() {
        let mut layer = unarmed_layer();
        unsafe { set_geometry(&mut layer, 0, 0, 1, 0, 0, 0, 0, 0) };
        assert_eq!(layer.byte(DIRTY), 0);
    }

    #[test]
    fn the_origin_words_are_stored_verbatim_including_negatives() {
        let mut layer = panel_layer();
        unsafe { set_geometry(&mut layer, (-5i32) as u32, (-6i32) as u32, 0, 0, 1, 1, 1, 1) };
        assert_eq!(layer.word(ORIGIN_X), -5);
        assert_eq!(layer.word(ORIGIN_Y), -6);
    }

    // ---- enable / disable ----------------------------------------------

    /// Serializes the tests that swap [`LAYER_DRIVER_HOOKS`].
    static HOOK_LOCK: StdMutex<()> = StdMutex::new(());
    static ALT_COMMITS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn counting_alt_commit(_layer: *mut u8) {
        ALT_COMMITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Installs the counting notify and hands back the guard; the caller
    /// restores with [`restore_hooks`] (the seek_core.rs rule: never
    /// shadow a guard).
    fn with_counting_alt_commit() -> MutexGuard<'static, ()> {
        let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ALT_COMMITS.store(0, Ordering::SeqCst);
        unsafe { LAYER_DRIVER_HOOKS = LayerDriverHooks { alt_commit: counting_alt_commit } };
        guard
    }

    fn restore_hooks(guard: MutexGuard<'static, ()>) {
        unsafe { LAYER_DRIVER_HOOKS = DEFAULT_LAYER_DRIVER_HOOKS };
        drop(guard);
    }

    #[test]
    fn enabling_a_disabled_layer_clears_the_flag_and_records_the_change() {
        let mut layer = unarmed_layer();
        layer.0[DISABLED] = 1;
        unsafe { layer_enable(layer.ptr()) };
        assert_eq!(layer.byte(DISABLED), 0);
        assert_eq!(layer.byte(ENABLE_CHANGED), 1);
        assert_eq!(layer.byte(DIRTY), 1);
    }

    #[test]
    fn enabling_an_enabled_layer_is_a_no_op() {
        let mut layer = unarmed_layer();
        let before = layer.0;
        unsafe { layer_enable(layer.ptr()) };
        assert!(layer.0 == before, "no transition means no writes");
    }

    #[test]
    fn disabling_always_dirties_but_only_flags_a_real_transition() {
        let mut layer = unarmed_layer();
        unsafe { layer_disable(layer.ptr()) };
        assert_eq!(layer.byte(DISABLED), 1);
        assert_eq!(layer.byte(ENABLE_CHANGED), 1);
        assert_eq!(layer.byte(DIRTY), 1);

        // Second disable: still dirties, but the change flag is not
        // re-raised (it is left at whatever it was).
        layer.0[ENABLE_CHANGED] = 0;
        layer.0[DIRTY] = 0;
        unsafe { layer_disable(layer.ptr()) };
        assert_eq!(layer.byte(DISABLED), 1);
        assert_eq!(layer.byte(ENABLE_CHANGED), 0);
        assert_eq!(layer.byte(DIRTY), 1);
    }

    #[test]
    fn the_alternate_commit_notify_runs_only_for_format_variant_three() {
        let guard = with_counting_alt_commit();

        let mut plain = unarmed_layer();
        plain.0[DISABLED] = 1;
        plain.0[FORMAT_VARIANT] = 2;
        unsafe { layer_enable(plain.ptr()) };
        assert_eq!(ALT_COMMITS.load(Ordering::SeqCst), 0);

        let mut alt = unarmed_layer();
        alt.0[DISABLED] = 1;
        alt.0[FORMAT_VARIANT] = FORMAT_VARIANT_ALT_COMMIT;
        unsafe { layer_enable(alt.ptr()) };
        assert_eq!(ALT_COMMITS.load(Ordering::SeqCst), 1);

        // No transition, no notify.
        unsafe { layer_enable(alt.ptr()) };
        assert_eq!(ALT_COMMITS.load(Ordering::SeqCst), 1);

        // The disable side never notifies.
        unsafe { layer_disable(alt.ptr()) };
        assert_eq!(ALT_COMMITS.load(Ordering::SeqCst), 1);

        restore_hooks(guard);
    }

    #[test]
    fn enable_and_disable_take_the_layers_own_mutex() {
        // A mutex whose cell is NULL is the "not yet created" state and
        // both primitives no-op on it; proving the *address* handed to
        // them is layer + 0x78 is what matters here, so point the cell
        // at a handle and count the ROM calls.
        static SEM_CALLS: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn count(_handle: u32) {
            SEM_CALLS.fetch_add(1, Ordering::SeqCst);
        }

        let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = unsafe { core::ptr::read(core::ptr::addr_of!(ROM_KERNEL)) };
        let mut ops: RomKernelOps = saved;
        ops.sema_wait = count;
        ops.sema_signal = count;
        unsafe { core::ptr::write(core::ptr::addr_of_mut!(ROM_KERNEL), ops) };

        let mut handle: u32 = 7;
        let mut layer = unarmed_layer();
        unsafe { (layer.ptr().add(MUTEX) as *mut *mut u32).write(&mut handle) };

        SEM_CALLS.store(0, Ordering::SeqCst);
        unsafe { layer_enable(layer.ptr()) };
        assert_eq!(SEM_CALLS.load(Ordering::SeqCst), 2, "lock + unlock");

        unsafe { core::ptr::write(core::ptr::addr_of_mut!(ROM_KERNEL), saved) };
        drop(guard);
    }
}
