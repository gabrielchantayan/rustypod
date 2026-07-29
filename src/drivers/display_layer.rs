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
//! +0x00 ptr  notify target (the display object), first argument of
//!            the enable-state notify @ 0x081d892c
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
//! +0x42 u8   parked-enable (layer_force_enable @ 0x08120654 raises it,
//!            layer_restore_enable @ 0x0812068c consumes it)
//! +0x43 u8   enable-state changed since the last render
//! +0x44 u8   geometry set
//! +0x46 u8   flag                [config +0x2d]
//! +0x48 u8   global alpha, 0..255
//! +0x49 u8   blend mode, 0..3 (see BLEND_MODE_*)
//! +0x50 ptr  bound surface (retained; swapped by 0x081206c4)
//! +0x60 ptr  previous surface, compared by the render pass
//! +0x64 ptr  surface the render pass last handed the driver
//! +0x78      the layer's mutex (kernel::sync_mutex::Mutex)
//! +0x1bc u8  dirty — every mutator raises it; the render pass
//!            @ 0x0811f8c8 tests it and the force/restore pair
//!            @ 0x08120654 / 0x0812068c clears it
//! +0x1be/+0x1c0/+0x1c4                        [config +0x34/+0x38/+0x3c]
//! +0x1c8..+0x1d4  the four surface plane addresses, filled by
//!            0x081203c4 and installed by 0x0811feb8
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
//! `drivers/surface.rs` / `drivers/ata_cmd.rs` precedent. The byte and
//! word fields keep their literal offsets on every host; the *pointer*
//! fields the render pass loads are native-width, which on a 64-bit
//! test host makes each of them span eight bytes. That is free where
//! the target field is followed by unaccounted slack — +0x00 (the
//! driver moved out, see below), +0x50 (spanning +0x54), the
//! `layer_swap_surface` precedent — but +0x04, +0x60 and +0x64 are
//! densely packed against accounted neighbors. Those three are parked,
//! on 64-bit hosts only, in the object's own dead space (the
//! `heap/block_region.rs` word-index rule, applied field by field):
//! the driver at 0x70, the previous surface at 0x58 and the
//! last-handed surface at 0x68 — all inside the unaccounted
//! +0x54..+0x5f / +0x68..+0x77 gaps, eight-aligned, disjoint from every
//! accounted field. On the 32-bit target every offset is the literal
//! one and the codegen is unaffected. See [`DRIVER`],
//! [`PREVIOUS_SURFACE`] and [`LAST_SURFACE`].

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

/// +0x00: the notify target (display object), first argument of the
/// enable-state notify @ 0x081d892c. Native-width on every host: on
/// target exactly the 4-byte field; on a 64-bit host the 8-byte access
/// spans the target's +0x04 slot, which is free there because the
/// driver is parked elsewhere (see [`DRIVER`]).
const NOTIFY_TARGET: usize = 0x00;

/// +0x04 on target: the display driver object whose vtable the render
/// pass dispatches. Followed by the accounted kind/id bytes at +0x08,
/// so there is no slack for an 8-byte host access — on 64-bit hosts the
/// field is parked at 0x70, inside the unaccounted +0x68..+0x77 gap
/// (eight-aligned, clear of [`LAST_SURFACE`]'s host slot).
#[cfg(target_pointer_width = "32")]
const DRIVER: usize = 0x04;
#[cfg(target_pointer_width = "64")]
const DRIVER: usize = 0x70;

/// +0x60 on target: the previous surface, only ever *compared* against
/// [`LAST_SURFACE`] by the render pass's kind-1 guard. Followed by the
/// accounted +0x64 slot, so on 64-bit hosts it is parked at 0x58, in
/// the unaccounted +0x54..+0x5f gap right behind [`BOUND_SURFACE`]'s
/// native span.
#[cfg(target_pointer_width = "32")]
const PREVIOUS_SURFACE: usize = 0x60;
#[cfg(target_pointer_width = "64")]
const PREVIOUS_SURFACE: usize = 0x58;

/// +0x64 on target: the surface the render pass last handed the driver.
/// +0x68.. is unaccounted, but 0x64 is not eight-aligned, so on 64-bit
/// hosts the field is parked at 0x68 (the gap's first aligned slot).
#[cfg(target_pointer_width = "32")]
const LAST_SURFACE: usize = 0x64;
#[cfg(target_pointer_width = "64")]
const LAST_SURFACE: usize = 0x68;

const LAYER_KIND: usize = 0x08;
const KIND_SUBTYPE: usize = 0x09;
const PIXEL_FORMAT: usize = 0x0a;
const FORMAT_VARIANT: usize = 0x0b;const ORIGIN_X: usize = 0x0c;
const ORIGIN_Y: usize = 0x10;
const SOURCE_X: usize = 0x14;
const SOURCE_Y: usize = 0x18;
const WIDTH: usize = 0x1c;
const HEIGHT: usize = 0x20;
const DISPLAY_WIDTH: usize = 0x24;
const DISPLAY_HEIGHT: usize = 0x28;
const BUFFER_HEIGHT: usize = 0x2c;
const BUFFER_WIDTH: usize = 0x30;
const SURFACE_FLAG: usize = 0x34;
const OPAQUE_WORD: usize = 0x3c;
const CONFIGURED: usize = 0x40;
const DISABLED: usize = 0x41;
const PARKED_ENABLE: usize = 0x42;
const ENABLE_CHANGED: usize = 0x43;
const GEOMETRY_SET: usize = 0x44;
const EXTRA_FLAG: usize = 0x46;
const ALPHA: usize = 0x48;
const BLEND_MODE: usize = 0x49;
const BOUND_SURFACE: usize = 0x50;
const MUTEX: usize = 0x78;
const DIRTY: usize = 0x1bc;
const TAIL_FLAG: usize = 0x1be;
const TAIL_WORD_0: usize = 0x1c0;
const TAIL_WORD_1: usize = 0x1c4;
/// +0x1c8..+0x1d4: the layer's plane block — four 32-bit plane address
/// words, refreshed in place by [`layer_query_planes`] from the render
/// pass and read back as `u32`s (target 32-bit addresses).
const PLANES: usize = 0x1c8;

// The 0x50-byte render descriptor the pass builds on its stack:
// 0x0828302c initializes it (class word at +0x00, -1 at +0x08/+0x0c/
// +0x28/+0x2c, zeros elsewhere), the pass fills the fields below from
// the layer, and the copy handed to the driver carries them at the
// same offsets shifted by +0x04 (its +0x00 is the class word instead).
const DESC_INIT_FIELD: usize = 0x04; // byte, left as the initializer set it
const DESC_DISABLED: usize = 0x05; // byte <- layer +0x41
const DESC_BUFFER_WIDTH: usize = 0x08; // word <- layer +0x30
const DESC_BUFFER_HEIGHT: usize = 0x0c; // word <- layer +0x2c
const DESC_WIDTH: usize = 0x10; // word <- layer +0x1c
const DESC_HEIGHT: usize = 0x14; // word <- layer +0x20
const DESC_ORIGIN_X: usize = 0x18; // word <- layer +0x0c
const DESC_ORIGIN_Y: usize = 0x1c; // word <- layer +0x10
const DESC_SOURCE_X: usize = 0x20; // word <- layer +0x14
const DESC_SOURCE_Y: usize = 0x24; // word <- layer +0x18
const DESC_DISPLAY_WIDTH: usize = 0x28; // word <- layer +0x24
const DESC_DISPLAY_HEIGHT: usize = 0x2c; // word <- layer +0x28
const DESC_TAIL_FLAG: usize = 0x30; // byte <- layer +0x1be
const DESC_TAIL_WORD_0: usize = 0x34; // word <- layer +0x1c0
const DESC_TAIL_WORD_1: usize = 0x38; // word <- layer +0x1c4
const DESC_FORMAT_CODE: usize = 0x3c; // byte <- 0x08120ad4
const DESC_PLANES: usize = 0x40; // three words, aliased by pixel format
/// Size of both descriptor blocks.
const DESC_SIZE: usize = 0x50;

// The configuration block, as `drivers/surface.rs` lays it out.
const CFG_PIXEL_FORMAT: usize = 0x00;
const CFG_FORMAT_VARIANT: usize = 0x01;
const CFG_ORIGIN_X: usize = 0x04;
const CFG_ORIGIN_Y: usize = 0x08;
const CFG_WIDTH: usize = 0x0c;
const CFG_HEIGHT: usize = 0x10;
const CFG_BUFFER_WIDTH: usize = 0x14;
const CFG_BUFFER_HEIGHT: usize = 0x18;
const CFG_DISPLAY_WIDTH: usize = 0x1c;
const CFG_DISPLAY_HEIGHT: usize = 0x20;
const CFG_SOURCE_Y: usize = 0x24;
const CFG_SOURCE_X: usize = 0x28;
const CFG_SURFACE_FLAG: usize = 0x2c;
const CFG_EXTRA_FLAG: usize = 0x2d;
const CFG_OPAQUE_WORD: usize = 0x30;
const CFG_TAIL_FLAG: usize = 0x34;
const CFG_TAIL_WORD_0: usize = 0x38;
const CFG_TAIL_WORD_1: usize = 0x3c;

/// +0x08: the layer kind that owns the [`KIND5_RENDER_SUPPRESSED`]
/// latch.
pub const LAYER_KIND_LATCHED: u8 = 5;

/// Pixel format that forces [`BLEND_MODE_PIXEL_ALPHA`].
pub const PIXEL_FORMAT_ALPHA: u8 = 3;

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

/// A stored pointer field, native-width at the given (possibly
/// host-parked) offset — the [`layer_swap_surface`] precedent.
#[inline(always)]
unsafe fn ptr_field(layer: *mut u8, offset: usize) -> *mut u8 {
    (layer.add(offset) as *const *mut u8).read_volatile()
}

#[inline(always)]
unsafe fn set_ptr_field(layer: *mut u8, offset: usize, value: *mut u8) {
    (layer.add(offset) as *mut *mut u8).write_volatile(value);
}

/// The layer's embedded mutex (`add r0, r4, #0x78`).
#[inline(always)]
unsafe fn layer_mutex(layer: *mut u8) -> *mut Mutex {
    layer.add(MUTEX) as *mut Mutex
}

/// The four surface planes a layer binds: one per component for the
/// planar pixel formats, aliased down to one or two entries for the
/// packed ones (`layer_query_planes` @ 0x081203c4 fills them from the
/// bound surface, `layer_install_planes` @ 0x0811feb8 consumes them).
pub const PLANE_COUNT: usize = 4;

/// Indirect dispatch for this cluster's callees that are unported or
/// kept interceptable for tests (the house pattern — see
/// `heap/alloc_core.rs`).
#[derive(Clone, Copy)]
pub struct LayerDriverHooks {
    /// `FUN_081206c4` @ 0x081206c4 (2 call sites): swaps the layer's
    /// bound surface (+0x50) — releases the old one through its vtable
    /// slot +0x04, stores the new pointer, retains it through slot
    /// +0x00. [`layer_enable`] calls it with NULL, [`layer_bind_surface`]
    /// with the caller's surface. Ported below as [`layer_swap_surface`];
    /// the slot stays so tests can interpose a recording mock. Default:
    /// the port itself.
    pub swap_surface: unsafe extern "C" fn(layer: *mut u8, surface: *mut u8),
    /// `FUN_081203c4` @ 0x081203c4 (2 call sites): reads the four plane
    /// addresses of the bound surface (+0x50) out through the surface
    /// accessor @ 0x082978bc, selecting and aliasing them by the layer's
    /// pixel format (+0x0a). Returns the layer. Ported below as
    /// [`layer_query_planes`]; the slot stays so tests can interpose a
    /// recording mock. Default: the port itself.
    pub query_planes: unsafe extern "C" fn(
        layer: *mut u8,
        plane0: *mut *mut u8,
        plane1: *mut *mut u8,
        plane2: *mut *mut u8,
        plane3: *mut *mut u8,
    ) -> *mut u8,
    /// `FUN_0811feb8` @ 0x0811feb8 (2 call sites): installs four plane
    /// addresses into the layer's plane block (+0x1c8..+0x1d4), first
    /// disabling a layer that is not disabled yet and flushing the
    /// pixel range through 0x08044c48; raises the dirty flag.
    /// Default: no-op.
    pub install_planes: unsafe extern "C" fn(
        layer: *mut u8,
        plane0: *mut u8,
        plane1: *mut u8,
        plane2: *mut u8,
        plane3: *mut u8,
    ),
    /// `FUN_0811f8c8` @ 0x0811f8c8 (5 call sites): the render pass —
    /// the consumer of every field this module writes. Returns the
    /// layer. Ported below as [`layer_render`]; the slot stays so tests
    /// can interpose a recording mock. Default: the port itself.
    pub render: unsafe extern "C" fn(layer: *mut u8) -> *mut u8,
    /// `FUN_0828302c` @ 0x0828302c (1 `bl` call site, [`layer_render`]):
    /// initializes the 0x50-byte render descriptor — class word at
    /// +0x00, -1 at +0x08/+0x0c/+0x28/+0x2c, zeros elsewhere. Default:
    /// no-op, which is behaviorally exact for [`layer_render`] — its
    /// descriptor starts zeroed and the pass overwrites every word the
    /// initializer would have armed, except the +0x04/+0x3c zero bytes
    /// the zeroed block already has.
    pub descriptor_init: unsafe extern "C" fn(desc: *mut u8),
    /// `FUN_08120ad4` @ 0x08120ad4 (1 `bl` call site, [`layer_render`]):
    /// maps the layer's pixel format (+0x0a) to the driver's plane-
    /// format code byte — 0 -> 8, 1 -> 9, 2 -> 3, 3 -> 7, anything else
    /// stores nothing — and writes it through `out` (descriptor +0x3c).
    /// Default: no-op (leaves the zeroed byte).
    pub plane_format_code: unsafe extern "C" fn(layer: *mut u8, out: *mut u8),
    /// `FUN_081d892c` @ 0x081d892c (2 `bl` call sites, both
    /// [`layer_render`]): the enable-state notify — the display object
    /// is told a layer's disabled state reached the panel.
    /// Default: no-op.
    pub notify: unsafe extern "C" fn(target: *mut u8, layer_id: u8, disabled: u8),
}

unsafe extern "C" fn install_planes_stub(
    _layer: *mut u8,
    _plane0: *mut u8,
    _plane1: *mut u8,
    _plane2: *mut u8,
    _plane3: *mut u8,
) {
}

unsafe extern "C" fn descriptor_init_stub(_desc: *mut u8) {}

unsafe extern "C" fn plane_format_code_stub(_layer: *mut u8, _out: *mut u8) {}

unsafe extern "C" fn notify_stub(_target: *mut u8, _layer_id: u8, _disabled: u8) {}

/// Wired defaults: the ported swap, query and render plus no-op stubs
/// for the originals not yet ported.
pub(crate) const DEFAULT_LAYER_DRIVER_HOOKS: LayerDriverHooks = LayerDriverHooks {
    swap_surface: layer_swap_surface,
    query_planes: layer_query_planes,
    install_planes: install_planes_stub,
    render: layer_render,
    descriptor_init: descriptor_init_stub,
    plane_format_code: plane_format_code_stub,
    notify: notify_stub,
};

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
/// left alone (no dirty flag, no surface swap). On an actual transition
/// it records that the enable state changed (+0x43), marks the layer
/// dirty and — for format variant 3 only — **unbinds the layer's
/// surface**: `FUN_081206c4(layer, NULL)`, which reaches this port
/// through [`LAYER_DRIVER_HOOKS`]. The next
/// [`layer_reconfigure`] rebinds one.
///
/// The whole body runs under the layer's mutex; the original releases it
/// with a tail branch to `mutex_unlock`.
///
/// Correction to the earlier port: the callee takes **two** arguments
/// (`mov r4, r1` is its second instruction), and the original leaves the
/// `mov r1, #0` it used for the +0x41 store live across the `bleq` —
/// i.e. it passes a NULL surface, which the earlier one-argument hook
/// silently dropped.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_enable(layer: *mut u8) {
    mutex_lock(layer_mutex(layer));
    if byte(layer, DISABLED) != 0 {
        set_byte(layer, ENABLE_CHANGED, 1);
        set_byte(layer, DISABLED, 0);
        set_byte(layer, DIRTY, 1);
        if byte(layer, FORMAT_VARIANT) == FORMAT_VARIANT_ALT_COMMIT {
            (driver_hooks().swap_surface)(layer, core::ptr::null_mut());
        }
    }
    mutex_unlock(layer_mutex(layer));
}

/// The bound surface's vtable, modeled down to the two slots
/// [`layer_swap_surface`] dispatches. The slots are native-width — on
/// the 32-bit target they sit at +0x00/+0x04, on a 64-bit host at
/// +0x00/+0x08, and host tests plant a native vtable (the
/// `cxx/templates.rs` precedent).
#[repr(C)]
pub struct SurfaceVtable {
    /// +0x00: retain — tail-dispatched with the new surface.
    pub retain: unsafe extern "C" fn(surface: *mut u8),
    /// +0x04 on target: release — called on the old surface.
    pub release: unsafe extern "C" fn(surface: *mut u8),
}

/// layer_swap_surface — original: `FUN_081206c4` @ 0x081206c4
/// (60 bytes; 2 `bl` call sites: [`layer_enable`] with a NULL surface,
/// [`layer_bind_surface`] with the caller's).
///
/// Refcounted swap of the layer's bound surface at +0x50:
///
/// 1. Loads the old surface and, if it is non-NULL, releases it through
///    vtable slot +0x04 (two predicated loads and a `blxne`).
/// 2. Stores the new pointer into +0x50 — unconditional, even for NULL.
/// 3. If the new surface is non-NULL, tail-dispatches vtable slot +0x00
///    to retain it (`ldmiane` + `bxne`); a NULL new surface falls
///    through to the plain epilogue. A NULL-to-NULL swap is therefore
///    a single dead store with no vtable traffic.
///
/// Deviations:
///
/// - +0x50 is accessed as a native-width pointer through the literal
///   byte offset: exactly the 4-byte field on target; on a 64-bit host
///   the 8-byte access spans the unaccounted +0x54 word (the next known
///   field is +0x60), which is how the tests plant fake surfaces. That
///   slack is exactly what the densely-packed +0x04/+0x60/+0x64 pointer
///   fields lack, which is why the render pass stays behind the hook.
/// - The retain dispatch is a trailing call; LLVM lowers it back to the
///   original's tail branch.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_swap_surface(layer: *mut u8, surface: *mut u8) {
    let slot = layer.add(BOUND_SURFACE) as *mut *mut u8;
    let old_surface = slot.read_volatile();
    if !old_surface.is_null() {
        let vtable = (old_surface as *const *const SurfaceVtable).read_volatile();
        ((*vtable).release)(old_surface);
    }
    slot.write_volatile(surface);
    if !surface.is_null() {
        let vtable = (surface as *const *const SurfaceVtable).read_volatile();
        ((*vtable).retain)(surface);
    }
}

// The bound surface's plane block, as `surface_plane_address` reads it:
// a pixel-format byte and up to three component plane addresses (one
// for the packed formats, three for the planar one).
const SURFACE_FORMAT: usize = 0x08;
const SURFACE_PLANE_A: usize = 0x24;
const SURFACE_PLANE_B: usize = 0x28;
const SURFACE_PLANE_C: usize = 0x2c;

/// surface_plane_address — original: `FUN_082978bc` @ 0x082978bc
/// (200 bytes; 39 `bl` call sites, including every plane lookup
/// [`layer_query_planes`] makes).
///
/// The surface object's plane getter: a seven-way jump table
/// (`addls pc, pc, r1, lsl #2`) on `index`, each arm gating on the
/// surface's own pixel-format byte at +0x08 and returning one of the
/// three plane-address words, or 0 when the gate fails or the index is
/// out of range:
///
/// ```text
/// index  surface +0x08   returns
///  0       0 or 1        plane A (+0x24)
///  1         1           plane B (+0x28)
///  2         0           plane B (+0x28)
///  3         0           plane C (+0x2c)
///  4         2           plane A (+0x24)
///  5         3           plane A (+0x24)
///  6         4           plane A (+0x24)
/// else     —             0
/// ```
///
/// Read with the installer @ 0x0811feb8 (which flushes plane A in full
/// and B/C at a quarter of the area for format 0), this pins the
/// formats: 0 = planar three-component (YUV 4:2:0 — A luma, B/C
/// chroma), 1 = two-plane, 2/3/4 = packed single-plane.
///
/// The function belongs to the surface object cluster; it lives in
/// this module because its only ported caller is [`layer_query_planes`]
/// and the porting task is confined to `drivers/display_layer`.
///
/// Deviations:
///
/// - Returns the plane word as a `u32` (a target 32-bit address)
///   rather than a pointer, so the surface block stays pure 4-byte
///   fields and nothing shifts on a 64-bit test host; callers cast.
/// - The original's index-0 arm computes its `format == 0 ||
///   format == 1` gate as two predicated flag bytes ORed together; the
///   port is the plain boolean it computes.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn surface_plane_address(surface: *mut u8, index: u32) -> u32 {
    let format = surface.add(SURFACE_FORMAT).read_volatile();
    let plane = |offset: usize| (surface.add(offset) as *const u32).read_volatile();
    match index {
        0 if format == 0 || format == 1 => plane(SURFACE_PLANE_A),
        1 if format == 1 => plane(SURFACE_PLANE_B),
        2 if format == 0 => plane(SURFACE_PLANE_B),
        3 if format == 0 => plane(SURFACE_PLANE_C),
        4 if format == 2 => plane(SURFACE_PLANE_A),
        5 if format == 3 => plane(SURFACE_PLANE_A),
        6 if format == 4 => plane(SURFACE_PLANE_A),
        _ => 0,
    }
}

/// layer_query_planes — original: `FUN_081203c4` @ 0x081203c4
/// (224 bytes; 2 `bl` call sites: [`layer_reconfigure`] and the render
/// pass `FUN_0811f8c8`).
///
/// Reads the bound surface's component plane addresses into four
/// out-slots, selecting and aliasing them by the layer's pixel format
/// (+0x0a). Every lookup goes through [`surface_plane_address`], which
/// re-gates on the surface's own format byte:
///
/// ```text
/// layer +0x0a   *p0          *p1          *p2          *p3
///  0 (planar)   plane 0      plane 2      plane 3      0
///  1 (2-plane)  plane 0      plane 1      plane 0      plane 1
///  2 (packed)   plane 4      0            0            0
///  3 (packed)   plane 5      0            0            0
///  else         0            0            0            0
/// ```
///
/// An unbound layer (+0x50 NULL) returns immediately **without**
/// touching the out-slots — the four zeroing stores happen only on the
/// bound path, before the format dispatch, so any bound layer (even one
/// with an unknown format) leaves all four slots zeroed. Returns the
/// layer pointer (`mov r0, r4`) on both paths.
///
/// Deviations:
///
/// - +0x50 is read as a native-width pointer through the literal byte
///   offset, the [`layer_swap_surface`] precedent: exactly the 4-byte
///   field on target; on a 64-bit host the 8-byte read spans the
///   unaccounted +0x54 word, which is how the tests plant fake
///   surfaces.
/// - The out-slots are native-width pointers; the original's `str`
///   writes 32-bit words, and the accessor's `u32` answers are
///   zero-extended on a 64-bit host.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_query_planes(
    layer: *mut u8,
    plane0: *mut *mut u8,
    plane1: *mut *mut u8,
    plane2: *mut *mut u8,
    plane3: *mut *mut u8,
) -> *mut u8 {
    let surface = (layer.add(BOUND_SURFACE) as *const *mut u8).read_volatile();
    if surface.is_null() {
        return layer;
    }
    plane0.write_volatile(core::ptr::null_mut());
    plane1.write_volatile(core::ptr::null_mut());
    plane2.write_volatile(core::ptr::null_mut());
    plane3.write_volatile(core::ptr::null_mut());
    match byte(layer, PIXEL_FORMAT) {
        0 => {
            plane0.write_volatile(surface_plane_address(surface, 0) as *mut u8);
            plane1.write_volatile(surface_plane_address(surface, 2) as *mut u8);
            plane2.write_volatile(surface_plane_address(surface, 3) as *mut u8);
        }
        1 => {
            let even = surface_plane_address(surface, 0) as *mut u8;
            plane0.write_volatile(even);
            plane2.write_volatile(even);
            let odd = surface_plane_address(surface, 1) as *mut u8;
            plane1.write_volatile(odd);
            plane3.write_volatile(odd);
        }
        2 => plane0.write_volatile(surface_plane_address(surface, 4) as *mut u8),
        3 => plane0.write_volatile(surface_plane_address(surface, 5) as *mut u8),
        _ => {}
    }
    layer
}

/// layer_bind_surface — original: `FUN_0811fe80` @ 0x0811fe80
/// (56 bytes; 1 `bl` call site, [`layer_reconfigure`]).
///
/// Binds `surface` to a format-variant-3 layer: re-checks the variant
/// (returning immediately for any other), then swaps the surface in
/// under the layer's mutex. Every other variant keeps whatever surface
/// it already had, which is why [`layer_reconfigure`] can call this
/// unconditionally.
///
/// Deviation kept from the original: the caller already holds the same
/// mutex, so this re-locks it. The layer mutex is a plain RTXC counting
/// semaphore (kernel/sync_mutex.rs — no recursion counter), so the pair
/// only survives because these layers' +0x78 cell is never created; the
/// port reproduces the instruction sequence rather than "fixing" it.
// A real `bl` target of `layer_reconfigure`: LLVM inlines a body this
// small and the stock caller would then reach a different copy.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_bind_surface(layer: *mut u8, surface: *mut u8) {
    if byte(layer, FORMAT_VARIANT) != FORMAT_VARIANT_ALT_COMMIT {
        return;
    }
    mutex_lock(layer_mutex(layer));
    (driver_hooks().swap_surface)(layer, surface);
    mutex_unlock(layer_mutex(layer));
}

/// layer_reconfigure — original: `FUN_0811fc4c` @ 0x0811fc4c (120 bytes;
/// **74 call sites**, binary-scanned: 57 `bl` + 17 tail `b`, from 46
/// distinct callers — the hottest function of the display-layer cluster,
/// plus the alias thunk @ 0x08120134).
///
/// Points a layer at a surface and re-derives everything downstream of
/// it. Under the layer's mutex:
///
/// 1. [`layer_bind_surface`] — a no-op unless the format variant is 3,
///    in which case the layer's +0x50 surface is released and `surface`
///    retained in its place.
/// 2. `query_planes` reads the (now current) surface's four plane
///    addresses, selected and aliased by the layer's pixel format.
/// 3. `install_planes` writes those same four words into the layer's
///    plane block at +0x1c8..+0x1d4 and raises the dirty flag.
///
/// Steps 2 and 3 are a pure pass-through in the original: each of the
/// four out-parameters of the query is handed to the matching parameter
/// of the install, in order, with no inspection.
///
/// Returns 0 (`mov r0, #0`), like the original.
// `#[inline(never)]`: [`layer_reconfigure_thunk`] must stay a veneer —
// inlining this body into it turns the one-word `b` into a second copy.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_reconfigure(layer: *mut u8, surface: *mut u8) -> u32 {
    mutex_lock(layer_mutex(layer));
    layer_bind_surface(layer, surface);

    let mut planes: [*mut u8; PLANE_COUNT] = [core::ptr::null_mut(); PLANE_COUNT];
    let hooks = driver_hooks();
    (hooks.query_planes)(
        layer,
        &mut planes[0],
        &mut planes[1],
        &mut planes[2],
        &mut planes[3],
    );
    (hooks.install_planes)(layer, planes[0], planes[1], planes[2], planes[3]);

    mutex_unlock(layer_mutex(layer));
    0
}

/// layer_reconfigure_thunk — original: `thunk_FUN_0811fc4c` @ 0x08120134
/// (4 bytes; 1 `bl` call site @ 0x080f58e8).
///
/// A single `b 0x0811fc4c` — an ADS alias veneer that tail-branches into
/// [`layer_reconfigure`] with the arguments untouched (registers fall
/// through). The port is the same forward-and-return; semantically a
/// pure alias. match.py deviation, the crate-wide one: LLVM keeps a
/// frame pointer on armv5te (the `layer_install_planes` notes), which
/// blocks the sibling-call fold, so the veneer is `bl` + `mov r0,#0` +
/// return instead of the original's bare `b`. The call-graph edge —
/// thunk to reconfigure, nothing else — is identical.
// `#[inline(never)]`: the original is a real `bl` target; inlining it
// into a caller would duplicate the branch. `layer_reconfigure` itself
// is `#[inline(never)]` for the mirror reason — inlining its body here
// would turn the veneer into a second copy of the whole function.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_reconfigure_thunk(layer: *mut u8, surface: *mut u8) -> u32 {
    layer_reconfigure(layer, surface)
}

/// layer_force_enable — original: `FUN_08120654` @ 0x08120654
/// (56 bytes; 1 `bl` call site @ 0x081d8a20).
///
/// Temporarily makes a hidden layer visible and remembers to put it
/// back. A layer that is already enabled is left completely untouched.
/// A disabled one is enabled ([`layer_enable`]), rendered at once so the
/// change reaches the panel, its dirty flag cleared, and the parked flag
/// at +0x42 raised for [`layer_restore_enable`].
///
/// The single caller walks all six layers of a display object; it
/// ignores the return value, which is the parked flag on both paths
/// (0 when nothing was done, 1 when the layer was forced on).
///
/// Renamed from the earlier scouting note's `layer_suspend`: this half
/// *enables*, so "suspend" read backwards.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_force_enable(layer: *mut u8) -> u8 {
    if byte(layer, DISABLED) == 0 {
        return 0;
    }
    layer_enable(layer);
    (driver_hooks().render)(layer);
    set_byte(layer, DIRTY, 0);
    set_byte(layer, PARKED_ENABLE, 1);
    1
}

/// layer_restore_enable — original: `FUN_0812068c` @ 0x0812068c
/// (56 bytes; 1 `bl` call site @ 0x081d8ac0).
///
/// The mirror of [`layer_force_enable`]: if the parked flag at +0x42 is
/// set, disables the layer again ([`layer_disable`]), renders, clears
/// the dirty flag and clears the parked flag. Returns the parked flag as
/// it was on entry — the caller ORs the six layers' answers to learn
/// whether the display changed at all.
///
/// Note the asymmetry with the forcing half: it reads +0x42 and never
/// re-reads +0x41, so a layer someone else enabled in between is still
/// disabled here.
///
/// Renamed from the earlier scouting note's `layer_resume`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_restore_enable(layer: *mut u8) -> u8 {
    let parked = byte(layer, PARKED_ENABLE);
    if parked == 0 {
        return parked;
    }
    layer_disable(layer);
    (driver_hooks().render)(layer);
    set_byte(layer, DIRTY, 0);
    set_byte(layer, PARKED_ENABLE, 0);
    parked
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

/// Original: the byte global @ 0x089ca8ac. Only the kind-5 layer
/// touches it, and only three functions reference the literal:
///
/// - [`layer_apply_config`] and the render pass `FUN_0811f8c8` set it to
///   `surface_flag == 0` whenever the layer is kind 5 with subtype 0;
/// - the flush @ 0x0811fcc4 renders that layer *only* while this byte is
///   clear — hence the name.
///
/// Deviation (the `app/context.rs` precedent): the latch is a crate
/// static rather than the word at 0x089ca8ac, which is runtime-
/// initialized RW data. It defaults to 0, the pre-init state.
pub static mut KIND5_RENDER_SUPPRESSED: u8 = 0;

/// layer_apply_config — original: `FUN_08120978` @ 0x08120978
/// (344 bytes; 17 `bl` call sites from 12 distinct callers).
///
/// Copies a whole `surface_config_init`-shaped block (see
/// `drivers/surface.rs`) into a live layer, under the layer's mutex.
/// This is the function whose stores recovered the layer field map, and
/// the counterpart of the piecemeal setters above.
///
/// What it does beyond a straight copy:
///
/// - **Clamps to zero.** Origin, source offset, width and height are
///   each stored and then overwritten with 0 if negative — the original
///   is a `str` followed by a predicated `strlt`, so the store happens
///   twice, not once. Behaviorally a clamp.
/// - **Clamps the buffer to the image.** Buffer height is raised to at
///   least the (already clamped) height, buffer width to at least the
///   width.
/// - **Resolves the "auto" display size.** A display width of -1 makes
///   the applier write the resolved width *and* height back into the
///   caller's block before forwarding them, which is why callers can
///   read their block afterwards to learn the resolved size. Any other
///   value is taken literally, and the display *height* is never
///   consulted for the -1 test.
/// - **Forces per-pixel alpha** ([`BLEND_MODE_PIXEL_ALPHA`]) when the
///   pixel format is [`PIXEL_FORMAT_ALPHA`].
/// - **Drives the [`KIND5_RENDER_SUPPRESSED`] latch** for a kind-5,
///   subtype-0 layer: set when the surface flag is 0, cleared otherwise.
/// - Raises the configured flag (+0x40), the geometry flag (+0x44, set
///   first thing, before any copying) and the dirty flag.
///
/// Returns 0 (`mov r0, #0`), like the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_apply_config(layer: *mut u8, config: *mut u8) -> u32 {
    let cfg_byte = |offset: usize| config.add(offset).read_volatile();
    let cfg_word = |offset: usize| (config.add(offset) as *const i32).read_volatile();

    mutex_lock(layer_mutex(layer));
    set_byte(layer, GEOMETRY_SET, 1);

    let pixel_format = cfg_byte(CFG_PIXEL_FORMAT);
    set_byte(layer, PIXEL_FORMAT, pixel_format);
    if pixel_format == PIXEL_FORMAT_ALPHA {
        set_byte(layer, BLEND_MODE, BLEND_MODE_PIXEL_ALPHA);
    }
    set_byte(layer, FORMAT_VARIANT, cfg_byte(CFG_FORMAT_VARIANT));

    // Each of these is "store, then store 0 again if negative".
    for (layer_offset, config_offset) in [
        (ORIGIN_X, CFG_ORIGIN_X),
        (ORIGIN_Y, CFG_ORIGIN_Y),
        (SOURCE_Y, CFG_SOURCE_Y),
        (SOURCE_X, CFG_SOURCE_X),
        (WIDTH, CFG_WIDTH),
        (HEIGHT, CFG_HEIGHT),
    ] {
        let value = cfg_word(config_offset);
        set_word(layer, layer_offset, if value < 0 { 0 } else { value });
    }

    let height = word(layer, HEIGHT);
    let buffer_height = cfg_word(CFG_BUFFER_HEIGHT);
    set_word(layer, BUFFER_HEIGHT, if buffer_height < height { height } else { buffer_height });

    let buffer_width = cfg_word(CFG_BUFFER_WIDTH);
    set_word(layer, BUFFER_WIDTH, buffer_width);
    set_byte(layer, SURFACE_FLAG, cfg_byte(CFG_SURFACE_FLAG));
    set_byte(layer, EXTRA_FLAG, cfg_byte(CFG_EXTRA_FLAG));
    set_word(layer, OPAQUE_WORD, cfg_word(CFG_OPAQUE_WORD));

    let width = word(layer, WIDTH);
    if buffer_width < width {
        set_word(layer, BUFFER_WIDTH, width);
    }

    // -1 in the display *width* alone triggers the write-back of both.
    if cfg_word(CFG_DISPLAY_WIDTH) == DISPLAY_SIZE_KEEP {
        (config.add(CFG_DISPLAY_WIDTH) as *mut i32).write_volatile(width);
        (config.add(CFG_DISPLAY_HEIGHT) as *mut i32).write_volatile(word(layer, HEIGHT));
    }
    set_word(layer, DISPLAY_WIDTH, cfg_word(CFG_DISPLAY_WIDTH));
    set_word(layer, DISPLAY_HEIGHT, cfg_word(CFG_DISPLAY_HEIGHT));

    if byte(layer, KIND_SUBTYPE) == 0 && byte(layer, LAYER_KIND) == LAYER_KIND_LATCHED {
        let suppressed = u8::from(byte(layer, SURFACE_FLAG) == 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(KIND5_RENDER_SUPPRESSED), suppressed);
    }

    set_byte(layer, TAIL_FLAG, cfg_byte(CFG_TAIL_FLAG));
    set_word(layer, TAIL_WORD_0, cfg_word(CFG_TAIL_WORD_0));
    set_word(layer, TAIL_WORD_1, cfg_word(CFG_TAIL_WORD_1));
    set_byte(layer, CONFIGURED, 1);
    set_byte(layer, DIRTY, 1);

    mutex_unlock(layer_mutex(layer));
    0
}

/// The display driver's vtable, modeled down to the five slots
/// [`layer_render`] dispatches. The slots are native-width — on the
/// 32-bit target they sit at +0x14/+0x18/+0x3c/+0x40/+0x44, on a
/// 64-bit host at word indices 5/6/15/16/17, and host tests plant a
/// native vtable (the [`SurfaceVtable`] precedent).
#[repr(C)]
pub struct DriverVtable {
    /// +0x00..+0x13: slots the render pass never touches.
    pub _slots_0x00: [usize; 5],
    /// +0x14: push the geometry descriptor copy to the driver.
    pub push_geometry: unsafe extern "C" fn(driver: *mut u8, layer_id: u8, desc: *mut u8),
    /// +0x18: kind-5 only — hand the driver the surface flag (+0x34).
    pub kind5_surface_flag: unsafe extern "C" fn(driver: *mut u8, surface_flag: u8),
    /// +0x1c..+0x3b: slots the render pass never touches.
    pub _slots_0x1c: [usize; 8],
    /// +0x3c: the enable state changed while the layer is enabled.
    pub enable_state_changed: unsafe extern "C" fn(driver: *mut u8, layer_id: u8),
    /// +0x40: set the driver's blend code (1/3/2/5 for modes 0..3).
    pub set_blend_mode: unsafe extern "C" fn(driver: *mut u8, layer_id: u8, code: u32),
    /// +0x44: push the global alpha byte (+0x48) — modes 1 and 3 only.
    pub set_global_alpha: unsafe extern "C" fn(driver: *mut u8, layer_id: u8, alpha: u8),
}

/// Original: the literal 0x089a651c — the class word the render pass
/// plants at +0x00 of the descriptor copy it hands the driver (the
/// same word 0x0828302c puts at +0x00 of the descriptor itself).
///
/// Deviation (the `heap/block_region.rs` REGION_START_FALLBACK
/// precedent): 0x089a651c is runtime data, so the word is modeled as
/// the address of this crate static; only its identity as the class
/// marker matters to the consumer.
static LAYER_RENDER_CLASS: u32 = 0;

/// The 0x50-byte render descriptor (and the second block the driver
/// actually receives), aligned so the word stores are well aligned on
/// every host.
#[repr(align(8))]
struct RenderDescriptor([u8; DESC_SIZE]);

impl RenderDescriptor {
    #[inline(always)]
    fn new() -> Self {
        RenderDescriptor([0; DESC_SIZE])
    }
    #[inline(always)]
    fn ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
    #[inline(always)]
    unsafe fn set_byte(&mut self, offset: usize, value: u8) {
        self.0.as_mut_ptr().add(offset).write_volatile(value);
    }
    #[inline(always)]
    unsafe fn set_word(&mut self, offset: usize, value: u32) {
        (self.0.as_mut_ptr().add(offset) as *mut u32).write_volatile(value);
    }
}

/// layer_render — original: `FUN_0811f8c8` @ 0x0811f8c8 (892 bytes;
/// 5 `bl` call sites: the flush @ 0x0811fd38, [`layer_force_enable`],
/// [`layer_restore_enable`], 0x081d8b3c and 0x081d8bb4).
///
/// The render pass of the display layer — the consumer of every field
/// this module's setters write. Returns the layer pointer on every
/// path (`mov r0, r4`).
///
/// 1. **Dirty gate.** Returns at once unless the dirty byte (+0x1bc) is
///    set; the flag itself is the *callers'* business (the force/restore
///    pair clears it after rendering).
/// 2. **Surface swap.** The surface the driver was last handed (+0x64),
///    if any, is released through its vtable slot +0x04 — except under
///    the kind-1 guard: subtype (+0x09) 1 with the surface flag (+0x34)
///    set bails out of the whole render when the previous surface
///    (+0x60) differs from the last-handed one. The bound surface
///    (+0x50) is then stored into +0x64 unconditionally and, if
///    non-NULL, retained through vtable slot +0x00.
/// 3. **Short path.** When the enable state changed (+0x43) while the
///    layer is enabled (+0x41 clear), the geometry push is skipped:
///    driver vtable[+0x3c], clear +0x43, notify 0x081d892c with the
///    (re-read) disabled byte, and for a kind-5 subtype-0 layer raise
///    the [`KIND5_RENDER_SUPPRESSED`] latch (the byte @ 0x089ca8ac in
///    the original). Return.
/// 4. **Long path.** Otherwise build the 0x50-byte render descriptor on
///    the stack: `descriptor_init` (0x0828302c), then the geometry,
///    buffer, tail and disabled fields copied from the layer;
///    `plane_format_code` (0x08120ad4) maps the pixel format into
///    descriptor +0x3c; [`layer_query_planes`] refreshes the layer's
///    plane block (+0x1c8..+0x1d4) in place; the plane words are
///    aliased into descriptor +0x40.. by pixel format (0: planes 0/2/1,
///    1: planes 0/1, 2 or 3: plane 0, anything else: zeros). If the
///    enable state changed while the layer is *disabled*, the notify
///    fires here instead. A kind-5 layer hands its surface flag to
///    driver vtable[+0x18]. The descriptor +0x04.. is then copied into
///    a second block behind the class word and pushed through driver
///    vtable[+0x14].
/// 5. **Blend.** The +0x49 mode is translated to the driver's code:
///    0 -> vtable[+0x40](code 1); 1 -> code 3 then vtable[+0x44](alpha
///    @ +0x48); 2 -> code 2; 3 -> code 5 then the alpha push; any other
///    mode skips both calls (the `BLEND_MODE_*` table in the module
///    header).
/// 6. **Tail.** If the enable state changed while the layer is enabled
///    — re-tested at the end, because the driver and notify calls above
///    may have mutated the layer — driver vtable[+0x3c] fires and +0x43
///    is cleared.
///
/// Deviations:
///
/// - The pointer fields it loads are native-width; on 64-bit hosts the
///   driver, previous-surface and last-surface fields are parked in the
///   object's dead space — see the module header and [`DRIVER`],
///   [`PREVIOUS_SURFACE`], [`LAST_SURFACE`]. On target every offset is
///   literal.
/// - The class word is the address of [`LAYER_RENDER_CLASS`], not the
///   literal 0x089a651c (runtime data).
/// - `descriptor_init`, `plane_format_code` and `notify` dispatch
///   through [`LAYER_DRIVER_HOOKS`] (unported originals; documented
///   no-op defaults, the `install_planes` precedent).
///   [`layer_query_planes`] is called directly — through local slots
///   seeded from the plane block, because its native-width out-stores
///   would otherwise straddle the block's 4-byte slots on a 64-bit
///   host (see the body).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_render(layer: *mut u8) -> *mut u8 {
    if byte(layer, DIRTY) == 0 {
        return layer;
    }

    // Swap the surface the driver was last handed for the bound one.
    let last_surface = ptr_field(layer, LAST_SURFACE);
    if !last_surface.is_null() {
        if byte(layer, KIND_SUBTYPE) == 1
            && byte(layer, SURFACE_FLAG) != 0
            && ptr_field(layer, PREVIOUS_SURFACE) != last_surface
        {
            return layer;
        }
        let vtable = (last_surface as *const *const SurfaceVtable).read_volatile();
        ((*vtable).release)(last_surface);
    }
    let bound_surface = ptr_field(layer, BOUND_SURFACE);
    set_ptr_field(layer, LAST_SURFACE, bound_surface);
    if !bound_surface.is_null() {
        let vtable = (bound_surface as *const *const SurfaceVtable).read_volatile();
        ((*vtable).retain)(bound_surface);
    }

    let driver = ptr_field(layer, DRIVER);
    let driver_vtable = || (driver as *const *const DriverVtable).read_volatile();
    let layer_id = || byte(layer, LAYER_KIND);

    // Short path: the enable state changed on an enabled layer.
    if byte(layer, ENABLE_CHANGED) != 0 && byte(layer, DISABLED) == 0 {
        ((*driver_vtable()).enable_state_changed)(driver, layer_id());
        set_byte(layer, ENABLE_CHANGED, 0);
        let disabled = byte(layer, DISABLED);
        (driver_hooks().notify)(ptr_field(layer, NOTIFY_TARGET), layer_id(), disabled);
        if byte(layer, KIND_SUBTYPE) == 0 && byte(layer, LAYER_KIND) == LAYER_KIND_LATCHED {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(KIND5_RENDER_SUPPRESSED), 1);
        }
        return layer;
    }

    // Long path: build the render descriptor and push the geometry.
    let hooks = driver_hooks();
    let mut desc = RenderDescriptor::new();
    (hooks.descriptor_init)(desc.ptr());
    desc.set_byte(DESC_DISABLED, byte(layer, DISABLED));
    desc.set_word(DESC_HEIGHT, word(layer, HEIGHT) as u32);
    desc.set_word(DESC_WIDTH, word(layer, WIDTH) as u32);
    desc.set_word(DESC_ORIGIN_X, word(layer, ORIGIN_X) as u32);
    desc.set_word(DESC_ORIGIN_Y, word(layer, ORIGIN_Y) as u32);
    desc.set_word(DESC_SOURCE_X, word(layer, SOURCE_X) as u32);
    desc.set_word(DESC_SOURCE_Y, word(layer, SOURCE_Y) as u32);
    desc.set_word(DESC_DISPLAY_WIDTH, word(layer, DISPLAY_WIDTH) as u32);
    desc.set_word(DESC_DISPLAY_HEIGHT, word(layer, DISPLAY_HEIGHT) as u32);
    desc.set_word(DESC_BUFFER_WIDTH, word(layer, BUFFER_WIDTH) as u32);
    desc.set_word(DESC_BUFFER_HEIGHT, word(layer, BUFFER_HEIGHT) as u32);
    desc.set_byte(DESC_TAIL_FLAG, byte(layer, TAIL_FLAG));
    desc.set_word(DESC_TAIL_WORD_0, word(layer, TAIL_WORD_0) as u32);
    desc.set_word(DESC_TAIL_WORD_1, word(layer, TAIL_WORD_1) as u32);
    (hooks.plane_format_code)(layer, desc.ptr().add(DESC_FORMAT_CODE));

    // Refresh the plane block in place, then alias the plane words by
    // pixel format. Host deviation: the query's out-slots are
    // native-width while the block slots are 4 bytes apart, so the
    // query runs into local slots seeded from the block and each
    // answer's low 32 bits are stored back. On target this is the
    // original's direct query into the block; the seed/store-back is a
    // no-op there, including the unbound-surface early return, which
    // leaves the seeded values untouched.
    let mut slots: [*mut u8; PLANE_COUNT] = [core::ptr::null_mut(); PLANE_COUNT];
    for (index, slot) in slots.iter_mut().enumerate() {
        *slot = (layer.add(PLANES + 4 * index) as *const u32).read_volatile() as *mut u8;
    }
    layer_query_planes(
        layer,
        &mut slots[0],
        &mut slots[1],
        &mut slots[2],
        &mut slots[3],
    );
    for (index, slot) in slots.iter().enumerate() {
        (layer.add(PLANES + 4 * index) as *mut u32).write_volatile(*slot as u32);
    }
    let plane = |index: usize| (layer.add(PLANES + 4 * index) as *const u32).read_volatile();
    desc.set_word(DESC_PLANES, 0);
    desc.set_word(DESC_PLANES + 4, 0);
    desc.set_word(DESC_PLANES + 8, 0);
    desc.set_word(DESC_PLANES + 12, 0);
    match byte(layer, PIXEL_FORMAT) {
        0 => {
            desc.set_word(DESC_PLANES, plane(0));
            desc.set_word(DESC_PLANES + 8, plane(1));
            desc.set_word(DESC_PLANES + 4, plane(2));
        }
        1 => {
            desc.set_word(DESC_PLANES, plane(0));
            desc.set_word(DESC_PLANES + 4, plane(1));
        }
        2 | 3 => desc.set_word(DESC_PLANES, plane(0)),
        _ => {}
    }

    // An enable-state change on a disabled layer notifies here instead.
    if byte(layer, ENABLE_CHANGED) != 0 && byte(layer, DISABLED) != 0 {
        let disabled = byte(layer, DISABLED);
        (hooks.notify)(ptr_field(layer, NOTIFY_TARGET), layer_id(), disabled);
    }

    if byte(layer, LAYER_KIND) == LAYER_KIND_LATCHED {
        ((*driver_vtable()).kind5_surface_flag)(driver, byte(layer, SURFACE_FLAG));
    }

    // The driver gets a copy behind the class word — a 4-byte field on
    // every host, so the +0x04.. copy never touches it. On a 64-bit
    // host the word carries the low 32 bits of the class static's
    // address.
    let mut block = RenderDescriptor::new();
    for offset in DESC_INIT_FIELD..DESC_SIZE {
        block.set_byte(offset, desc.ptr().add(offset).read_volatile());
    }
    (block.ptr() as *mut u32)
        .write_volatile(core::ptr::addr_of!(LAYER_RENDER_CLASS) as usize as u32);
    ((*driver_vtable()).push_geometry)(driver, layer_id(), block.ptr());

    // Translate the blend mode into the driver's code; modes 1 and 3
    // also push the global alpha.
    match byte(layer, BLEND_MODE) {
        BLEND_MODE_OPAQUE => ((*driver_vtable()).set_blend_mode)(driver, layer_id(), 1),
        BLEND_MODE_GLOBAL_ALPHA => {
            ((*driver_vtable()).set_blend_mode)(driver, layer_id(), 3);
            let alpha = byte(layer, ALPHA);
            ((*driver_vtable()).set_global_alpha)(driver, layer_id(), alpha);
        }
        BLEND_MODE_PIXEL_ALPHA => ((*driver_vtable()).set_blend_mode)(driver, layer_id(), 2),
        BLEND_MODE_PIXEL_AND_GLOBAL_ALPHA => {
            ((*driver_vtable()).set_blend_mode)(driver, layer_id(), 5);
            let alpha = byte(layer, ALPHA);
            ((*driver_vtable()).set_global_alpha)(driver, layer_id(), alpha);
        }
        _ => {}
    }

    // The driver/notify traffic above may have changed the enable
    // state; close out a change on an enabled layer.
    if byte(layer, ENABLE_CHANGED) != 0 && byte(layer, DISABLED) == 0 {
        ((*driver_vtable()).enable_state_changed)(driver, layer_id());
        set_byte(layer, ENABLE_CHANGED, 0);
    }
    layer
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
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
    static SWAPS: AtomicU32 = AtomicU32::new(0);
    static LAST_SWAPPED_SURFACE: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RENDERS: AtomicU32 = AtomicU32::new(0);
    static QUERIES: AtomicU32 = AtomicU32::new(0);
    /// The four words the recording `install_planes` last received.
    static INSTALLED: [AtomicUsize; PLANE_COUNT] =
        [const { AtomicUsize::new(0) }; PLANE_COUNT];

    unsafe extern "C" fn recording_swap_surface(_layer: *mut u8, surface: *mut u8) {
        SWAPS.fetch_add(1, Ordering::SeqCst);
        LAST_SWAPPED_SURFACE.store(surface as usize, Ordering::SeqCst);
    }

    /// Stands in for 0x081203c4: hands back four distinct, recognizable
    /// plane addresses so the pass-through can be checked slot by slot.
    unsafe extern "C" fn recording_query_planes(
        layer: *mut u8,
        plane0: *mut *mut u8,
        plane1: *mut *mut u8,
        plane2: *mut *mut u8,
        plane3: *mut *mut u8,
    ) -> *mut u8 {
        QUERIES.fetch_add(1, Ordering::SeqCst);
        for (slot, out) in [plane0, plane1, plane2, plane3].into_iter().enumerate() {
            out.write((0x1000 + slot * 0x100) as *mut u8);
        }
        layer
    }

    unsafe extern "C" fn recording_install_planes(
        _layer: *mut u8,
        plane0: *mut u8,
        plane1: *mut u8,
        plane2: *mut u8,
        plane3: *mut u8,
    ) {
        for (slot, plane) in [plane0, plane1, plane2, plane3].into_iter().enumerate() {
            INSTALLED[slot].store(plane as usize, Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn recording_render(layer: *mut u8) -> *mut u8 {
        RENDERS.fetch_add(1, Ordering::SeqCst);
        layer
    }

    /// The recording suite leaves the render pass's own callees at
    /// their defaults; only the swap/query/install/render traffic is
    /// intercepted.
    unsafe extern "C" fn recording_descriptor_init(_desc: *mut u8) {}

    unsafe extern "C" fn recording_plane_format_code(_layer: *mut u8, _out: *mut u8) {}

    unsafe extern "C" fn recording_notify(_target: *mut u8, _layer_id: u8, _disabled: u8) {}

    /// Installs the recording hooks and hands back the guard; the caller
    /// restores with [`restore_hooks`] (the seek_core.rs rule: never
    /// shadow a guard).
    fn with_recording_hooks() -> MutexGuard<'static, ()> {
        let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        SWAPS.store(0, Ordering::SeqCst);
        LAST_SWAPPED_SURFACE.store(usize::MAX, Ordering::SeqCst);
        RENDERS.store(0, Ordering::SeqCst);
        QUERIES.store(0, Ordering::SeqCst);
        for slot in &INSTALLED {
            slot.store(0, Ordering::SeqCst);
        }
        unsafe {
            LAYER_DRIVER_HOOKS = LayerDriverHooks {
                swap_surface: recording_swap_surface,
                query_planes: recording_query_planes,
                install_planes: recording_install_planes,
                render: recording_render,
                descriptor_init: recording_descriptor_init,
                plane_format_code: recording_plane_format_code,
                notify: recording_notify,
            }
        };
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
    fn enabling_unbinds_the_surface_only_for_format_variant_three() {
        let guard = with_recording_hooks();

        let mut plain = unarmed_layer();
        plain.0[DISABLED] = 1;
        plain.0[FORMAT_VARIANT] = 2;
        unsafe { layer_enable(plain.ptr()) };
        assert_eq!(SWAPS.load(Ordering::SeqCst), 0);

        let mut alt = unarmed_layer();
        alt.0[DISABLED] = 1;
        alt.0[FORMAT_VARIANT] = FORMAT_VARIANT_ALT_COMMIT;
        unsafe { layer_enable(alt.ptr()) };
        assert_eq!(SWAPS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_SWAPPED_SURFACE.load(Ordering::SeqCst), 0, "a NULL surface");

        // No transition, no swap.
        unsafe { layer_enable(alt.ptr()) };
        assert_eq!(SWAPS.load(Ordering::SeqCst), 1);

        // The disable side never swaps.
        unsafe { layer_disable(alt.ptr()) };
        assert_eq!(SWAPS.load(Ordering::SeqCst), 1);

        restore_hooks(guard);
    }

    // ---- swap surface ----------------------------------------------------

    /// Serializes the tests that share the recording surface vtable.
    static SWAP_LOCK: StdMutex<()> = StdMutex::new(());
    /// Ordered event log: surface address | kind (0 = release,
    /// 1 = retain). Fake surfaces are aligned, so the low bit is free.
    static SWAP_EVENTS: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];
    static SWAP_EVENT_COUNT: AtomicUsize = AtomicUsize::new(0);

    fn record_swap_event(kind: usize, surface: *mut u8) {
        let index = SWAP_EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
        SWAP_EVENTS[index].store(surface as usize | kind, Ordering::SeqCst);
    }

    unsafe extern "C" fn recording_release(surface: *mut u8) {
        record_swap_event(0, surface);
    }

    unsafe extern "C" fn recording_retain(surface: *mut u8) {
        record_swap_event(1, surface);
    }

    static TEST_SURFACE_VTABLE: SurfaceVtable = SurfaceVtable {
        retain: recording_retain,
        release: recording_release,
    };

    /// A surface, modeled down to its first word — the vtable pointer.
    #[repr(C)]
    struct FakeSurface {
        vtable: *const SurfaceVtable,
    }

    impl FakeSurface {
        fn new() -> Self {
            FakeSurface { vtable: &TEST_SURFACE_VTABLE }
        }
        fn ptr(&mut self) -> *mut u8 {
            self as *mut FakeSurface as *mut u8
        }
    }

    impl Layer {
        fn set_bound_surface(&mut self, surface: *mut u8) {
            unsafe { (self.0.as_mut_ptr().add(BOUND_SURFACE) as *mut *mut u8).write(surface) };
        }
        fn bound_surface(&self) -> *mut u8 {
            unsafe { (self.0.as_ptr().add(BOUND_SURFACE) as *const *mut u8).read() }
        }
    }

    fn with_recording_surface_vtable() -> MutexGuard<'static, ()> {
        let guard = SWAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        SWAP_EVENT_COUNT.store(0, Ordering::SeqCst);
        guard
    }

    /// The log as (kind, surface address) pairs, oldest first.
    fn swap_events() -> std::vec::Vec<(usize, usize)> {
        (0..SWAP_EVENT_COUNT.load(Ordering::SeqCst))
            .map(|index| {
                let event = SWAP_EVENTS[index].load(Ordering::SeqCst);
                (event & 1, event & !1)
            })
            .collect()
    }

    #[test]
    fn swapping_onto_an_unbound_layer_only_retains_the_new_surface() {
        let _guard = with_recording_surface_vtable();
        let mut layer = unarmed_layer();
        let mut surface = FakeSurface::new();
        let surface_ptr = surface.ptr();

        unsafe { layer_swap_surface(layer.ptr(), surface_ptr) };

        assert_eq!(layer.bound_surface(), surface_ptr);
        assert_eq!(swap_events().as_slice(), &[(1, surface_ptr as usize)]);
    }

    #[test]
    fn swapping_releases_the_old_surface_before_retaining_the_new_one() {
        let _guard = with_recording_surface_vtable();
        let mut old = FakeSurface::new();
        let mut new = FakeSurface::new();
        let (old_ptr, new_ptr) = (old.ptr(), new.ptr());
        let mut layer = unarmed_layer();
        layer.set_bound_surface(old_ptr);

        unsafe { layer_swap_surface(layer.ptr(), new_ptr) };

        assert_eq!(layer.bound_surface(), new_ptr);
        assert_eq!(
            swap_events().as_slice(),
            &[(0, old_ptr as usize), (1, new_ptr as usize)],
            "release(old), then retain(new)"
        );
    }

    #[test]
    fn swapping_to_null_releases_without_retaining() {
        let _guard = with_recording_surface_vtable();
        let mut old = FakeSurface::new();
        let old_ptr = old.ptr();
        let mut layer = unarmed_layer();
        layer.set_bound_surface(old_ptr);

        unsafe { layer_swap_surface(layer.ptr(), core::ptr::null_mut()) };

        assert!(layer.bound_surface().is_null());
        assert_eq!(swap_events().as_slice(), &[(0, old_ptr as usize)]);
    }

    #[test]
    fn a_null_for_null_swap_calls_no_vtable_slot() {
        let _guard = with_recording_surface_vtable();
        let mut layer = unarmed_layer();
        unsafe { layer_swap_surface(layer.ptr(), core::ptr::null_mut()) };
        assert!(layer.bound_surface().is_null());
        assert!(swap_events().is_empty());
    }

    #[test]
    fn the_swap_touches_nothing_but_the_surface_slot() {
        let _guard = with_recording_surface_vtable();
        let mut layer = unarmed_layer();
        layer.0 = [0xa5; 0x200];
        let mut old = FakeSurface::new();
        layer.set_bound_surface(old.ptr());

        unsafe { layer_swap_surface(layer.ptr(), core::ptr::null_mut()) };

        assert!(layer.bound_surface().is_null());
        let slot = BOUND_SURFACE..BOUND_SURFACE + core::mem::size_of::<*mut u8>();
        for offset in 0..0x200 {
            if slot.contains(&offset) {
                continue;
            }
            assert_eq!(layer.byte(offset), 0xa5, "byte +{offset:#x}");
        }
    }

    // ---- surface plane address -----------------------------------------

    /// The surface object, modeled down to what `surface_plane_address`
    /// reads: the format byte at +0x08 and the three plane words.
    #[repr(align(4))]
    struct PlaneSurface([u8; 0x30]);

    const PLANE_A_WORD: u32 = 0x2000_0000;
    const PLANE_B_WORD: u32 = 0x2001_0000;
    const PLANE_C_WORD: u32 = 0x2001_4000;

    impl PlaneSurface {
        fn with_format(format: u8) -> Self {
            let mut surface = PlaneSurface([0; 0x30]);
            surface.0[SURFACE_FORMAT] = format;
            surface.set_word(SURFACE_PLANE_A, PLANE_A_WORD);
            surface.set_word(SURFACE_PLANE_B, PLANE_B_WORD);
            surface.set_word(SURFACE_PLANE_C, PLANE_C_WORD);
            surface
        }
        fn set_word(&mut self, offset: usize, value: u32) {
            self.0[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    /// The hand-computed truth table from the original's jump table,
    /// written out independently of the port.
    fn reference_plane_address(surface: &PlaneSurface, index: u32) -> u32 {
        let format = surface.0[SURFACE_FORMAT];
        let (a, b, c) = (
            surface.word(SURFACE_PLANE_A),
            surface.word(SURFACE_PLANE_B),
            surface.word(SURFACE_PLANE_C),
        );
        match index {
            0 => {
                if format == 0 || format == 1 {
                    a
                } else {
                    0
                }
            }
            1 => {
                if format == 1 {
                    b
                } else {
                    0
                }
            }
            2 => {
                if format == 0 {
                    b
                } else {
                    0
                }
            }
            3 => {
                if format == 0 {
                    c
                } else {
                    0
                }
            }
            4..=6 => {
                if u32::from(format) == index - 2 {
                    a
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    #[test]
    fn every_format_and_index_matches_the_reference_table() {
        for format in [0u8, 1, 2, 3, 4, 5, 0xff] {
            let mut surface = PlaneSurface::with_format(format);
            for index in 0..=7u32 {
                assert_eq!(
                    unsafe { surface_plane_address(surface.ptr(), index) },
                    reference_plane_address(&surface, index),
                    "format {format:#x}, index {index}"
                );
            }
        }
    }

    #[test]
    fn the_planar_format_exposes_all_three_planes() {
        let mut surface = PlaneSurface::with_format(0);
        assert_eq!(unsafe { surface_plane_address(surface.ptr(), 0) }, PLANE_A_WORD);
        assert_eq!(unsafe { surface_plane_address(surface.ptr(), 2) }, PLANE_B_WORD);
        assert_eq!(unsafe { surface_plane_address(surface.ptr(), 3) }, PLANE_C_WORD);
        assert_eq!(unsafe { surface_plane_address(surface.ptr(), 1) }, 0, "no packed alias");
    }

    #[test]
    fn the_two_plane_format_aliases_plane_a_and_b() {
        let mut surface = PlaneSurface::with_format(1);
        assert_eq!(unsafe { surface_plane_address(surface.ptr(), 0) }, PLANE_A_WORD);
        assert_eq!(unsafe { surface_plane_address(surface.ptr(), 1) }, PLANE_B_WORD);
        assert_eq!(unsafe { surface_plane_address(surface.ptr(), 2) }, 0);
        assert_eq!(unsafe { surface_plane_address(surface.ptr(), 3) }, 0);
    }

    #[test]
    fn each_packed_format_answers_only_its_own_index() {
        for (format, index) in [(2u8, 4u32), (3, 5), (4, 6)] {
            let mut surface = PlaneSurface::with_format(format);
            assert_eq!(
                unsafe { surface_plane_address(surface.ptr(), index) },
                PLANE_A_WORD,
                "format {format}, index {index}"
            );
            // The same index on the neighboring format is a miss.
            let mut other = PlaneSurface::with_format(format + 1);
            assert_eq!(unsafe { surface_plane_address(other.ptr(), index) }, 0);
        }
    }

    #[test]
    fn out_of_range_indices_and_unknown_formats_return_zero() {
        let mut surface = PlaneSurface::with_format(0);
        for index in [7u32, 8, 0xffff_ffff] {
            assert_eq!(unsafe { surface_plane_address(surface.ptr(), index) }, 0);
        }
        let mut unknown = PlaneSurface::with_format(9);
        for index in 0..=6u32 {
            assert_eq!(unsafe { surface_plane_address(unknown.ptr(), index) }, 0);
        }
    }

    #[test]
    fn the_lookup_is_purely_a_read() {
        let mut surface = PlaneSurface::with_format(0);
        let before = surface.0;
        for index in 0..=7u32 {
            unsafe { surface_plane_address(surface.ptr(), index) };
        }
        assert!(surface.0 == before);
    }

    // ---- query planes ----------------------------------------------------

    /// The four out-slots, poisoned so an untouched one is visible.
    struct PlaneSlots([*mut u8; PLANE_COUNT]);

    impl PlaneSlots {
        fn poisoned() -> Self {
            PlaneSlots([0xa5a5_a5a5 as *mut u8; PLANE_COUNT])
        }
        fn query(&mut self, layer: *mut u8) -> *mut u8 {
            unsafe {
                layer_query_planes(
                    layer,
                    &mut self.0[0],
                    &mut self.0[1],
                    &mut self.0[2],
                    &mut self.0[3],
                )
            }
        }
    }

    /// A layer of the given pixel format bound to a surface of the same
    /// format (the pairing real callers always have).
    fn bound_layer(layer_format: u8, surface: &mut PlaneSurface) -> Layer {
        let mut layer = unarmed_layer();
        layer.0[PIXEL_FORMAT] = layer_format;
        layer.set_bound_surface(surface.ptr());
        layer
    }

    #[test]
    fn an_unbound_layer_leaves_the_out_slots_untouched() {
        let mut layer = unarmed_layer();
        let mut slots = PlaneSlots::poisoned();
        let returned = slots.query(layer.ptr());
        assert_eq!(returned, layer.ptr());
        assert_eq!(slots.0, [0xa5a5_a5a5 as *mut u8; PLANE_COUNT]);
    }

    #[test]
    fn a_planar_layer_gets_the_three_component_planes_in_order() {
        let mut surface = PlaneSurface::with_format(0);
        let mut layer = bound_layer(0, &mut surface);
        let mut slots = PlaneSlots::poisoned();
        let returned = slots.query(layer.ptr());
        assert_eq!(returned, layer.ptr());
        assert_eq!(slots.0[0], PLANE_A_WORD as *mut u8);
        assert_eq!(slots.0[1], PLANE_B_WORD as *mut u8);
        assert_eq!(slots.0[2], PLANE_C_WORD as *mut u8);
        assert_eq!(slots.0[3], core::ptr::null_mut());
    }

    #[test]
    fn a_two_plane_layer_aliases_each_plane_into_two_slots() {
        let mut surface = PlaneSurface::with_format(1);
        let mut layer = bound_layer(1, &mut surface);
        let mut slots = PlaneSlots::poisoned();
        slots.query(layer.ptr());
        assert_eq!(slots.0[0], PLANE_A_WORD as *mut u8);
        assert_eq!(slots.0[2], PLANE_A_WORD as *mut u8, "plane A aliased into slot 2");
        assert_eq!(slots.0[1], PLANE_B_WORD as *mut u8);
        assert_eq!(slots.0[3], PLANE_B_WORD as *mut u8, "plane B aliased into slot 3");
    }

    #[test]
    fn the_packed_formats_fill_only_the_first_slot() {
        for format in [2u8, 3] {
            let mut surface = PlaneSurface::with_format(format);
            let mut layer = bound_layer(format, &mut surface);
            let mut slots = PlaneSlots::poisoned();
            slots.query(layer.ptr());
            assert_eq!(slots.0[0], PLANE_A_WORD as *mut u8, "format {format}");
            assert_eq!(
                slots.0[1..],
                [core::ptr::null_mut(); 3],
                "format {format} leaves the rest zeroed"
            );
        }
    }

    #[test]
    fn an_unknown_pixel_format_still_zeroes_all_four_slots() {
        // The zeroing stores run before the format dispatch, so even a
        // format the dispatch rejects leaves nothing poisoned.
        let mut surface = PlaneSurface::with_format(0);
        let mut layer = bound_layer(9, &mut surface);
        let mut slots = PlaneSlots::poisoned();
        let returned = slots.query(layer.ptr());
        assert_eq!(returned, layer.ptr());
        assert_eq!(slots.0, [core::ptr::null_mut(); PLANE_COUNT]);
    }

    #[test]
    fn a_format_mismatch_with_the_surface_yields_zeroed_slots() {
        // The accessor re-gates on the surface's own format byte: a
        // packed layer bound to a planar surface gets nothing back.
        let mut surface = PlaneSurface::with_format(0);
        let mut layer = bound_layer(2, &mut surface);
        let mut slots = PlaneSlots::poisoned();
        slots.query(layer.ptr());
        assert_eq!(slots.0, [core::ptr::null_mut(); PLANE_COUNT]);
    }

    #[test]
    fn the_query_writes_nothing_into_the_layer_itself() {
        let mut surface = PlaneSurface::with_format(0);
        let mut layer = unarmed_layer();
        layer.0 = [0x5a; 0x200];
        layer.0[PIXEL_FORMAT] = 0;
        layer.set_bound_surface(surface.ptr());
        let before = layer.0;
        let mut slots = PlaneSlots::poisoned();
        slots.query(layer.ptr());
        assert!(layer.0 == before);
        assert_eq!(slots.0[0], PLANE_A_WORD as *mut u8);
    }

    // ---- bind / reconfigure --------------------------------------------

    #[test]
    fn binding_a_surface_is_gated_on_format_variant_three() {
        let guard = with_recording_hooks();

        let mut plain = unarmed_layer();
        plain.0[FORMAT_VARIANT] = 2;
        unsafe { layer_bind_surface(plain.ptr(), 0x4000 as *mut u8) };
        assert_eq!(SWAPS.load(Ordering::SeqCst), 0);

        let mut alt = unarmed_layer();
        alt.0[FORMAT_VARIANT] = FORMAT_VARIANT_ALT_COMMIT;
        unsafe { layer_bind_surface(alt.ptr(), 0x4000 as *mut u8) };
        assert_eq!(SWAPS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_SWAPPED_SURFACE.load(Ordering::SeqCst), 0x4000);

        restore_hooks(guard);
    }

    #[test]
    fn reconfiguring_pipes_every_queried_plane_straight_into_the_installer() {
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0[FORMAT_VARIANT] = FORMAT_VARIANT_ALT_COMMIT;
        assert_eq!(unsafe { layer_reconfigure(layer.ptr(), 0x9000 as *mut u8) }, 0);

        assert_eq!(SWAPS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_SWAPPED_SURFACE.load(Ordering::SeqCst), 0x9000);
        assert_eq!(QUERIES.load(Ordering::SeqCst), 1);
        for (slot, installed) in INSTALLED.iter().enumerate() {
            assert_eq!(
                installed.load(Ordering::SeqCst),
                0x1000 + slot * 0x100,
                "plane {slot} must reach the installer in its own slot"
            );
        }

        restore_hooks(guard);
    }

    #[test]
    fn reconfiguring_a_plain_layer_still_queries_and_installs() {
        // Only the bind is variant-gated; the plane round trip is not.
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0[FORMAT_VARIANT] = 1;
        unsafe { layer_reconfigure(layer.ptr(), 0x9000 as *mut u8) };
        assert_eq!(SWAPS.load(Ordering::SeqCst), 0, "no surface swap");
        assert_eq!(QUERIES.load(Ordering::SeqCst), 1);
        assert_eq!(INSTALLED[3].load(Ordering::SeqCst), 0x1300);

        restore_hooks(guard);
    }

    #[test]
    fn reconfiguring_writes_nothing_into_the_layer_itself() {
        // Every field the layer gains comes from `install_planes`; the
        // original's own body only reads +0x0b.
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0 = [0x5a; 0x200];
        layer.0[FORMAT_VARIANT] = FORMAT_VARIANT_ALT_COMMIT;
        // The mutex cell must stay NULL or the lock pair reaches the ROM
        // table; +0x78..+0x80 is left as the poison would have it.
        layer.0[MUTEX..MUTEX + core::mem::size_of::<usize>()].fill(0);
        let before = layer.0;
        unsafe { layer_reconfigure(layer.ptr(), core::ptr::null_mut()) };
        assert!(layer.0 == before);

        restore_hooks(guard);
    }

    #[test]
    fn the_reconfigure_thunk_is_a_pure_alias_of_reconfigure() {
        // Same return value, same downstream traffic as the direct call.
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0[FORMAT_VARIANT] = FORMAT_VARIANT_ALT_COMMIT;
        assert_eq!(
            unsafe { layer_reconfigure_thunk(layer.ptr(), 0x9000 as *mut u8) },
            0
        );
        assert_eq!(SWAPS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_SWAPPED_SURFACE.load(Ordering::SeqCst), 0x9000);
        assert_eq!(QUERIES.load(Ordering::SeqCst), 1);
        for (slot, installed) in INSTALLED.iter().enumerate() {
            assert_eq!(
                installed.load(Ordering::SeqCst),
                0x1000 + slot * 0x100,
                "plane {slot} must pass through the thunk untouched"
            );
        }

        restore_hooks(guard);
    }

    // ---- force / restore enable ----------------------------------------

    #[test]
    fn forcing_an_already_enabled_layer_does_nothing_at_all() {
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        let before = layer.0;
        assert_eq!(unsafe { layer_force_enable(layer.ptr()) }, 0);
        assert!(layer.0 == before);
        assert_eq!(RENDERS.load(Ordering::SeqCst), 0);

        restore_hooks(guard);
    }

    #[test]
    fn forcing_a_hidden_layer_enables_renders_and_parks_it() {
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0[DISABLED] = 1;
        assert_eq!(unsafe { layer_force_enable(layer.ptr()) }, 1);
        assert_eq!(layer.byte(DISABLED), 0);
        assert_eq!(layer.byte(ENABLE_CHANGED), 1);
        assert_eq!(RENDERS.load(Ordering::SeqCst), 1);
        assert_eq!(layer.byte(DIRTY), 0, "the render consumed the dirty flag");
        assert_eq!(layer.byte(PARKED_ENABLE), 1);

        restore_hooks(guard);
    }

    #[test]
    fn restoring_an_unparked_layer_does_nothing_at_all() {
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0[DISABLED] = 0;
        let before = layer.0;
        assert_eq!(unsafe { layer_restore_enable(layer.ptr()) }, 0);
        assert!(layer.0 == before);
        assert_eq!(RENDERS.load(Ordering::SeqCst), 0);

        restore_hooks(guard);
    }

    #[test]
    fn force_then_restore_round_trips_a_hidden_layer() {
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0[DISABLED] = 1;
        unsafe { layer_force_enable(layer.ptr()) };
        assert_eq!(unsafe { layer_restore_enable(layer.ptr()) }, 1);
        assert_eq!(layer.byte(DISABLED), 1, "back to hidden");
        assert_eq!(layer.byte(PARKED_ENABLE), 0);
        assert_eq!(layer.byte(DIRTY), 0);
        assert_eq!(RENDERS.load(Ordering::SeqCst), 2);

        // Idempotent: a second restore is a no-op.
        assert_eq!(unsafe { layer_restore_enable(layer.ptr()) }, 0);
        assert_eq!(RENDERS.load(Ordering::SeqCst), 2);

        restore_hooks(guard);
    }

    #[test]
    fn restore_keys_off_the_parked_flag_alone_not_the_enable_state() {
        // Someone else enabling the layer in between does not stop the
        // restore from disabling it again.
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0[PARKED_ENABLE] = 1;
        layer.0[DISABLED] = 0;
        assert_eq!(unsafe { layer_restore_enable(layer.ptr()) }, 1);
        assert_eq!(layer.byte(DISABLED), 1);

        restore_hooks(guard);
    }

    #[test]
    fn forcing_an_alt_commit_layer_unbinds_its_surface_through_enable() {
        let guard = with_recording_hooks();

        let mut layer = unarmed_layer();
        layer.0[DISABLED] = 1;
        layer.0[FORMAT_VARIANT] = FORMAT_VARIANT_ALT_COMMIT;
        unsafe { layer_force_enable(layer.ptr()) };
        assert_eq!(SWAPS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_SWAPPED_SURFACE.load(Ordering::SeqCst), 0);

        restore_hooks(guard);
    }

    // ---- apply config --------------------------------------------------

    /// The 0x40-byte configuration block, as `surface_config_init`
    /// leaves it.
    #[repr(align(4))]
    struct Config([u8; 0x40]);

    impl Config {
        fn fresh() -> Self {
            let mut config = Config([0; 0x40]);
            unsafe { crate::drivers::surface::surface_config_init(config.0.as_mut_ptr()) };
            config
        }
        /// `&mut` and a writable raw pointer: the applier writes the
        /// resolved display size back into the caller's block.
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn word(&self, offset: usize) -> i32 {
            i32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
        }
        fn set_word(&mut self, offset: usize, value: i32) {
            self.0[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// A 320x240 config with a 100x50 image at (10, 20).
    fn panel_config() -> Config {
        let mut config = Config::fresh();
        config.set_word(CFG_ORIGIN_X, 10);
        config.set_word(CFG_ORIGIN_Y, 20);
        config.set_word(CFG_WIDTH, 100);
        config.set_word(CFG_HEIGHT, 50);
        config.set_word(CFG_BUFFER_WIDTH, 320);
        config.set_word(CFG_BUFFER_HEIGHT, 240);
        config
    }

    #[test]
    fn applying_a_config_copies_every_field_to_its_layer_slot() {
        let mut layer = unarmed_layer();
        let mut config = panel_config();
        config.set_word(CFG_SOURCE_X, 4);
        config.set_word(CFG_SOURCE_Y, 8);
        config.set_word(CFG_DISPLAY_WIDTH, 200);
        config.set_word(CFG_DISPLAY_HEIGHT, 150);
        config.0[CFG_SURFACE_FLAG] = 1;
        config.0[CFG_EXTRA_FLAG] = 2;
        config.set_word(CFG_OPAQUE_WORD, 0x1234_5678);
        config.0[CFG_TAIL_FLAG] = 3;
        config.set_word(CFG_TAIL_WORD_0, 0x0bad_f00d_u32 as i32);
        config.set_word(CFG_TAIL_WORD_1, 0x0000_0042);

        assert_eq!(unsafe { layer_apply_config(layer.ptr(), config.ptr()) }, 0);

        assert_eq!(layer.byte(PIXEL_FORMAT), 2);
        assert_eq!(layer.byte(FORMAT_VARIANT), 3);
        assert_eq!(layer.word(ORIGIN_X), 10);
        assert_eq!(layer.word(ORIGIN_Y), 20);
        assert_eq!(layer.word(SOURCE_X), 4);
        assert_eq!(layer.word(SOURCE_Y), 8);
        assert_eq!(layer.word(WIDTH), 100);
        assert_eq!(layer.word(HEIGHT), 50);
        assert_eq!(layer.word(BUFFER_WIDTH), 320);
        assert_eq!(layer.word(BUFFER_HEIGHT), 240);
        assert_eq!(layer.word(DISPLAY_WIDTH), 200);
        assert_eq!(layer.word(DISPLAY_HEIGHT), 150);
        assert_eq!(layer.byte(SURFACE_FLAG), 1);
        assert_eq!(layer.byte(EXTRA_FLAG), 2);
        assert_eq!(layer.word(OPAQUE_WORD), 0x1234_5678);
        assert_eq!(layer.byte(TAIL_FLAG), 3);
        assert_eq!(layer.word(TAIL_WORD_0), 0x0bad_f00d_u32 as i32);
        assert_eq!(layer.word(TAIL_WORD_1), 0x42);
        assert_eq!(layer.byte(CONFIGURED), 1);
        assert_eq!(layer.byte(GEOMETRY_SET), 1);
        assert_eq!(layer.byte(DIRTY), 1);
    }

    #[test]
    fn every_negative_geometry_word_is_clamped_to_zero() {
        let mut layer = unarmed_layer();
        let mut config = panel_config();
        for offset in [
            CFG_ORIGIN_X,
            CFG_ORIGIN_Y,
            CFG_SOURCE_X,
            CFG_SOURCE_Y,
            CFG_WIDTH,
            CFG_HEIGHT,
        ] {
            config.set_word(offset, -7);
        }
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        for offset in [ORIGIN_X, ORIGIN_Y, SOURCE_X, SOURCE_Y, WIDTH, HEIGHT] {
            assert_eq!(layer.word(offset), 0, "layer +{offset:#x}");
        }
    }

    #[test]
    fn the_buffer_size_is_raised_to_at_least_the_image_size() {
        let mut layer = unarmed_layer();
        let mut config = panel_config();
        config.set_word(CFG_BUFFER_WIDTH, 10);
        config.set_word(CFG_BUFFER_HEIGHT, 10);
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(layer.word(BUFFER_WIDTH), 100, "raised to the width");
        assert_eq!(layer.word(BUFFER_HEIGHT), 50, "raised to the height");

        // A buffer that already exceeds the image is left alone.
        let mut layer = unarmed_layer();
        let mut config = panel_config();
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(layer.word(BUFFER_WIDTH), 320);
        assert_eq!(layer.word(BUFFER_HEIGHT), 240);
    }

    #[test]
    fn the_clamp_uses_the_already_clamped_image_size() {
        // A negative height becomes 0, so a negative buffer height is
        // raised to 0 rather than to the raw -5.
        let mut layer = unarmed_layer();
        let mut config = panel_config();
        config.set_word(CFG_HEIGHT, -5);
        config.set_word(CFG_BUFFER_HEIGHT, -9);
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(layer.word(HEIGHT), 0);
        assert_eq!(layer.word(BUFFER_HEIGHT), 0);
    }

    #[test]
    fn the_auto_display_size_is_resolved_and_written_back() {
        let mut layer = unarmed_layer();
        let mut config = panel_config();
        // surface_config_init already armed both with -1.
        assert_eq!(config.word(CFG_DISPLAY_WIDTH), -1);
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(config.word(CFG_DISPLAY_WIDTH), 100, "written back");
        assert_eq!(config.word(CFG_DISPLAY_HEIGHT), 50, "written back");
        assert_eq!(layer.word(DISPLAY_WIDTH), 100);
        assert_eq!(layer.word(DISPLAY_HEIGHT), 50);
    }

    #[test]
    fn only_the_display_width_is_tested_for_the_auto_sentinel() {
        // -1 in the height alone is taken literally and NOT resolved.
        let mut layer = unarmed_layer();
        let mut config = panel_config();
        config.set_word(CFG_DISPLAY_WIDTH, 64);
        config.set_word(CFG_DISPLAY_HEIGHT, -1);
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(config.word(CFG_DISPLAY_HEIGHT), -1, "not written back");
        assert_eq!(layer.word(DISPLAY_WIDTH), 64);
        assert_eq!(layer.word(DISPLAY_HEIGHT), -1);
    }

    #[test]
    fn the_alpha_pixel_format_forces_the_pixel_alpha_blend_mode() {
        let mut layer = unarmed_layer();
        layer.0[BLEND_MODE] = BLEND_MODE_OPAQUE;
        let mut config = panel_config();
        config.0[CFG_PIXEL_FORMAT] = PIXEL_FORMAT_ALPHA;
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(layer.byte(PIXEL_FORMAT), PIXEL_FORMAT_ALPHA);
        assert_eq!(layer.byte(BLEND_MODE), BLEND_MODE_PIXEL_ALPHA);

        // Any other format leaves the mode alone.
        let mut layer = unarmed_layer();
        layer.0[BLEND_MODE] = BLEND_MODE_GLOBAL_ALPHA;
        let mut config = panel_config();
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(layer.byte(BLEND_MODE), BLEND_MODE_GLOBAL_ALPHA);
    }

    #[test]
    fn the_kind5_latch_follows_the_surface_flag() {
        let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore = |guard: MutexGuard<'static, ()>| {
            unsafe { KIND5_RENDER_SUPPRESSED = 0 };
            drop(guard);
        };

        // kind 5, subtype 0, surface flag 0 -> suppressed.
        let mut layer = unarmed_layer();
        layer.0[LAYER_KIND] = LAYER_KIND_LATCHED;
        let mut config = panel_config();
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(unsafe { KIND5_RENDER_SUPPRESSED }, 1);

        // ... and a nonzero surface flag clears it again.
        let mut config = panel_config();
        config.0[CFG_SURFACE_FLAG] = 1;
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(unsafe { KIND5_RENDER_SUPPRESSED }, 0);

        restore(guard);
    }

    #[test]
    fn any_other_layer_leaves_the_kind5_latch_alone() {
        let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { KIND5_RENDER_SUPPRESSED = 0xaa };

        for (kind, subtype) in [(4u8, 0u8), (LAYER_KIND_LATCHED, 1), (0, 0)] {
            let mut layer = unarmed_layer();
            layer.0[LAYER_KIND] = kind;
            layer.0[KIND_SUBTYPE] = subtype;
            let mut config = panel_config();
            unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
            assert_eq!(unsafe { KIND5_RENDER_SUPPRESSED }, 0xaa, "kind {kind}/{subtype}");
        }

        unsafe { KIND5_RENDER_SUPPRESSED = 0 };
        drop(guard);
    }

    #[test]
    fn applying_a_config_does_not_touch_the_enable_state_or_the_alpha() {
        let mut layer = unarmed_layer();
        layer.0[DISABLED] = 1;
        layer.0[ALPHA] = 0x33;
        let mut config = panel_config();
        unsafe { layer_apply_config(layer.ptr(), config.ptr()) };
        assert_eq!(layer.byte(DISABLED), 1);
        assert_eq!(layer.byte(ALPHA), 0x33);
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

    // ---- render --------------------------------------------------------

    /// Serializes the render suite (shared driver/hook recording
    /// statics).
    static RENDER_LOCK: StdMutex<()> = StdMutex::new(());
    static GEOMETRY_CALLS: AtomicU32 = AtomicU32::new(0);
    static ENABLE_STATE_CALLS: AtomicU32 = AtomicU32::new(0);
    static KIND5_FLAG_CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST_KIND5_FLAG: AtomicUsize = AtomicUsize::new(usize::MAX);
    static BLEND_CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST_BLEND_CODE: AtomicUsize = AtomicUsize::new(usize::MAX);
    static ALPHA_CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST_ALPHA: AtomicUsize = AtomicUsize::new(usize::MAX);
    static NOTIFY_CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST_NOTIFY: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
    static DESC_INIT_CALLS: AtomicU32 = AtomicU32::new(0);
    static FORMAT_CODE_CALLS: AtomicU32 = AtomicU32::new(0);
    /// Set by a test to make the geometry mock raise +0x43 mid-render.
    static GEOMETRY_RAISES_ENABLE: AtomicU32 = AtomicU32::new(0);
    /// The descriptor copy the geometry push last received.
    static mut CAPTURED_BLOCK: [u8; DESC_SIZE] = [0; DESC_SIZE];

    unsafe extern "C" fn mock_descriptor_init(desc: *mut u8) {
        DESC_INIT_CALLS.fetch_add(1, Ordering::SeqCst);
        // The stores of the original @ 0x0828302c that matter here: the
        // two zero bytes and the zeroed plane tail (the class word and
        // the -1 fields are overwritten or never copied out).
        desc.add(DESC_INIT_FIELD).write(0);
        desc.add(DESC_FORMAT_CODE).write(0);
        for offset in (DESC_PLANES..DESC_SIZE).step_by(4) {
            (desc.add(offset) as *mut u32).write(0);
        }
    }

    /// The original @ 0x08120ad4: pixel format -> plane-format code.
    unsafe extern "C" fn mock_plane_format_code(layer: *mut u8, out: *mut u8) {
        FORMAT_CODE_CALLS.fetch_add(1, Ordering::SeqCst);
        let code = match layer.add(PIXEL_FORMAT).read() {
            0 => 8,
            1 => 9,
            2 => 3,
            3 => 7,
            _ => return,
        };
        out.write(code);
    }

    unsafe extern "C" fn mock_notify(target: *mut u8, layer_id: u8, disabled: u8) {
        NOTIFY_CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_NOTIFY[0].store(target as usize, Ordering::SeqCst);
        LAST_NOTIFY[1].store(layer_id as usize, Ordering::SeqCst);
        LAST_NOTIFY[2].store(disabled as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn recording_push_geometry(
        _driver: *mut u8,
        layer_id: u8,
        desc: *mut u8,
    ) {
        GEOMETRY_CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_NOTIFY[1].store(layer_id as usize, Ordering::SeqCst);
        core::ptr::copy_nonoverlapping(
            desc,
            core::ptr::addr_of_mut!(CAPTURED_BLOCK) as *mut u8,
            DESC_SIZE,
        );
        if GEOMETRY_RAISES_ENABLE.load(Ordering::SeqCst) != 0 {
            // The original's callees may mutate the layer; the pass
            // re-tests the enable state at the tail.
            let layer = CURRENT_LAYER.load(Ordering::SeqCst) as *mut u8;
            layer.add(ENABLE_CHANGED).write(1);
        }
    }

    static CURRENT_LAYER: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recording_enable_state_changed(_driver: *mut u8, _layer_id: u8) {
        ENABLE_STATE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn recording_kind5_surface_flag(_driver: *mut u8, surface_flag: u8) {
        KIND5_FLAG_CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_KIND5_FLAG.store(surface_flag as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn recording_set_blend_mode(_driver: *mut u8, _layer_id: u8, code: u32) {
        BLEND_CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_BLEND_CODE.store(code as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn recording_set_global_alpha(_driver: *mut u8, _layer_id: u8, alpha: u8) {
        ALPHA_CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_ALPHA.store(alpha as usize, Ordering::SeqCst);
    }

    static TEST_DRIVER_VTABLE: DriverVtable = DriverVtable {
        _slots_0x00: [0; 5],
        push_geometry: recording_push_geometry,
        kind5_surface_flag: recording_kind5_surface_flag,
        _slots_0x1c: [0; 8],
        enable_state_changed: recording_enable_state_changed,
        set_blend_mode: recording_set_blend_mode,
        set_global_alpha: recording_set_global_alpha,
    };

    /// A display driver, modeled down to its vtable pointer.
    #[repr(C)]
    struct FakeDriver {
        vtable: *const DriverVtable,
    }

    impl FakeDriver {
        fn new() -> Self {
            FakeDriver { vtable: &TEST_DRIVER_VTABLE }
        }
        fn ptr(&mut self) -> *mut u8 {
            self as *mut FakeDriver as *mut u8
        }
    }

    impl Layer {
        fn set_ptr(&mut self, offset: usize, value: *mut u8) {
            unsafe { (self.0.as_mut_ptr().add(offset) as *mut *mut u8).write(value) };
        }
        fn ptr_at(&self, offset: usize) -> *mut u8 {
            unsafe { (self.0.as_ptr().add(offset) as *const *mut u8).read() }
        }
    }

    /// The captured descriptor copy as words/bytes.
    fn captured_byte(offset: usize) -> u8 {
        unsafe { core::ptr::addr_of!(CAPTURED_BLOCK).cast::<u8>().add(offset).read() }
    }
    fn captured_word(offset: usize) -> u32 {
        u32::from_le_bytes([
            captured_byte(offset),
            captured_byte(offset + 1),
            captured_byte(offset + 2),
            captured_byte(offset + 3),
        ])
    }

    /// The recording hooks with the REAL swap/query behind the render:
    /// only the unported callees are mocked.
    fn with_render_mocks() -> MutexGuard<'static, ()> {
        let guard = RENDER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        GEOMETRY_CALLS.store(0, Ordering::SeqCst);
        ENABLE_STATE_CALLS.store(0, Ordering::SeqCst);
        KIND5_FLAG_CALLS.store(0, Ordering::SeqCst);
        LAST_KIND5_FLAG.store(usize::MAX, Ordering::SeqCst);
        BLEND_CALLS.store(0, Ordering::SeqCst);
        LAST_BLEND_CODE.store(usize::MAX, Ordering::SeqCst);
        ALPHA_CALLS.store(0, Ordering::SeqCst);
        LAST_ALPHA.store(usize::MAX, Ordering::SeqCst);
        NOTIFY_CALLS.store(0, Ordering::SeqCst);
        for slot in &LAST_NOTIFY {
            slot.store(0, Ordering::SeqCst);
        }
        DESC_INIT_CALLS.store(0, Ordering::SeqCst);
        FORMAT_CODE_CALLS.store(0, Ordering::SeqCst);
        GEOMETRY_RAISES_ENABLE.store(0, Ordering::SeqCst);
        unsafe {
            LAYER_DRIVER_HOOKS = LayerDriverHooks {
                swap_surface: layer_swap_surface,
                query_planes: layer_query_planes,
                install_planes: install_planes_stub,
                render: layer_render,
                descriptor_init: mock_descriptor_init,
                plane_format_code: mock_plane_format_code,
                notify: mock_notify,
            }
        };
        guard
    }

    fn restore_render_mocks(guard: MutexGuard<'static, ()>) {
        unsafe { LAYER_DRIVER_HOOKS = DEFAULT_LAYER_DRIVER_HOOKS };
        drop(guard);
    }

    /// A dirty layer wired to a recording driver.
    fn render_layer(driver: &mut FakeDriver) -> Layer {
        let mut layer = unarmed_layer();
        layer.set_ptr(DRIVER, driver.ptr());
        layer.0[DIRTY] = 1;
        layer
    }

    #[test]
    fn a_clean_layer_is_not_rendered() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut layer = unarmed_layer();
        layer.set_ptr(DRIVER, driver.ptr());
        let before = layer.0;

        let returned = unsafe { layer_render(layer.ptr()) };
        assert_eq!(returned, layer.ptr());
        assert!(layer.0 == before, "a clean layer is untouched");
        assert_eq!(GEOMETRY_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(BLEND_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(ENABLE_STATE_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(NOTIFY_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(DESC_INIT_CALLS.load(Ordering::SeqCst), 0);

        restore_render_mocks(guard);
    }

    #[test]
    fn a_dirty_layer_pushes_geometry_and_the_opaque_blend_code() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut layer = render_layer(&mut driver);
        layer.0[PIXEL_FORMAT] = 2;
        layer.0[BLEND_MODE] = BLEND_MODE_OPAQUE;
        // The query leaves an unbound layer's plane block alone; the
        // alias then copies whatever words were planted there.
        layer.set_word(PLANES, 0x1111_2222);
        layer.set_word(PLANES + 4, 0x3333_4444);
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);

        let returned = unsafe { layer_render(layer.ptr()) };
        assert_eq!(returned, layer.ptr());
        assert_eq!(DESC_INIT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FORMAT_CODE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(GEOMETRY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(BLEND_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_BLEND_CODE.load(Ordering::SeqCst), 1, "mode 0 -> code 1");
        assert_eq!(ALPHA_CALLS.load(Ordering::SeqCst), 0, "mode 0 pushes no alpha");
        assert_eq!(ENABLE_STATE_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(NOTIFY_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(KIND5_FLAG_CALLS.load(Ordering::SeqCst), 0);
        // The descriptor copy: class word, then the descriptor +0x04...
        assert_eq!(
            captured_word(0),
            core::ptr::addr_of!(LAYER_RENDER_CLASS) as usize as u32,
            "the class word"
        );
        assert_eq!(captured_byte(DESC_FORMAT_CODE), 3, "pixel format 2 -> code 3");
        assert_eq!(captured_word(DESC_PLANES), 0x1111_2222, "packed format keeps plane 0");
        assert_eq!(captured_word(DESC_PLANES + 4), 0, "zeroed before aliasing");
        assert!(layer.ptr_at(LAST_SURFACE).is_null(), "NULL stored over NULL");
        assert_eq!(layer.byte(DIRTY), 1, "the pass does not clear the dirty flag");

        restore_render_mocks(guard);
    }

    #[test]
    fn the_descriptor_carries_the_layers_geometry_words() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut layer = render_layer(&mut driver);
        layer.0[DISABLED] = 1;
        layer.set_word(ORIGIN_X, 10);
        layer.set_word(ORIGIN_Y, 20);
        layer.set_word(SOURCE_X, 4);
        layer.set_word(SOURCE_Y, 8);
        layer.set_word(WIDTH, 100);
        layer.set_word(HEIGHT, 50);
        layer.set_word(DISPLAY_WIDTH, 200);
        layer.set_word(DISPLAY_HEIGHT, 150);
        layer.set_word(BUFFER_WIDTH, 320);
        layer.set_word(BUFFER_HEIGHT, 240);
        layer.0[TAIL_FLAG] = 3;
        layer.set_word(TAIL_WORD_0, 0x0bad_f00d_u32 as i32);
        layer.set_word(TAIL_WORD_1, 0x42);
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);

        unsafe { layer_render(layer.ptr()) };
        assert_eq!(captured_byte(DESC_DISABLED), 1);
        assert_eq!(captured_word(DESC_ORIGIN_X), 10);
        assert_eq!(captured_word(DESC_ORIGIN_Y), 20);
        assert_eq!(captured_word(DESC_SOURCE_X), 4);
        assert_eq!(captured_word(DESC_SOURCE_Y), 8);
        assert_eq!(captured_word(DESC_WIDTH), 100);
        assert_eq!(captured_word(DESC_HEIGHT), 50);
        assert_eq!(captured_word(DESC_DISPLAY_WIDTH), 200);
        assert_eq!(captured_word(DESC_DISPLAY_HEIGHT), 150);
        assert_eq!(captured_word(DESC_BUFFER_WIDTH), 320);
        assert_eq!(captured_word(DESC_BUFFER_HEIGHT), 240);
        assert_eq!(captured_byte(DESC_TAIL_FLAG), 3);
        assert_eq!(captured_word(DESC_TAIL_WORD_0), 0x0bad_f00d);
        assert_eq!(captured_word(DESC_TAIL_WORD_1), 0x42);

        restore_render_mocks(guard);
    }

    #[test]
    fn the_short_path_reports_the_enable_change_without_geometry() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut layer = render_layer(&mut driver);
        layer.0[LAYER_KIND] = 2;
        layer.0[ENABLE_CHANGED] = 1;
        layer.set_ptr(NOTIFY_TARGET, 0x5ead_beef as *mut u8);
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);

        let returned = unsafe { layer_render(layer.ptr()) };
        assert_eq!(returned, layer.ptr());
        assert_eq!(ENABLE_STATE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(layer.byte(ENABLE_CHANGED), 0, "consumed by the short path");
        assert_eq!(NOTIFY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_NOTIFY[0].load(Ordering::SeqCst), 0x5ead_beef, "the notify target");
        assert_eq!(LAST_NOTIFY[1].load(Ordering::SeqCst), 2, "the layer id");
        assert_eq!(LAST_NOTIFY[2].load(Ordering::SeqCst), 0, "the layer is enabled");
        assert_eq!(GEOMETRY_CALLS.load(Ordering::SeqCst), 0, "no descriptor");
        assert_eq!(BLEND_CALLS.load(Ordering::SeqCst), 0, "no blend push");
        assert_eq!(DESC_INIT_CALLS.load(Ordering::SeqCst), 0);

        restore_render_mocks(guard);
    }

    #[test]
    fn the_short_path_raises_the_kind5_latch() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();

        let mut layer = render_layer(&mut driver);
        layer.0[LAYER_KIND] = LAYER_KIND_LATCHED;
        layer.0[ENABLE_CHANGED] = 1;
        unsafe { KIND5_RENDER_SUPPRESSED = 0 };
        unsafe { layer_render(layer.ptr()) };
        assert_eq!(unsafe { KIND5_RENDER_SUPPRESSED }, 1, "kind 5, subtype 0");

        // Any other kind or subtype leaves the latch alone.
        unsafe { KIND5_RENDER_SUPPRESSED = 0 };
        let mut other = render_layer(&mut driver);
        other.0[LAYER_KIND] = LAYER_KIND_LATCHED;
        other.0[KIND_SUBTYPE] = 1;
        other.0[ENABLE_CHANGED] = 1;
        unsafe { layer_render(other.ptr()) };
        assert_eq!(unsafe { KIND5_RENDER_SUPPRESSED }, 0, "subtype 1 does not latch");

        unsafe { KIND5_RENDER_SUPPRESSED = 0 };
        restore_render_mocks(guard);
    }

    #[test]
    fn rendering_releases_the_handed_surface_and_retains_the_bound_one() {
        let _swap = with_recording_surface_vtable();
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut old = FakeSurface::new();
        let mut new = FakeSurface::new();
        let (old_ptr, new_ptr) = (old.ptr(), new.ptr());
        let mut layer = render_layer(&mut driver);
        layer.set_ptr(LAST_SURFACE, old_ptr);
        layer.set_bound_surface(new_ptr);
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);

        unsafe { layer_render(layer.ptr()) };
        assert_eq!(layer.ptr_at(LAST_SURFACE), new_ptr);
        assert_eq!(
            swap_events().as_slice(),
            &[(0, old_ptr as usize), (1, new_ptr as usize)],
            "release(handed), then retain(bound)"
        );

        restore_render_mocks(guard);
    }

    #[test]
    fn the_kind1_guard_bails_out_before_touching_anything() {
        let _swap = with_recording_surface_vtable();
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut old = FakeSurface::new();
        let mut new = FakeSurface::new();
        let (old_ptr, new_ptr) = (old.ptr(), new.ptr());
        let mut layer = render_layer(&mut driver);
        layer.0[KIND_SUBTYPE] = 1;
        layer.0[SURFACE_FLAG] = 1;
        layer.set_ptr(LAST_SURFACE, old_ptr);
        layer.set_ptr(PREVIOUS_SURFACE, 0x1111_0000 as *mut u8);
        layer.set_bound_surface(new_ptr);
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);

        let returned = unsafe { layer_render(layer.ptr()) };
        assert_eq!(returned, layer.ptr());
        assert_eq!(layer.ptr_at(LAST_SURFACE), old_ptr, "no swap happened");
        assert!(swap_events().is_empty(), "nothing released or retained");
        assert_eq!(layer.byte(DIRTY), 1, "the layer stays dirty");
        assert_eq!(GEOMETRY_CALLS.load(Ordering::SeqCst), 0);

        // When the previous surface IS the handed one, the guard passes.
        layer.set_ptr(PREVIOUS_SURFACE, old_ptr);
        unsafe { layer_render(layer.ptr()) };
        assert_eq!(layer.ptr_at(LAST_SURFACE), new_ptr);
        assert_eq!(
            swap_events().as_slice(),
            &[(0, old_ptr as usize), (1, new_ptr as usize)]
        );

        restore_render_mocks(guard);
    }

    #[test]
    fn the_blend_modes_reach_the_driver_as_codes() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        for (mode, code, alpha) in [
            (BLEND_MODE_OPAQUE, 1usize, None),
            (BLEND_MODE_GLOBAL_ALPHA, 3, Some(0x7fusize)),
            (BLEND_MODE_PIXEL_ALPHA, 2, None),
            (BLEND_MODE_PIXEL_AND_GLOBAL_ALPHA, 5, Some(0x7f)),
        ] {
            BLEND_CALLS.store(0, Ordering::SeqCst);
            LAST_BLEND_CODE.store(usize::MAX, Ordering::SeqCst);
            ALPHA_CALLS.store(0, Ordering::SeqCst);
            LAST_ALPHA.store(usize::MAX, Ordering::SeqCst);
            let mut layer = render_layer(&mut driver);
            layer.0[BLEND_MODE] = mode;
            layer.0[ALPHA] = 0x7f;
            CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);

            unsafe { layer_render(layer.ptr()) };
            assert_eq!(BLEND_CALLS.load(Ordering::SeqCst), 1, "mode {mode}");
            assert_eq!(LAST_BLEND_CODE.load(Ordering::SeqCst), code, "mode {mode}");
            match alpha {
                Some(expected) => {
                    assert_eq!(ALPHA_CALLS.load(Ordering::SeqCst), 1, "mode {mode}");
                    assert_eq!(LAST_ALPHA.load(Ordering::SeqCst), expected, "mode {mode}");
                }
                None => assert_eq!(ALPHA_CALLS.load(Ordering::SeqCst), 0, "mode {mode}"),
            }
        }

        // An unknown mode skips the blend dispatch entirely.
        BLEND_CALLS.store(0, Ordering::SeqCst);
        ALPHA_CALLS.store(0, Ordering::SeqCst);
        let mut layer = render_layer(&mut driver);
        layer.0[BLEND_MODE] = 4;
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);
        unsafe { layer_render(layer.ptr()) };
        assert_eq!(BLEND_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(ALPHA_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(GEOMETRY_CALLS.load(Ordering::SeqCst) > 0, true, "geometry still pushed");

        restore_render_mocks(guard);
    }

    /// A bound surface that is both retainable (a vtable pointer at
    /// +0x00) and plane-readable (the format byte and plane words, as
    /// [`PlaneSurface`] lays them out).
    #[repr(align(8))]
    struct RenderSurface([u8; 0x30]);

    impl RenderSurface {
        fn with_format(format: u8) -> Self {
            let mut surface = RenderSurface([0; 0x30]);
            unsafe {
                (surface.0.as_mut_ptr() as *mut *const SurfaceVtable)
                    .write(&TEST_SURFACE_VTABLE)
            };
            surface.0[SURFACE_FORMAT] = format;
            surface.0[SURFACE_PLANE_A..SURFACE_PLANE_A + 4]
                .copy_from_slice(&PLANE_A_WORD.to_le_bytes());
            surface.0[SURFACE_PLANE_B..SURFACE_PLANE_B + 4]
                .copy_from_slice(&PLANE_B_WORD.to_le_bytes());
            surface.0[SURFACE_PLANE_C..SURFACE_PLANE_C + 4]
                .copy_from_slice(&PLANE_C_WORD.to_le_bytes());
            surface
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    #[test]
    fn the_plane_words_are_aliased_by_pixel_format() {
        let _swap = with_recording_surface_vtable();
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();

        // Planar: all three planes, in the descriptor's 0/2/1 order.
        let mut surface = RenderSurface::with_format(0);
        let mut layer = render_layer(&mut driver);
        layer.0[PIXEL_FORMAT] = 0;
        layer.set_bound_surface(surface.ptr());
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);
        unsafe { layer_render(layer.ptr()) };
        assert_eq!(captured_word(DESC_PLANES), PLANE_A_WORD);
        assert_eq!(captured_word(DESC_PLANES + 4), PLANE_C_WORD, "plane 2 in the middle slot");
        assert_eq!(captured_word(DESC_PLANES + 8), PLANE_B_WORD, "plane 1 in the last slot");

        // Two-plane: A and B.
        let mut surface = RenderSurface::with_format(1);
        let mut layer = render_layer(&mut driver);
        layer.0[PIXEL_FORMAT] = 1;
        layer.set_bound_surface(surface.ptr());
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);
        unsafe { layer_render(layer.ptr()) };
        assert_eq!(captured_word(DESC_PLANES), PLANE_A_WORD);
        assert_eq!(captured_word(DESC_PLANES + 4), PLANE_B_WORD);
        assert_eq!(captured_word(DESC_PLANES + 8), 0, "zeroed before aliasing");

        // Packed: A only.
        let mut surface = RenderSurface::with_format(2);
        let mut layer = render_layer(&mut driver);
        layer.0[PIXEL_FORMAT] = 2;
        layer.set_bound_surface(surface.ptr());
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);
        unsafe { layer_render(layer.ptr()) };
        assert_eq!(captured_word(DESC_PLANES), PLANE_A_WORD);
        assert_eq!(captured_word(DESC_PLANES + 4), 0);
        assert_eq!(captured_word(DESC_PLANES + 8), 0);

        restore_render_mocks(guard);
    }

    #[test]
    fn a_disabled_layers_enable_change_notifies_on_the_long_path() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut layer = render_layer(&mut driver);
        layer.0[ENABLE_CHANGED] = 1;
        layer.0[DISABLED] = 1;
        layer.set_ptr(NOTIFY_TARGET, 0x5ead_beef as *mut u8);
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);

        unsafe { layer_render(layer.ptr()) };
        assert_eq!(NOTIFY_CALLS.load(Ordering::SeqCst), 1, "the change is reported");
        assert_eq!(LAST_NOTIFY[2].load(Ordering::SeqCst), 1, "as a disable");
        assert_eq!(GEOMETRY_CALLS.load(Ordering::SeqCst), 1, "the long path ran");
        // The tail only closes out a change on an ENABLED layer.
        assert_eq!(ENABLE_STATE_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(layer.byte(ENABLE_CHANGED), 1, "left for the next render");

        restore_render_mocks(guard);
    }

    #[test]
    fn a_kind5_layer_hands_the_driver_its_surface_flag() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut layer = render_layer(&mut driver);
        layer.0[LAYER_KIND] = LAYER_KIND_LATCHED;
        layer.0[SURFACE_FLAG] = 1;
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);

        unsafe { layer_render(layer.ptr()) };
        assert_eq!(KIND5_FLAG_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_KIND5_FLAG.load(Ordering::SeqCst), 1);

        // Any other kind skips the call.
        let mut other = render_layer(&mut driver);
        other.0[LAYER_KIND] = 4;
        CURRENT_LAYER.store(other.ptr() as usize, Ordering::SeqCst);
        KIND5_FLAG_CALLS.store(0, Ordering::SeqCst);
        unsafe { layer_render(other.ptr()) };
        assert_eq!(KIND5_FLAG_CALLS.load(Ordering::SeqCst), 0);

        restore_render_mocks(guard);
    }

    #[test]
    fn an_enable_change_raised_mid_render_is_closed_out_at_the_tail() {
        let guard = with_render_mocks();
        let mut driver = FakeDriver::new();
        let mut layer = render_layer(&mut driver);
        CURRENT_LAYER.store(layer.ptr() as usize, Ordering::SeqCst);
        GEOMETRY_RAISES_ENABLE.store(1, Ordering::SeqCst);

        unsafe { layer_render(layer.ptr()) };
        assert_eq!(ENABLE_STATE_CALLS.load(Ordering::SeqCst), 1, "the tail re-tests");
        assert_eq!(layer.byte(ENABLE_CHANGED), 0, "and clears the flag");

        restore_render_mocks(guard);
    }
}
