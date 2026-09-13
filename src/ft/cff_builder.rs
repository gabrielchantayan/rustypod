//! FreeType CFF glyph-loader builder (`cffgload.c`) — the point
//! recorder the Type 2 charstring interpreter feeds while decoding a
//! glyph outline. The interpreter (`cff_parse_charstrings`, unported @
//! 0x080df818 and its scaled siblings 0x080ea434 / 0x080ea5a0 /
//! 0x080eade0) decodes rmoveto/rlineto/rrcurveto operands into 16.16
//! coordinates and calls [`cff_builder_add_point`] per point: on-curve
//! flag nonzero for endpoints, zero for the two cubic control points of
//! each rrcurveto triplet (trace strings "rmoveto", "hlineto",
//! "rrcurveto", ... sit at 0x080e027c..0x080e06b0).
//!
//! The body decodes verbatim from the raw ARM at 0x080bfd14 as
//! FreeType's
//!
//! ```text
//! static void
//! cff_builder_add_point( CFF_Builder*  builder,
//!                        FT_Pos        x,
//!                        FT_Pos        y,
//!                        FT_Byte       flag )
//! {
//!   FT_Outline*  outline = builder->current;
//!
//!   if ( builder->load_points )
//!   {
//!     FT_Vector*  point   = outline->points + outline->n_points;
//!     FT_Byte*    control = (FT_Byte*)outline->tags  + outline->n_points;
//!
//!     point->x = x >> 16;
//!     point->y = y >> 16;
//!     *control = (FT_Byte)( flag ? FT_CURVE_TAG_ON : FT_CURVE_TAG_CUBIC );
//!
//!     builder->last = *point;
//!   }
//!
//!   outline->n_points++;
//! }}
//! ```
//!
//! The sibling capacity gate [`cff_check_points`] (cffgload.c
//! `check_points`, 0x0807ba0c) lives here too: it is the interpreter's
//! `will `count` more points fit?` pre-check, an inlined fast path of
//! `FT_GlyphLoader_CheckPoints` (unported @ 0x0804c638) over
//! `builder->loader`.

use crate::ft::types::{FtOutline, FtVector};
use core::ffi::c_void;

/// `FT_CURVE_TAG_ON` (ftimage.h) — the point lies on the curve.
pub const FT_CURVE_TAG_ON: u8 = 1;

/// `FT_CURVE_TAG_CUBIC` (ftimage.h) — cubic (rrcurveto) control point.
pub const FT_CURVE_TAG_CUBIC: u8 = 2;

/// `CFF_Builder` (cffgload.h `CFF_Builder_Rec`) sliced down to the
/// members the ported functions touch, at their firmware offsets: the
/// three head words (memory, face, glyph) at +0x00..+0x0b, `loader`
/// @ +0x0c, one more head word @ +0x10, `current` @ +0x14, `last` @
/// +0x18/+0x1c, `path_begun` @ +0x50 and `load_points` @ +0x51. The
/// +0x20..+0x4f span (left_bearing, advance, bbox, no_recurse, ...) is
/// opaque to this port.
///
/// `loader` and `current` are native pointers like the pointer fields
/// of ft/types.rs structs: exact on the 32-bit target, wider on 64-bit
/// hosts — all accesses are by field name, never by raw offset.
#[repr(C)]
pub struct CffBuilder {
    _reserved_00: [u32; 3],
    pub loader: *mut FtGlyphLoader,
    _reserved_10: u32,
    pub current: *mut FtOutline,
    pub last: FtVector,
    _reserved_20: [u32; 12],
    pub path_begun: u8,
    pub load_points: u8,
}

// Firmware layout: exact only where pointers are 32-bit.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(CffBuilder, loader)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(CffBuilder, current)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(CffBuilder, last)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x50] = [0; core::mem::offset_of!(CffBuilder, path_begun)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x51] = [0; core::mem::offset_of!(CffBuilder, load_points)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x54] = [0; core::mem::size_of::<CffBuilder>()];

/// cff_builder_add_point (FreeType `cff_builder_add_point`, cffgload.c)
/// — original: `FUN_080bfd14` @ 0x080bfd14 (100 bytes,
/// 0x080bfd14..0x080bfd78; the next function's `push {r4..r8, lr}`
/// prologue confirms the extent). 36 call sites verified by decoding
/// every B/BL word in osos.dec: 35 unconditional `bl` plus ONE `bleq`
/// (@ 0x080c8a54 in the 0x080c8a28 wrapper, which calls this with
/// `on_curve = 1` only when the 0x0807ba0c point-capacity check returns
/// 0 — a gated call, not a missing NULL guard here); no `b` tails, and
/// no DATA word holds the address, so it is never virtually dispatched.
///
/// Appends the 16.16 point `(x, y)` to the outline the builder is
/// recording into:
///
/// - `x`/`y` are truncated to integers by ARITHMETIC shift right 16
///   (`asr`, i.e. floor — negative fractions round away from zero);
/// - the tag byte is [`FT_CURVE_TAG_ON`] when `on_curve != 0`,
///   [`FT_CURVE_TAG_CUBIC`] otherwise (`cmp r3,#0 / movne 1 / moveq 2`);
/// - `builder->last` receives the TRUNCATED point (the original stores,
///   then reloads the pair with `ldm` before copying);
/// - `outline->n_points` is sign-extended for indexing (`ldrsh`) so a
///   negative count indexes BACKWARDS from `points`/`tags`, and is then
///   incremented via 16-bit `ldrh/add/strh` — OUTSIDE the `load_points`
///   guard, so a pass with `load_points == 0` still advances the count
///   without storing anything (the interpreter's point-counting pass).
///
/// No NULL guard on `builder`, `current`, `points` or `tags`, matching
/// the original: the interpreter guarantees them.
///
/// # Safety
/// `builder` must point to a valid [`CffBuilder`]; when
/// `load_points != 0`, `current->points` and `current->tags` must have
/// room for element `n_points` (as a SIGNED index).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_builder_add_point(
    builder: *mut CffBuilder,
    x: i32,
    y: i32,
    on_curve: i32,
) {
    let outline: *mut FtOutline = (*builder).current;
    if (*builder).load_points != 0 {
        let index = (*outline).n_points as isize;
        let point: *mut FtVector = (*outline).points.offset(index);
        (*point).x = x >> 16;
        (*point).y = y >> 16;
        *(*outline).tags.offset(index) =
            if on_curve != 0 { FT_CURVE_TAG_ON } else { FT_CURVE_TAG_CUBIC };
        (*builder).last = *point;
    }
    (*outline).n_points = (*outline).n_points.wrapping_add(1);
}

/// `FT_GlyphLoadRec` (internal/ftgloadr.h), as configured in the retail
/// FreeType build. Each embedded load occupies 32 bytes: its 20-byte outline,
/// then the auxiliary point pointer, subglyph count, and subglyph pointer.
/// `FT_GlyphLoader_Rewind` copies the complete record, so these tail fields
/// are represented instead of treated as opaque.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FtGlyphLoad {
    pub outline: FtOutline,
    pub extra_points: *mut FtVector,
    pub num_subglyphs: u32,
    pub subglyphs: *mut c_void,
}

// Firmware layout: exact only where pointers are 32-bit.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::size_of::<FtGlyphLoad>()];

/// `FT_GlyphLoaderRec` (internal/ftgloadr.h), including its two 32-byte
/// embedded glyph-load records. `base` starts at +0x14 and `current` at
/// +0x34 on the retail ARM ABI.
#[repr(C)]
pub struct FtGlyphLoader {
    _reserved_00: u32,
    pub max_points: u32,
    _reserved_08: [u32; 3],
    pub base: FtGlyphLoad,
    pub current: FtGlyphLoad,
}

// Firmware layout: exact only where pointers are 32-bit.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(FtGlyphLoader, max_points)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(FtGlyphLoader, base)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x34] = [0; core::mem::offset_of!(FtGlyphLoader, current)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x54] = [0; core::mem::size_of::<FtGlyphLoader>()];
/// `FT_GlyphLoader_Rewind` (FreeType internal/ftgloadr.c) — original:
/// `FUN_0804c9f4` @ `0x0804c9f4`, 32 bytes
/// (`0x0804c9f4..0x0804ca14`; the next `push {r4,r5,r6,lr}` confirms the
/// extent). Seven direct callers verified by decoding every ARM B/BL immediate
/// in `osos.dec`: seven unconditional `bl`, no predicated calls, and no tail
/// `b`.
///
/// Resets the base outline's signed contour and point counts, clears its
/// subglyph count, then copies the complete 32-byte base glyph-load record
/// into `current`. The three pointer-sized fields are assigned by name, which
/// preserves the 32-bit target layout without overlapping widened host
/// pointers.
///
/// Deliberate deviation: the original tail-branches to the IRAM memcpy veneer
/// at `0x08037df8`, whose return leaves `r0 = current + 0x20`; this typed
/// `void` port uses a fieldwise copy. Every verified caller overwrites or
/// ignores `r0` immediately after the call, so the differing dead return
/// register is unobservable.
///
/// # Safety
/// `loader` must be a valid, writable [`FtGlyphLoader`]. The retail routine
/// has no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_glyph_loader_rewind(loader: *mut FtGlyphLoader) {
    let loader = unsafe { &mut *loader };
    loader.base.outline.n_contours = 0;
    loader.base.outline.n_points = 0;
    loader.base.num_subglyphs = 0;
    loader.current = loader.base;
}

/// Firmware load address of the unported glyph-loader grow path
/// `FT_GlyphLoader_CheckPoints` @ 0x0804c638, which [`cff_check_points`]
/// tail-branches when the inlined head finds the outlines need to grow.
pub const FT_GLYPH_LOADER_CHECK_POINTS_ADDRESS: usize = 0x0804_c638;

/// Target default for [`GLYPH_LOADER_CHECK_POINTS`]: the stock
/// `FT_GlyphLoader_CheckPoints` @ 0x0804c638.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_glyph_loader_check_points(
    loader: *mut FtGlyphLoader,
    count: i32,
    new_contours: i32,
) -> i32 {
    let check: unsafe extern "C" fn(*mut FtGlyphLoader, i32, i32) -> i32 =
        core::mem::transmute(FT_GLYPH_LOADER_CHECK_POINTS_ADDRESS);
    check(loader, count, new_contours)
}

/// Host default for [`GLYPH_LOADER_CHECK_POINTS`]: the grow path remains
/// unported.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_glyph_loader_check_points(
    _loader: *mut FtGlyphLoader,
    _count: i32,
    _new_contours: i32,
) -> i32 {
    panic!("cff_check_points overflow requires FT_GlyphLoader_CheckPoints 0x0804c638")
}

/// Direct-call boundary for the unported `FT_GlyphLoader_CheckPoints`
/// @ 0x0804c638. Its head (which [`cff_check_points`] inlines) is
/// verified from raw ARM; the growth body reallocates the base and
/// current outline arrays. A later port replaces this seam without
/// changing this caller.
#[cfg(target_os = "none")]
pub static mut GLYPH_LOADER_CHECK_POINTS: unsafe extern "C" fn(
    loader: *mut FtGlyphLoader,
    count: i32,
    new_contours: i32,
) -> i32 = firmware_glyph_loader_check_points;

#[cfg(not(target_os = "none"))]
pub static mut GLYPH_LOADER_CHECK_POINTS: unsafe extern "C" fn(
    loader: *mut FtGlyphLoader,
    count: i32,
    new_contours: i32,
) -> i32 = missing_glyph_loader_check_points;

/// cff_check_points (FreeType `check_points`, cffgload.c) — original:
/// `FUN_0807ba0c` @ 0x0807ba0c (52 bytes, 0x0807ba0c..0x0807ba40; the
/// next function's `mov r3, r0 / push {lr}` prologue confirms the
/// extent — Ghidra's 52-byte report is exactly right here). 13 call
/// sites verified by decoding every B/BL word in osos.dec: all
/// unconditional `bl` (@ 0x080c8a3c, 0x080e0170, 0x080e0218,
/// 0x080e0354, 0x080e0448, 0x080e0528, 0x080e0614, 0x080e0794,
/// 0x080e088c, 0x080e0968, 0x080e0a60, 0x080e0b90, 0x080e0c94 — the
/// cff charstring interpreter and its scaled siblings); no `b` tails
/// and no DATA word holds the address, so it is never virtually
/// dispatched.
///
/// The Type 2 interpreter's "will `count` more points fit?" gate,
/// called before recording points (e.g. the 0x080c8a28 wrapper calls
/// [`cff_builder_add_point`] with on_curve=1 only when this returns 0).
/// It is `FT_GlyphLoader_CheckPoints(builder->loader, count, 0)` with
/// the loader head partially inlined by the ADS compiler:
///
/// - `count == 0` returns 0 IMMEDIATELY, before `builder` is
///   dereferenced (`cmp r1,#0 / beq`), so a NULL builder with a zero
///   count is safe;
/// - otherwise `need = base.n_points + current.n_points + count` with
///   both counts sign-extended (`ldrsh` @ loader+0x16 and +0x36 —
///   NEGATIVE counts subtract) and wrapping 32-bit adds;
/// - if `need > loader->max_points` (SIGNED `bgt`), zero r2 and
///   tail-branch the out-of-line `FT_GlyphLoader_CheckPoints` @
///   0x0804c638, whose return value becomes ours;
/// - else return 0 (FT_Err_Ok). Equal-to-capacity fits: the original
///   uses `bgt`, not `bge`.
///
/// Deliberate deviation: the tail `bgt` (which reuses the caller's
/// return address and leaves r2=0 as the third argument) is a plain
/// `return` of the seam call's value in Rust; the unported callee sits
/// behind [`GLYPH_LOADER_CHECK_POINTS`], wired to 0x0804c638 on target
/// and a test model on host.
///
/// # Safety
/// When `count != 0`, `builder` must point to a valid [`CffBuilder`]
/// whose `loader` points to a valid [`FtGlyphLoader`]. No NULL guards,
/// matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_check_points(builder: *mut CffBuilder, count: i32) -> i32 {
    if count == 0 {
        return 0;
    }
    let loader: *mut FtGlyphLoader = (*builder).loader;
    let need = ((*loader).base.outline.n_points as i32)
        .wrapping_add((*loader).current.outline.n_points as i32)
        .wrapping_add(count);
    if need > (*loader).max_points as i32 {
        let check = core::ptr::addr_of!(GLYPH_LOADER_CHECK_POINTS).read_volatile();
        return check(loader, count, 0);
    }
    0
}

/// Firmware load address of the unported `cff_builder_add_contour`
/// (0x080cc9d8), which [`cff_builder_start_point`] invokes before
/// recording its first point.
pub const CFF_BUILDER_ADD_CONTOUR_ADDRESS: usize = 0x080c_c9d8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_cff_builder_add_contour(builder: *mut CffBuilder) -> i32 {
    let add_contour: unsafe extern "C" fn(*mut CffBuilder) -> i32 =
        core::mem::transmute(CFF_BUILDER_ADD_CONTOUR_ADDRESS);
    add_contour(builder)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cff_builder_add_contour(_builder: *mut CffBuilder) -> i32 {
    panic!("cff_builder_start_point requires cff_builder_add_contour 0x080cc9d8")
}

/// Direct-call boundary for the unported `cff_builder_add_contour` @
/// 0x080cc9d8. It records the preceding contour and grows its storage when
/// needed; a later port can replace this seam without changing the start
/// point logic.
#[cfg(target_os = "none")]
pub static mut CFF_BUILDER_ADD_CONTOUR: unsafe extern "C" fn(*mut CffBuilder) -> i32 =
    firmware_cff_builder_add_contour;

#[cfg(not(target_os = "none"))]
pub static mut CFF_BUILDER_ADD_CONTOUR: unsafe extern "C" fn(*mut CffBuilder) -> i32 =
    missing_cff_builder_add_contour;

/// cff_builder_start_point (FreeType `cff_builder_start_point`, cffgload.c)
/// — original: `FUN_080cca60` @ 0x080cca60 (76 bytes,
/// 0x080cca60..0x080ccaac; the next function starts with `ldr r0,[r0,#0x8c]`).
/// 12 call sites verified by decoding every B/BL word in osos.dec: all are
/// unconditional `bl` (0x080e0158, 0x080e0204, 0x080e033c, 0x080e040c,
/// 0x080e04ec, 0x080e05d8, 0x080e0780, 0x080e0874, 0x080e0954,
/// 0x080e0a4c, 0x080e0b7c, 0x080e0c80); no `b` tails and no DATA word holds
/// the address, so it is not virtually dispatched.
///
/// Starts an outline path exactly once: a pre-existing `path_begun` returns
/// success untouched; otherwise marks it begun, records the preceding
/// contour through the stock `cff_builder_add_contour` seam, then checks
/// capacity for one point and appends `(x,y)` as on-curve if it fits.
/// Contour and capacity errors propagate; the capacity error leaves the new
/// path begun but writes no point.
///
/// Deliberate deviation: the ARM tail-branches to unported
/// `FUN_080c8a28`, whose verified body is the same `cff_check_points(...,1)`
/// followed by `cff_builder_add_point(...,1)` sequence expressed directly
/// here. The preceding unported 0x080cc9d8 call remains a direct seam.
///
/// # Safety
/// `builder` must point to a valid [`CffBuilder`], and its members must meet
/// the safety requirements of the called contour, capacity, and point paths.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_builder_start_point(
    builder: *mut CffBuilder,
    x: i32,
    y: i32,
) -> i32 {
    if (*builder).path_begun != 0 {
        return 0;
    }
    (*builder).path_begun = 1;
    let add_contour = core::ptr::addr_of!(CFF_BUILDER_ADD_CONTOUR).read_volatile();
    let error = add_contour(builder);
    if error != 0 {
        return error;
    }
    let error = cff_check_points(builder, 1);
    if error == 0 {
        cff_builder_add_point(builder, x, y, 1);
    }
    error
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// A builder + outline + backing arrays, all on the stack; the
    /// builder's `current` points at the outline.
    struct Fixture {
        points: [FtVector; 8],
        tags: [u8; 8],
        outline: FtOutline,
        builder: CffBuilder,
    }

    impl Fixture {
        /// Boxed so the fixture's address is stable before the internal
        /// pointers are wired (they point INTO the fixture itself).
        fn new(n_points: i16, load_points: u8) -> std::boxed::Box<Self> {
            let mut fx = std::boxed::Box::new(Fixture {
                points: [FtVector { x: -777, y: 888 }; 8],
                tags: [0xaa; 8],
                outline: FtOutline {
                    n_contours: 0,
                    n_points,
                    points: core::ptr::null_mut(),
                    tags: core::ptr::null_mut(),
                    contours: core::ptr::null_mut(),
                    flags: 0,
                },
                builder: CffBuilder {
                    _reserved_00: [0xdeadbeef; 3],
                    loader: core::ptr::null_mut(),
                    _reserved_10: 0xdeadbeef,
                    current: core::ptr::null_mut(),
                    last: FtVector { x: -1, y: -1 },
                    _reserved_20: [0xdeadbeef; 12],
                    path_begun: 0xde,
                    load_points,
                },
            });
            fx.outline.points = fx.points.as_mut_ptr();
            fx.outline.tags = fx.tags.as_mut_ptr();
            fx.builder.current = &mut fx.outline;
            fx
        }
    }

    #[test]
    fn records_on_curve_point_and_truncates_16_16() {
        let mut fx = Fixture::new(0, 1);
        // (2.5, -1.5) in 16.16: x = 0x0002_8000, y = -0x0001_8000.
        unsafe { cff_builder_add_point(&mut fx.builder, 0x0002_8000, -0x0001_8000, 1) };
        // Arithmetic shift: 2.5 -> 2, -1.5 -> -2 (floor, not truncate-to-zero).
        assert_eq!(fx.points[0], FtVector { x: 2, y: -2 });
        assert_eq!(fx.tags[0], FT_CURVE_TAG_ON);
        assert_eq!(fx.builder.last, FtVector { x: 2, y: -2 });
        assert_eq!(fx.outline.n_points, 1);
        // Neighbours untouched.
        assert_eq!(fx.points[1], FtVector { x: -777, y: 888 });
        assert_eq!(fx.tags[1], 0xaa);
    }

    #[test]
    fn zero_flag_marks_cubic_control_point() {
        let mut fx = Fixture::new(0, 1);
        unsafe { cff_builder_add_point(&mut fx.builder, 0, 0, 0) };
        assert_eq!(fx.tags[0], FT_CURVE_TAG_CUBIC);
        assert_eq!(fx.outline.n_points, 1);
    }

    #[test]
    fn any_nonzero_flag_is_on_curve() {
        let mut fx = Fixture::new(0, 1);
        unsafe { cff_builder_add_point(&mut fx.builder, 0, 0, -7) };
        assert_eq!(fx.tags[0], FT_CURVE_TAG_ON);
    }

    #[test]
    fn counting_pass_stores_nothing_but_still_increments() {
        let mut fx = Fixture::new(3, 0);
        unsafe { cff_builder_add_point(&mut fx.builder, 0x0005_0000, 0x0006_0000, 1) };
        // n_points advanced, but no point/tag/last was written.
        assert_eq!(fx.outline.n_points, 4);
        assert!(fx.points.iter().all(|p| *p == FtVector { x: -777, y: 888 }));
        assert!(fx.tags.iter().all(|t| *t == 0xaa));
        assert_eq!(fx.builder.last, FtVector { x: -1, y: -1 });
    }

    #[test]
    fn nonzero_index_appends_at_n_points() {
        let mut fx = Fixture::new(5, 1);
        unsafe { cff_builder_add_point(&mut fx.builder, 0x0009_0000, 0x000a_ffff, 1) };
        assert_eq!(fx.points[5], FtVector { x: 9, y: 10 });
        assert_eq!(fx.tags[5], FT_CURVE_TAG_ON);
        assert_eq!(fx.points[4], FtVector { x: -777, y: 888 });
        assert_eq!(fx.tags[4], 0xaa);
        assert_eq!(fx.outline.n_points, 6);
    }

    #[test]
    fn negative_n_points_indexes_backwards() {
        // ldrsh sign-extends the count: n_points == -1 writes element
        // `points[-1]`. Back the arrays one element in so the slot is real.
        let mut fx = Fixture::new(-1, 1);
        fx.outline.points = unsafe { fx.points.as_mut_ptr().add(1) };
        fx.outline.tags = unsafe { fx.tags.as_mut_ptr().add(1) };
        unsafe { cff_builder_add_point(&mut fx.builder, 0x0003_0000, 0x0004_0000, 1) };
        assert_eq!(fx.points[0], FtVector { x: 3, y: 4 });
        assert_eq!(fx.tags[0], FT_CURVE_TAG_ON);
        assert_eq!(fx.builder.last, FtVector { x: 3, y: 4 });
        assert_eq!(fx.outline.n_points, 0); // -1 + 1
    }

    #[test]
    fn n_points_increment_wraps_as_i16() {
        let mut fx = Fixture::new(i16::MAX, 0);
        unsafe { cff_builder_add_point(&mut fx.builder, 0, 0, 1) };
        assert_eq!(fx.outline.n_points, i16::MIN); // ldrh/add/strh low 16 bits
    }

    #[test]
    fn other_builder_fields_untouched() {
        let mut fx = Fixture::new(0, 1);
        unsafe { cff_builder_add_point(&mut fx.builder, 0x0001_0000, 0x0002_0000, 1) };
        assert!(fx.builder._reserved_00.iter().all(|w| *w == 0xdeadbeef));
        assert_eq!(fx.builder._reserved_10, 0xdeadbeef);
        assert!(fx.builder._reserved_20.iter().all(|w| *w == 0xdeadbeef));
        assert_eq!(fx.builder.path_begun, 0xde);
        assert_eq!(fx.builder.load_points, 1);
    }

    // --- cff_check_points ---

    use parking_lot::Mutex;

    /// Serializes the tests that override [`GLYPH_LOADER_CHECK_POINTS`].
    static CHECK_LOCK: Mutex<()> = Mutex::new(());

    /// Recorded arguments of the most recent seam call.
    static SEAM_CALLS: Mutex<std::vec::Vec<(usize, i32, i32)>> =
        Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_check_points(
        loader: *mut FtGlyphLoader,
        count: i32,
        new_contours: i32,
    ) -> i32 {
        SEAM_CALLS.lock().push((loader as usize, count, new_contours));
        7 // a distinguishable FT_Error value
    }

    /// A builder + glyph loader, boxed for a stable address; the
    /// builder's `loader` points at the loader record.
    struct CheckFixture {
        loader: FtGlyphLoader,
        builder: CffBuilder,
    }

    impl CheckFixture {
        fn new(base_points: i16, current_points: i16, max_points: u32) -> std::boxed::Box<Self> {
            let blank_outline = FtOutline {
                n_contours: 0,
                n_points: 0,
                points: core::ptr::null_mut(),
                tags: core::ptr::null_mut(),
                contours: core::ptr::null_mut(),
                flags: 0,
            };
            let mut fx = std::boxed::Box::new(CheckFixture {
                loader: FtGlyphLoader {
                    _reserved_00: 0xdeadbeef,
                    max_points,
                    _reserved_08: [0xdeadbeef; 3],
                    base: FtGlyphLoad {
                        outline: FtOutline {
                            n_points: base_points,
                            ..blank_outline
                        },
                        extra_points: core::ptr::null_mut(),
                        num_subglyphs: 0xdeadbeef,
                        subglyphs: core::ptr::null_mut(),
                    },
                    current: FtGlyphLoad {
                        outline: FtOutline {
                            n_points: current_points,
                            ..blank_outline
                        },
                        extra_points: core::ptr::null_mut(),
                        num_subglyphs: 0xdeadbeef,
                        subglyphs: core::ptr::null_mut(),
                    },
                },
                builder: CffBuilder {
                    _reserved_00: [0xdeadbeef; 3],
                    loader: core::ptr::null_mut(),
                    _reserved_10: 0xdeadbeef,
                    current: core::ptr::null_mut(),
                    last: FtVector { x: -1, y: -1 },
                    _reserved_20: [0xdeadbeef; 12],
                    path_begun: 0xde,
                    load_points: 0,
                },
            });
            fx.builder.loader = &mut fx.loader;
            fx
        }
    }

    /// Installs the recording seam for the duration of `body`.
    fn with_seam(body: impl FnOnce()) {
        let _lock = CHECK_LOCK.lock();
        SEAM_CALLS.lock().clear();
        let saved = unsafe { core::ptr::addr_of!(GLYPH_LOADER_CHECK_POINTS).read_volatile() };
        unsafe {
            core::ptr::addr_of_mut!(GLYPH_LOADER_CHECK_POINTS).write_volatile(record_check_points)
        };
        body();
        unsafe { core::ptr::addr_of_mut!(GLYPH_LOADER_CHECK_POINTS).write_volatile(saved) };
    }

    static CONTOUR_LOCK: Mutex<()> = Mutex::new(());
    static CONTOUR_CALLS: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_add_contour(builder: *mut CffBuilder) -> i32 {
        CONTOUR_CALLS.lock().push(builder as usize);
        0
    }

    unsafe extern "C" fn fail_add_contour(builder: *mut CffBuilder) -> i32 {
        CONTOUR_CALLS.lock().push(builder as usize);
        9
    }

    fn with_contour_seam(
        seam: unsafe extern "C" fn(*mut CffBuilder) -> i32,
        body: impl FnOnce(),
    ) {
        let _lock = CONTOUR_LOCK.lock();
        CONTOUR_CALLS.lock().clear();
        let saved = unsafe { core::ptr::addr_of!(CFF_BUILDER_ADD_CONTOUR).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(CFF_BUILDER_ADD_CONTOUR).write_volatile(seam) };
        body();
        unsafe { core::ptr::addr_of_mut!(CFF_BUILDER_ADD_CONTOUR).write_volatile(saved) };
    }

    struct StartPointFixture {
        points: [FtVector; 2],
        tags: [u8; 2],
        outline: FtOutline,
        loader: FtGlyphLoader,
        builder: CffBuilder,
    }

    impl StartPointFixture {
        fn new(max_points: u32, load_points: u8) -> std::boxed::Box<Self> {
            let mut fx = std::boxed::Box::new(StartPointFixture {
                points: [FtVector { x: -777, y: 888 }; 2],
                tags: [0xaa; 2],
                outline: FtOutline {
                    n_contours: 0,
                    n_points: 0,
                    points: core::ptr::null_mut(),
                    tags: core::ptr::null_mut(),
                    contours: core::ptr::null_mut(),
                    flags: 0,
                },
                loader: FtGlyphLoader {
                    _reserved_00: 0xdeadbeef,
                    max_points,
                    _reserved_08: [0xdeadbeef; 3],
                    base: FtGlyphLoad {
                        outline: FtOutline {
                            n_contours: 0,
                            n_points: 0,
                            points: core::ptr::null_mut(),
                            tags: core::ptr::null_mut(),
                            contours: core::ptr::null_mut(),
                            flags: 0,
                        },
                        extra_points: core::ptr::null_mut(),
                        num_subglyphs: 0xdeadbeef,
                        subglyphs: core::ptr::null_mut(),
                    },
                    current: FtGlyphLoad {
                        outline: FtOutline {
                            n_contours: 0,
                            n_points: 0,
                            points: core::ptr::null_mut(),
                            tags: core::ptr::null_mut(),
                            contours: core::ptr::null_mut(),
                            flags: 0,
                        },
                        extra_points: core::ptr::null_mut(),
                        num_subglyphs: 0xdeadbeef,
                        subglyphs: core::ptr::null_mut(),
                    },
                },
                builder: CffBuilder {
                    _reserved_00: [0xdeadbeef; 3],
                    loader: core::ptr::null_mut(),
                    _reserved_10: 0xdeadbeef,
                    current: core::ptr::null_mut(),
                    last: FtVector { x: -1, y: -1 },
                    _reserved_20: [0xdeadbeef; 12],
                    path_begun: 0,
                    load_points,
                },
            });
            fx.outline.points = fx.points.as_mut_ptr();
            fx.outline.tags = fx.tags.as_mut_ptr();
            fx.builder.current = &mut fx.outline;
            fx.builder.loader = &mut fx.loader;
            fx
        }
    }

    #[test]
    fn zero_count_returns_ok_without_touching_builder() {
        // `cmp r1,#0 / beq` runs BEFORE the loader load: even a NULL
        // builder is never dereferenced.
        let rc = unsafe { cff_check_points(core::ptr::null_mut(), 0) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn fits_within_capacity_returns_ok() {
        let mut fx = CheckFixture::new(10, 5, 100);
        with_seam(|| {
            let rc = unsafe { cff_check_points(&mut fx.builder, 20) };
            assert_eq!(rc, 0);
            assert!(SEAM_CALLS.lock().is_empty());
        });
    }

    #[test]
    fn exactly_at_capacity_fits() {
        // need == max_points: the original uses `bgt`, not `bge`.
        let mut fx = CheckFixture::new(10, 5, 35);
        with_seam(|| {
            let rc = unsafe { cff_check_points(&mut fx.builder, 20) };
            assert_eq!(rc, 0);
            assert!(SEAM_CALLS.lock().is_empty());
        });
    }

    #[test]
    fn overflow_tail_calls_grow_path_with_zero_contours() {
        let mut fx = CheckFixture::new(10, 5, 35);
        with_seam(|| {
            let rc = unsafe { cff_check_points(&mut fx.builder, 21) };
            assert_eq!(rc, 7); // the seam's return propagates
            let calls = SEAM_CALLS.lock();
            assert_eq!(
                calls.as_slice(),
                [(&mut fx.loader as *mut _ as usize, 21, 0)]
            );
        });
    }

    #[test]
    fn n_points_are_sign_extended() {
        // base.n_points == -1: signed need = -1 + 0 + 1 = 0, which is
        // NOT > max_points == 0, so no grow. A zero-extending (u16)
        // reader would compute 0x10000 > 0 and grow.
        let mut fx = CheckFixture::new(-1, 0, 0);
        with_seam(|| {
            let rc = unsafe { cff_check_points(&mut fx.builder, 1) };
            assert_eq!(rc, 0);
            assert!(SEAM_CALLS.lock().is_empty());
        });
    }

    #[test]
    fn negative_current_n_points_subtracts() {
        let mut fx = CheckFixture::new(0, -4, 0);
        with_seam(|| {
            let rc = unsafe { cff_check_points(&mut fx.builder, 3) };
            assert_eq!(rc, 0);
            assert!(SEAM_CALLS.lock().is_empty());
        });
    }

    #[test]
    fn negative_count_never_grows() {
        let mut fx = CheckFixture::new(10, 5, 0);
        with_seam(|| {
            let rc = unsafe { cff_check_points(&mut fx.builder, -20) };
            assert_eq!(rc, 0);
            assert!(SEAM_CALLS.lock().is_empty());
        });
    }

    // --- cff_builder_start_point ---

    #[test]
    fn started_path_returns_ok_without_calling_contour_seam() {
        let mut fx = StartPointFixture::new(1, 1);
        fx.builder.path_begun = 0xff;
        let rc = unsafe { cff_builder_start_point(&mut fx.builder, 0x0001_0000, 0x0002_0000) };
        assert_eq!(rc, 0);
        assert_eq!(fx.builder.path_begun, 0xff);
        assert_eq!(fx.outline.n_points, 0);
        assert_eq!(fx.points[0], FtVector { x: -777, y: 888 });
        assert_eq!(fx.tags[0], 0xaa);
    }

    #[test]
    fn contour_error_starts_path_and_propagates_without_adding_point() {
        let mut fx = StartPointFixture::new(1, 1);
        let builder = &mut fx.builder as *mut CffBuilder as usize;
        with_contour_seam(fail_add_contour, || {
            let rc = unsafe { cff_builder_start_point(&mut fx.builder, 0x0001_0000, 0x0002_0000) };
            assert_eq!(rc, 9);
            assert_eq!(CONTOUR_CALLS.lock().as_slice(), [builder]);
        });
        assert_eq!(fx.builder.path_begun, 1);
        assert_eq!(fx.outline.n_points, 0);
        assert_eq!(fx.points[0], FtVector { x: -777, y: 888 });
        assert_eq!(fx.tags[0], 0xaa);
    }

    #[test]
    fn starts_path_then_records_one_on_curve_point() {
        let mut fx = StartPointFixture::new(1, 1);
        let builder = &mut fx.builder as *mut CffBuilder as usize;
        with_contour_seam(record_add_contour, || {
            let rc = unsafe { cff_builder_start_point(&mut fx.builder, 0x0002_8000, -0x0001_8000) };
            assert_eq!(rc, 0);
            assert_eq!(CONTOUR_CALLS.lock().as_slice(), [builder]);
        });
        assert_eq!(fx.builder.path_begun, 1);
        assert_eq!(fx.points[0], FtVector { x: 2, y: -2 });
        assert_eq!(fx.tags[0], FT_CURVE_TAG_ON);
        assert_eq!(fx.builder.last, FtVector { x: 2, y: -2 });
        assert_eq!(fx.outline.n_points, 1);
    }

    #[test]
    fn capacity_error_starts_path_but_does_not_add_point() {
        let mut fx = StartPointFixture::new(0, 1);
        with_contour_seam(record_add_contour, || {
            with_seam(|| {
                let rc = unsafe {
                    cff_builder_start_point(&mut fx.builder, 0x0001_0000, 0x0002_0000)
                };
                assert_eq!(rc, 7);
                assert_eq!(CONTOUR_CALLS.lock().as_slice(), [&mut fx.builder as *mut _ as usize]);
                assert_eq!(SEAM_CALLS.lock().as_slice(), [(&mut fx.loader as *mut _ as usize, 1, 0)]);
            });
        });
        assert_eq!(fx.builder.path_begun, 1);
        assert_eq!(fx.outline.n_points, 0);
        assert_eq!(fx.points[0], FtVector { x: -777, y: 888 });
        assert_eq!(fx.tags[0], 0xaa);
    }
    // --- ft_glyph_loader_rewind ---

    #[test]
    fn rewind_clears_base_counts_and_clones_every_base_load_field() {
        let mut points = [FtVector { x: 1, y: -1 }; 2];
        let mut tags = [0xa5u8; 2];
        let mut contours = [7i16; 2];
        let mut subglyphs = [0x55u8; 4];
        let base = FtGlyphLoad {
            outline: FtOutline {
                n_contours: -2,
                n_points: -3,
                points: points.as_mut_ptr(),
                tags: tags.as_mut_ptr(),
                contours: contours.as_mut_ptr(),
                flags: 0x1234_5678,
            },
            extra_points: points.as_mut_ptr(),
            num_subglyphs: 0xfeed_beef,
            subglyphs: subglyphs.as_mut_ptr().cast(),
        };
        let mut loader = FtGlyphLoader {
            _reserved_00: 0xdeadbeef,
            max_points: 99,
            _reserved_08: [0xdeadbeef; 3],
            base,
            current: FtGlyphLoad {
                outline: FtOutline {
                    n_contours: 44,
                    n_points: 55,
                    points: core::ptr::null_mut(),
                    tags: core::ptr::null_mut(),
                    contours: core::ptr::null_mut(),
                    flags: 0,
                },
                extra_points: core::ptr::null_mut(),
                num_subglyphs: 66,
                subglyphs: core::ptr::null_mut(),
            },
        };

        unsafe { ft_glyph_loader_rewind(&mut loader) };

        assert_eq!(loader.base.outline.n_contours, 0);
        assert_eq!(loader.base.outline.n_points, 0);
        assert_eq!(loader.base.num_subglyphs, 0);
        assert_eq!(loader.current.outline.n_contours, 0);
        assert_eq!(loader.current.outline.n_points, 0);
        assert_eq!(loader.current.outline.points, points.as_mut_ptr());
        assert_eq!(loader.current.outline.tags, tags.as_mut_ptr());
        assert_eq!(loader.current.outline.contours, contours.as_mut_ptr());
        assert_eq!(loader.current.outline.flags, 0x1234_5678);
        assert_eq!(loader.current.extra_points, points.as_mut_ptr());
        assert_eq!(loader.current.num_subglyphs, 0);
        assert_eq!(loader.current.subglyphs, subglyphs.as_mut_ptr().cast());
        assert_eq!(loader.max_points, 99);
        assert_eq!(loader._reserved_00, 0xdeadbeef);
        assert_eq!(loader._reserved_08, [0xdeadbeef; 3]);
    }
}
