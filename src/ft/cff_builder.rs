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
//! }
//! ```

use crate::ft::types::{FtOutline, FtVector};

/// `FT_CURVE_TAG_ON` (ftimage.h) — the point lies on the curve.
pub const FT_CURVE_TAG_ON: u8 = 1;

/// `FT_CURVE_TAG_CUBIC` (ftimage.h) — cubic (rrcurveto) control point.
pub const FT_CURVE_TAG_CUBIC: u8 = 2;

/// `CFF_Builder` (cffgload.h `CFF_Builder_Rec`) sliced down to the
/// members [`cff_builder_add_point`] touches, at their firmware
/// offsets: the five head words (memory, face, glyph, loader, base)
/// at +0x00..+0x13, `current` @ +0x14, `last` @ +0x18/+0x1c and the
/// `load_points` bool @ +0x51. The +0x20..+0x50 span (left_bearing,
/// advance, bbox, no_recurse, ...) is opaque to this port.
///
/// `current` is a native pointer like the pointer fields of
/// ft/types.rs structs: exact on the 32-bit target, wider on 64-bit
/// hosts — all accesses are by field name, never by raw offset.
#[repr(C)]
pub struct CffBuilder {
    _reserved_00: [u32; 5],
    pub current: *mut FtOutline,
    pub last: FtVector,
    _reserved_20: [u32; 12],
    _reserved_50: u8,
    pub load_points: u8,
}

// Firmware layout: exact only where pointers are 32-bit.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(CffBuilder, current)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(CffBuilder, last)];
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
                    _reserved_00: [0xdeadbeef; 5],
                    current: core::ptr::null_mut(),
                    last: FtVector { x: -1, y: -1 },
                    _reserved_20: [0xdeadbeef; 12],
                    _reserved_50: 0xde,
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
        assert!(fx.builder._reserved_20.iter().all(|w| *w == 0xdeadbeef));
        assert_eq!(fx.builder._reserved_50, 0xde);
        assert_eq!(fx.builder.load_points, 1);
    }
}
