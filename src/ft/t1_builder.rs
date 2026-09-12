//! FreeType Type 1 glyph-outline builder point recorder.
//!
//! Type 1 charstring decoding keeps coordinates as either raw `FT_Pos`
//! values or 16.16 fixed-point values, selected by [`T1Builder::shift`].

use core::ffi::c_void;

use crate::ft::types::{FtBBox, FtOutline, FtVector};

/// `T1_BuilderRec` (psaux.h), sliced through `metrics_only` at +0x54.
///
/// The first six members are target pointers: each occupies four bytes on
/// ARM and naturally widens on the host.  Accesses use field names rather
/// than byte offsets, preserving the firmware layout without host overlap.
#[repr(C)]
pub struct T1Builder {
    pub memory: *mut c_void,
    pub face: *mut c_void,
    pub glyph: *mut c_void,
    pub loader: *mut c_void,
    pub base: *mut FtOutline,
    pub current: *mut FtOutline,
    pub last: FtVector,
    pub scale_x: i32,
    pub scale_y: i32,
    pub pos_x: i32,
    pub pos_y: i32,
    pub left_bearing: FtVector,
    pub advance: FtVector,
    pub bbox: FtBBox,
    pub parse_state: u8,
    pub load_points: u8,
    pub no_recurse: u8,
    pub shift: u8,
    pub metrics_only: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(T1Builder, current)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(T1Builder, last)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x51] = [0; core::mem::offset_of!(T1Builder, load_points)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x53] = [0; core::mem::offset_of!(T1Builder, shift)];

/// Type 1 `t1_builder_add_point` (psaux.c) — original: `FUN_080bb65c` @
/// 0x080bb65c (104 bytes, 0x080bb65c..0x080bb65c0; the separate two-word
/// `ldr r0,[r0,#0x168] / bx lr` function starts at 0x080bb6c4). Eight `bl`
/// call sites verified by decoding every B/BL word in `osos.dec`: seven
/// unconditional `bl` in `t1_decoder_parse_charstrings` at 0x080de384,
/// 0x080de920, 0x080de944, 0x080dead4, 0x080deaf8, 0x080deb68, and
/// 0x080deb8c, plus one gated `bleq` at 0x080c4d0c.  The predicated caller
/// invokes this only after its preceding decoder operation returns zero;
/// it is not a NULL guard in this callee.
///
/// If `load_points` is set, records the signed `n_points` slot of `current`:
/// `shift` selects arithmetic `>> 16` conversion from 16.16 fixed point;
/// otherwise x and y are stored unchanged.  A nonzero `on_curve` selects tag
/// 1, while zero selects cubic-control tag 2, and the stored point becomes
/// `last`.  The unsigned-halfword increment of `n_points` is outside that
/// guard, so a counting-only pass advances it with i16 wrap even when it
/// stores nothing.  No pointer is NULL-checked, matching the raw ARM.
///
/// No deliberate deviations.
///
/// # Safety
/// `builder` and `builder->current` must be valid.  When `load_points != 0`,
/// the outline's points and tags arrays must contain the signed `n_points`
/// element.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn t1_builder_add_point(
    builder: *mut T1Builder,
    x: i32,
    y: i32,
    on_curve: i32,
) {
    let outline = (*builder).current;
    if (*builder).load_points != 0 {
        let index = (*outline).n_points as isize;
        let point = (*outline).points.offset(index);
        let mut x = x;
        let mut y = y;
        if (*builder).shift != 0 {
            x >>= 16;
            y >>= 16;
        }
        (*point).x = x;
        (*point).y = y;
        *(*outline).tags.offset(index) = if on_curve != 0 { 1 } else { 2 };
        (*builder).last = *point;
    }
    (*outline).n_points = (*outline).n_points.wrapping_add(1);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    struct Fixture {
        points: [FtVector; 8],
        tags: [u8; 8],
        outline: FtOutline,
        builder: T1Builder,
    }

    impl Fixture {
        fn new(n_points: i16, load_points: u8, shift: u8) -> std::boxed::Box<Self> {
            let mut fixture = std::boxed::Box::new(Self {
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
                builder: T1Builder {
                    memory: core::ptr::null_mut(),
                    face: core::ptr::null_mut(),
                    glyph: core::ptr::null_mut(),
                    loader: core::ptr::null_mut(),
                    base: core::ptr::null_mut(),
                    current: core::ptr::null_mut(),
                    last: FtVector { x: -1, y: -1 },
                    scale_x: 0xdeadbeef_u32 as i32,
                    scale_y: 0xdeadbeef_u32 as i32,
                    pos_x: 0xdeadbeef_u32 as i32,
                    pos_y: 0xdeadbeef_u32 as i32,
                    left_bearing: FtVector { x: -777, y: 888 },
                    advance: FtVector { x: -777, y: 888 },
                    bbox: FtBBox { x_min: -1, y_min: -2, x_max: 3, y_max: 4 },
                    parse_state: 0xbe,
                    load_points,
                    no_recurse: 0xde,
                    shift,
                    metrics_only: 0xad,
                },
            });
            fixture.outline.points = fixture.points.as_mut_ptr();
            fixture.outline.tags = fixture.tags.as_mut_ptr();
            fixture.builder.current = &mut fixture.outline;
            fixture
        }
    }

    #[test]
    fn shifted_point_floors_fixed_coordinates_and_sets_on_curve_tag() {
        let mut fixture = Fixture::new(0, 1, 1);
        unsafe { t1_builder_add_point(&mut fixture.builder, 0x0002_8000, -0x0001_8000, -7) };
        assert_eq!(fixture.points[0], FtVector { x: 2, y: -2 });
        assert_eq!(fixture.tags[0], 1);
        assert_eq!(fixture.builder.last, FtVector { x: 2, y: -2 });
        assert_eq!(fixture.outline.n_points, 1);
    }

    #[test]
    fn unshifted_point_preserves_raw_coordinates_and_cubic_tag() {
        let mut fixture = Fixture::new(0, 1, 0);
        unsafe { t1_builder_add_point(&mut fixture.builder, -31, 0x1234_5678, 0) };
        assert_eq!(fixture.points[0], FtVector { x: -31, y: 0x1234_5678 });
        assert_eq!(fixture.tags[0], 2);
        assert_eq!(fixture.builder.last, FtVector { x: -31, y: 0x1234_5678 });
    }

    #[test]
    fn counting_pass_does_not_store_but_advances_count() {
        let mut fixture = Fixture::new(3, 0, 1);
        unsafe { t1_builder_add_point(&mut fixture.builder, 0x0005_0000, 0x0006_0000, 1) };
        assert_eq!(fixture.outline.n_points, 4);
        assert!(fixture.points.iter().all(|point| *point == FtVector { x: -777, y: 888 }));
        assert!(fixture.tags.iter().all(|tag| *tag == 0xaa));
        assert_eq!(fixture.builder.last, FtVector { x: -1, y: -1 });
    }

    #[test]
    fn negative_count_indexes_backwards() {
        let mut fixture = Fixture::new(-1, 1, 0);
        fixture.outline.points = unsafe { fixture.points.as_mut_ptr().add(1) };
        fixture.outline.tags = unsafe { fixture.tags.as_mut_ptr().add(1) };
        unsafe { t1_builder_add_point(&mut fixture.builder, 3, 4, 1) };
        assert_eq!(fixture.points[0], FtVector { x: 3, y: 4 });
        assert_eq!(fixture.tags[0], 1);
        assert_eq!(fixture.outline.n_points, 0);
    }

    #[test]
    fn point_count_wraps_as_a_signed_halfword() {
        let mut fixture = Fixture::new(i16::MAX, 0, 0);
        unsafe { t1_builder_add_point(&mut fixture.builder, 0, 0, 1) };
        assert_eq!(fixture.outline.n_points, i16::MIN);
    }
}
