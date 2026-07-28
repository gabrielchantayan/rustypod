//! FreeType `ftoutln` outline helpers — `FT_Vector_Transform`,
//! `FT_Outline_Transform`, `FT_Outline_Translate` and
//! `FT_Outline_Get_CBox` as compiled into retailOS. Pure pointer/integer
//! walks over the [`FtOutline`]/[`FtVector`] structs (ft/types); host
//! tests prove behavior against references built from the documented
//! FreeType semantics. Call counts are binary-scanned b/bl words.
//!
//! Shared quirk, faithfully preserved: the outline walkers compute
//! `limit = points + n_points` with `n_points` sign-extended from its
//! `i16` field and compare pointers *unsigned* (`bcc`), so a negative
//! `n_points` wraps `limit` below `points` and the loops run zero times.

use crate::ft::calc::ft_mulfix;
use crate::ft::types::{FtBBox, FtMatrix, FtOutline, FtVector};

/// ft_vector_transform (FreeType `FT_Vector_Transform`) — original:
/// `FUN_0804fe08` @ 0x0804fe08 (96 bytes; 13 call sites).
///
/// `v = matrix * v` in 16.16: `x' = mulfix(x, xx) + mulfix(y, xy)`,
/// `y' = mulfix(x, yx) + mulfix(y, yy)` (wrapping adds), stores after
/// all four products. Null `vector` or `matrix` is a no-op.
///
/// # Safety
/// `vector` and `matrix` must be null or valid pointers.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_vector_transform(vector: *mut FtVector, matrix: *const FtMatrix) {
    if vector.is_null() || matrix.is_null() {
        return;
    }
    let v = *vector;
    let m = *matrix;
    let xz = ft_mulfix(v.x, m.xx).wrapping_add(ft_mulfix(v.y, m.xy));
    let yz = ft_mulfix(v.x, m.yx).wrapping_add(ft_mulfix(v.y, m.yy));
    (*vector).x = xz;
    (*vector).y = yz;
}

/// ft_outline_transform (FreeType `FT_Outline_Transform`) — original:
/// `FUN_0804e0cc` @ 0x0804e0cc (64 bytes; 4 call sites).
///
/// Applies [`ft_vector_transform`] to every point: walks `points ..
/// points + n_points` with the module-header pointer-compare quirk.
/// Null `outline` or `matrix` is a no-op.
///
/// # Safety
/// `outline` must be null or point to a valid outline whose `points`
/// spans `n_points` vectors; `matrix` must be null or valid.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_outline_transform(outline: *const FtOutline, matrix: *const FtMatrix) {
    if outline.is_null() || matrix.is_null() {
        return;
    }
    let mut vec = (*outline).points;
    let limit = (vec as usize)
        .wrapping_add((((*outline).n_points as isize) as usize).wrapping_mul(8));
    while (vec as usize) < limit {
        ft_vector_transform(vec, matrix);
        vec = vec.wrapping_add(1);
    }
}

/// ft_outline_translate (FreeType `FT_Outline_Translate`) — original:
/// `FUN_0804e10c` @ 0x0804e10c (72 bytes; 9 call sites).
///
/// Adds `x_offset`/`y_offset` (wrapping) to every point, counting a
/// loop index from 0 while it is signed-less-than `n_points` — zero
/// iterations when `n_points <= 0`. (The original also masks the
/// counter with `bic 0x10000` to emulate a `FT_UShort` index; with
/// `n_points` sign-extended from `i16` the mask can never fire, so the
/// port omits it.)
///
/// # Deviations
///
/// The original loads `outline->points` *before* its null check (a
/// harmless read through NULL+4 on this hardware). The port checks
/// first — same observable behavior for every non-null outline.
///
/// # Safety
/// `outline` must be null or point to a valid outline whose `points`
/// spans `n_points` vectors.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_outline_translate(
    outline: *const FtOutline,
    x_offset: i32,
    y_offset: i32,
) {
    if outline.is_null() {
        return;
    }
    let mut vec = (*outline).points;
    let n = (*outline).n_points as i32;
    let mut i = 0;
    while i < n {
        (*vec).x = (*vec).x.wrapping_add(x_offset);
        (*vec).y = (*vec).y.wrapping_add(y_offset);
        vec = vec.wrapping_add(1);
        i += 1;
    }
}

/// ft_outline_get_cbox (FreeType `FT_Outline_Get_CBox`) — original:
/// `FUN_0804deb4` @ 0x0804deb4 (136 bytes; 8 call sites).
///
/// Control-box: signed min/max of every point's x and y, seeded from
/// `points[0]` and scanned from `points[1]` with the module-header
/// pointer-compare quirk (so a *negative* `n_points` still reads
/// `points[0]` and returns it as all four extremes). `n_points == 0`
/// yields an all-zero box. Null `outline` or `acbox` is a no-op.
///
/// # Safety
/// `outline` must be null or point to a valid outline whose `points`
/// spans `n_points` vectors (at least one when `n_points != 0`);
/// `acbox` must be null or valid.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_outline_get_cbox(outline: *const FtOutline, acbox: *mut FtBBox) {
    if outline.is_null() || acbox.is_null() {
        return;
    }
    let n = (*outline).n_points;
    let (x_min, y_min, x_max, y_max) = if n == 0 {
        (0, 0, 0, 0)
    } else {
        let mut vec = (*outline).points;
        let limit =
            (vec as usize).wrapping_add(((n as isize) as usize).wrapping_mul(8));
        let first = *vec;
        let (mut x_min, mut y_min) = (first.x, first.y);
        let (mut x_max, mut y_max) = (first.x, first.y);
        vec = vec.wrapping_add(1);
        while (vec as usize) < limit {
            let p = *vec;
            if p.x < x_min {
                x_min = p.x;
            }
            if p.x > x_max {
                x_max = p.x;
            }
            if p.y < y_min {
                y_min = p.y;
            }
            if p.y > y_max {
                y_max = p.y;
            }
            vec = vec.wrapping_add(1);
        }
        (x_min, y_min, x_max, y_max)
    };
    *acbox = FtBBox {
        x_min,
        y_min,
        x_max,
        y_max,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    const ONE: i32 = 0x10000;

    fn outline(points: &mut [FtVector]) -> FtOutline {
        FtOutline {
            n_contours: 1,
            n_points: points.len() as i16,
            points: points.as_mut_ptr(),
            tags: ptr::null_mut(),
            contours: ptr::null_mut(),
            flags: 0,
        }
    }

    fn v(x: i32, y: i32) -> FtVector {
        FtVector { x, y }
    }

    #[test]
    fn vector_transform_rotation_and_scale() {
        // 90-degree rotation [0,-1;1,0]: (x,y) -> (-y, x).
        let rot = FtMatrix { xx: 0, xy: -ONE, yx: ONE, yy: 0 };
        let mut p = v(3 * ONE, 5 * ONE);
        unsafe { ft_vector_transform(&mut p, &rot) };
        assert_eq!(p, v(-5 * ONE, 3 * ONE));
        // Scale by (2, 0.5).
        let sc = FtMatrix { xx: 2 * ONE, xy: 0, yx: 0, yy: ONE / 2 };
        unsafe { ft_vector_transform(&mut p, &sc) };
        assert_eq!(p, v(-10 * ONE, ONE + ONE / 2));
    }

    #[test]
    fn vector_transform_matches_mulfix_reference() {
        let m = FtMatrix { xx: 0x18000, xy: -0x8000, yx: 0x4000, yy: 0x28000 };
        for (x, y) in [(1, 1), (-0x12345, 0x54321), (0x7fffffff, -0x10000)] {
            let mut p = v(x, y);
            unsafe { ft_vector_transform(&mut p, &m) };
            let want_x = ft_mulfix(x, m.xx).wrapping_add(ft_mulfix(y, m.xy));
            let want_y = ft_mulfix(x, m.yx).wrapping_add(ft_mulfix(y, m.yy));
            assert_eq!(p, v(want_x, want_y), "({x:#x}, {y:#x})");
        }
    }

    #[test]
    fn vector_transform_null_is_noop() {
        let mut p = v(7, 8);
        unsafe {
            ft_vector_transform(&mut p, ptr::null());
            ft_vector_transform(ptr::null_mut(), &FtMatrix { xx: ONE, xy: 0, yx: 0, yy: ONE });
        }
        assert_eq!(p, v(7, 8));
    }

    #[test]
    fn outline_transform_transforms_every_point() {
        let rot = FtMatrix { xx: 0, xy: -ONE, yx: ONE, yy: 0 };
        let mut pts = [v(ONE, 0), v(0, ONE), v(-2 * ONE, 3 * ONE)];
        let o = outline(&mut pts);
        unsafe { ft_outline_transform(&o, &rot) };
        assert_eq!(pts, [v(0, ONE), v(-ONE, 0), v(-3 * ONE, -2 * ONE)]);
    }

    #[test]
    fn outline_transform_negative_n_points_is_noop() {
        let mut pts = [v(ONE, ONE)];
        let mut o = outline(&mut pts);
        o.n_points = -1; // limit wraps below points: zero iterations
        let m = FtMatrix { xx: 2 * ONE, xy: 0, yx: 0, yy: 2 * ONE };
        unsafe { ft_outline_transform(&o, &m) };
        assert_eq!(pts, [v(ONE, ONE)]);
    }

    #[test]
    fn outline_transform_null_is_noop() {
        let mut pts = [v(5, 6)];
        let o = outline(&mut pts);
        unsafe {
            ft_outline_transform(&o, ptr::null());
            ft_outline_transform(ptr::null(), &FtMatrix { xx: 0, xy: 0, yx: 0, yy: 0 });
        }
        assert_eq!(pts, [v(5, 6)]);
    }

    #[test]
    fn outline_translate_offsets_every_point() {
        let mut pts = [v(0, 0), v(100, -200), v(i32::MAX, i32::MIN)];
        let o = outline(&mut pts);
        unsafe { ft_outline_translate(&o, 10, -20) };
        // Wrapping adds, like the original's add instructions.
        assert_eq!(
            pts,
            [
                v(10, -20),
                v(110, -220),
                v(i32::MAX.wrapping_add(10), i32::MIN.wrapping_add(-20)),
            ]
        );
    }

    #[test]
    fn outline_translate_nonpositive_count_is_noop() {
        let mut pts = [v(1, 2)];
        let mut o = outline(&mut pts);
        o.n_points = 0;
        unsafe { ft_outline_translate(&o, 5, 5) };
        o.n_points = -3;
        unsafe { ft_outline_translate(&o, 5, 5) };
        unsafe { ft_outline_translate(ptr::null(), 5, 5) };
        assert_eq!(pts, [v(1, 2)]);
    }

    #[test]
    fn get_cbox_min_max_over_points() {
        let mut pts = [v(5, -3), v(-7, 11), v(2, 2), v(9, -8)];
        let o = outline(&mut pts);
        let mut b = FtBBox { x_min: 1, y_min: 1, x_max: 1, y_max: 1 };
        unsafe { ft_outline_get_cbox(&o, &mut b) };
        assert_eq!(
            b,
            FtBBox { x_min: -7, y_min: -8, x_max: 9, y_max: 11 }
        );
    }

    #[test]
    fn get_cbox_single_point_and_extremes() {
        let mut pts = [v(i32::MIN, i32::MAX)];
        let o = outline(&mut pts);
        let mut b = FtBBox { x_min: 0, y_min: 0, x_max: 0, y_max: 0 };
        unsafe { ft_outline_get_cbox(&o, &mut b) };
        assert_eq!(
            b,
            FtBBox { x_min: i32::MIN, y_min: i32::MAX, x_max: i32::MIN, y_max: i32::MAX }
        );
    }

    #[test]
    fn get_cbox_zero_points_yields_zero_box() {
        let mut pts = [v(3, 4)];
        let mut o = outline(&mut pts);
        o.n_points = 0;
        let mut b = FtBBox { x_min: 1, y_min: 2, x_max: 3, y_max: 4 };
        unsafe { ft_outline_get_cbox(&o, &mut b) };
        assert_eq!(b, FtBBox { x_min: 0, y_min: 0, x_max: 0, y_max: 0 });
    }

    #[test]
    fn get_cbox_negative_n_points_returns_first_point() {
        // The wrapped-limit quirk: point[0] seeds the extremes and the
        // scan loop never runs.
        let mut pts = [v(42, -17)];
        let mut o = outline(&mut pts);
        o.n_points = -5;
        let mut b = FtBBox { x_min: 0, y_min: 0, x_max: 0, y_max: 0 };
        unsafe { ft_outline_get_cbox(&o, &mut b) };
        assert_eq!(b, FtBBox { x_min: 42, y_min: -17, x_max: 42, y_max: -17 });
    }

    #[test]
    fn get_cbox_null_is_noop() {
        let mut b = FtBBox { x_min: 9, y_min: 9, x_max: 9, y_max: 9 };
        let mut pts = [v(1, 1)];
        let o = outline(&mut pts);
        unsafe {
            ft_outline_get_cbox(ptr::null(), &mut b);
            ft_outline_get_cbox(&o, ptr::null_mut());
        }
        assert_eq!(b, FtBBox { x_min: 9, y_min: 9, x_max: 9, y_max: 9 });
    }
}
