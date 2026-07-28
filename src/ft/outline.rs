//! FreeType `ftoutln` outline helpers — `FT_Vector_Transform`,
//! `FT_Outline_Transform`, `FT_Outline_Translate`,
//! `FT_Outline_Get_CBox` and `FT_Outline_Get_Orientation` as compiled
//! into retailOS. Pure pointer/integer walks over the
//! [`FtOutline`]/[`FtVector`] structs (ft/types); host tests prove
//! behavior against references built from the documented FreeType
//! semantics. Call counts are binary-scanned b/bl words.
//!
//! Shared quirk, faithfully preserved: the outline walkers compute
//! `limit = points + n_points` with `n_points` sign-extended from its
//! `i16` field and compare pointers *unsigned* (`bcc`), so a negative
//! `n_points` wraps `limit` below `points` and the loops run zero times.

use crate::ft::calc::ft_mulfix;
use crate::ft::trig::ft_atan2;
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

/// `FT_ORIENTATION_TRUETYPE` — clockwise contours (and the answer for
/// every outline this routine cannot judge).
pub const FT_ORIENTATION_TRUETYPE: i32 = 0;

/// `FT_ORIENTATION_POSTSCRIPT` — counter-clockwise contours.
pub const FT_ORIENTATION_POSTSCRIPT: i32 = 1;

/// Point index of `p` the way the original computes it: the byte
/// distance from `points`, arithmetic-shifted right by 3 (`ldrb tags[.,
/// asr #3]`).
#[inline(always)]
fn point_index(p: *const FtVector, points: *const FtVector) -> isize {
    (p as isize).wrapping_sub(points as isize) >> 3
}

/// ft_outline_get_orientation (FreeType `FT_Outline_Get_Orientation`) —
/// original: `FUN_0804df3c` @ 0x0804df3c (400 bytes; 1 call site).
///
/// Decides whether the outline is wound clockwise
/// ([`FT_ORIENTATION_TRUETYPE`]) or counter-clockwise
/// ([`FT_ORIENTATION_POSTSCRIPT`]) by looking at the corner at its
/// leftmost on-curve point — the pre-2.4 `FT_Atan2` flavor of the test,
/// before it was rewritten around `FT_Outline_Get_CBox` and area sums.
///
/// A null outline or `n_points <= 0` answers `FT_ORIENTATION_TRUETYPE`.
/// Otherwise, per contour (`first ..= last`, `first` starting at point 0
/// and continuing past each `last`):
///
/// - contours shorter than three points are skipped (`last >= first + 2`
///   as an *unsigned* pointer compare);
/// - the on-curve points (tag bit 0) are counted and the leftmost one is
///   remembered, seeded from `x < 32768`;
/// - a contour with **more than two** on-curve points whose leftmost `x`
///   beats the running minimum becomes the winner, carrying its `first`
///   and `last` bounds along.
///
/// With no winner the answer is again `FT_ORIENTATION_TRUETYPE`.
/// Otherwise the neighbors of the winning point are found by stepping
/// backwards/forwards *within the contour* (wrapping `first` to `last`
/// and back) until an on-curve point turns up — the `> 2` count above is
/// what guarantees those walks terminate — and the two edge angles
/// `atan2(neighbor - point)` decide it: `angle_in > angle_out` means
/// counter-clockwise. Note the original compares the raw angles rather
/// than `FT_Angle_Diff`, so the comparison is on the (-180, 180]
/// representatives.
///
/// The contour cursor is bounded by `contours + n_contours` compared
/// *unsigned*, the same wrapped-limit quirk as
/// [`ft_outline_transform`]: a negative `n_contours` runs zero
/// iterations and yields `FT_ORIENTATION_TRUETYPE`.
///
/// # Safety
/// `outline` must be null or point to a valid outline whose `points`
/// and `tags` span `n_points` entries and whose `contours` spans
/// `n_contours` entries.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_outline_get_orientation(outline: *const FtOutline) -> i32 {
    if outline.is_null() || (*outline).n_points <= 0 {
        return FT_ORIENTATION_TRUETYPE;
    }
    let points: *const FtVector = (*outline).points;
    let tags = (*outline).tags;
    let mut contour = (*outline).contours;
    let contour_limit = (contour as usize)
        .wrapping_add(((*outline).n_contours as isize as usize).wrapping_mul(2));

    let mut xmin = 32768;
    let mut xmin_point: *const FtVector = core::ptr::null();
    let mut xmin_first: *const FtVector = core::ptr::null();
    let mut xmin_last: *const FtVector = core::ptr::null();
    let mut first = points;

    while (contour as usize) < contour_limit {
        let last = points.wrapping_offset(*contour as isize);
        // "last - first >= 2 points", as the original's unsigned compare.
        if last as usize >= (first as usize).wrapping_add(16) {
            let mut on_curve_count = 0;
            let mut contour_xmin = 32768;
            let mut contour_xmin_point: *const FtVector = core::ptr::null();
            let mut p = first;
            while p as usize <= last as usize {
                let on_curve = *tags.offset(point_index(p, points)) & 1;
                on_curve_count += on_curve as i32;
                if (*p).x < contour_xmin && on_curve != 0 {
                    contour_xmin = (*p).x;
                    contour_xmin_point = p;
                }
                p = p.wrapping_add(1);
            }
            if on_curve_count > 2 && contour_xmin < xmin {
                xmin = contour_xmin;
                xmin_point = contour_xmin_point;
                xmin_first = first;
                xmin_last = last;
            }
        }
        first = last.wrapping_add(1);
        contour = contour.wrapping_add(1);
    }

    if xmin_point.is_null() {
        return FT_ORIENTATION_TRUETYPE;
    }

    // Previous/next on-curve neighbors, wrapping around the contour.
    let step_back = |p: *const FtVector| {
        if p != xmin_first {
            p.wrapping_sub(1)
        } else {
            xmin_last
        }
    };
    let step_forward = |p: *const FtVector| {
        if p != xmin_last {
            p.wrapping_add(1)
        } else {
            xmin_first
        }
    };
    let mut prev = step_back(xmin_point);
    while *tags.offset(point_index(prev, points)) & 1 == 0 {
        prev = step_back(prev);
    }
    let mut next = step_forward(xmin_point);
    while *tags.offset(point_index(next, points)) & 1 == 0 {
        next = step_forward(next);
    }

    let point = *xmin_point;
    let angle_in = ft_atan2(
        (*prev).x.wrapping_sub(point.x),
        (*prev).y.wrapping_sub(point.y),
    );
    let angle_out = ft_atan2(
        (*next).x.wrapping_sub(point.x),
        (*next).y.wrapping_sub(point.y),
    );
    if angle_in > angle_out {
        FT_ORIENTATION_POSTSCRIPT
    } else {
        FT_ORIENTATION_TRUETYPE
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{vec, vec::Vec};
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

    /// Full outline (points + tags + contour ends) for the orientation
    /// tests.
    struct Glyph {
        points: Vec<FtVector>,
        tags: Vec<u8>,
        contours: Vec<i16>,
    }

    impl Glyph {
        /// One closed contour, every point on-curve.
        fn polygon(points: &[(i32, i32)]) -> Glyph {
            Glyph {
                points: points.iter().map(|&(x, y)| v(x, y)).collect(),
                tags: vec![1; points.len()],
                contours: vec![points.len() as i16 - 1],
            }
        }

        fn outline(&mut self) -> FtOutline {
            FtOutline {
                n_contours: self.contours.len() as i16,
                n_points: self.points.len() as i16,
                points: self.points.as_mut_ptr(),
                tags: self.tags.as_mut_ptr(),
                contours: self.contours.as_mut_ptr(),
                flags: 0,
            }
        }

        fn orientation(&mut self) -> i32 {
            let o = self.outline();
            unsafe { ft_outline_get_orientation(&o) }
        }
    }

    /// Reference `FT_Outline_Get_Orientation` for this vintage, written
    /// against point *indices* rather than the port's pointers.
    fn orientation_ref(glyph: &Glyph) -> i32 {
        let n_points = glyph.points.len() as i32;
        if n_points <= 0 {
            return FT_ORIENTATION_TRUETYPE;
        }
        let (mut xmin, mut xmin_point) = (32768, -1i32);
        let (mut xmin_first, mut xmin_last) = (-1i32, -1i32);
        let mut first = 0i32;
        for &end in &glyph.contours {
            let last = end as i32;
            if last - first >= 2 {
                let (mut count, mut contour_xmin, mut contour_point) = (0, 32768, -1i32);
                for i in first..=last {
                    let on_curve = glyph.tags[i as usize] & 1;
                    count += on_curve as i32;
                    if glyph.points[i as usize].x < contour_xmin && on_curve != 0 {
                        contour_xmin = glyph.points[i as usize].x;
                        contour_point = i;
                    }
                }
                if count > 2 && contour_xmin < xmin {
                    xmin = contour_xmin;
                    xmin_point = contour_point;
                    xmin_first = first;
                    xmin_last = last;
                }
            }
            first = last + 1;
        }
        if xmin_point < 0 {
            return FT_ORIENTATION_TRUETYPE;
        }
        let back = |i: i32| if i != xmin_first { i - 1 } else { xmin_last };
        let forward = |i: i32| if i != xmin_last { i + 1 } else { xmin_first };
        let mut prev = back(xmin_point);
        while glyph.tags[prev as usize] & 1 == 0 {
            prev = back(prev);
        }
        let mut next = forward(xmin_point);
        while glyph.tags[next as usize] & 1 == 0 {
            next = forward(next);
        }
        let point = glyph.points[xmin_point as usize];
        let angle_in = ft_atan2(
            glyph.points[prev as usize].x.wrapping_sub(point.x),
            glyph.points[prev as usize].y.wrapping_sub(point.y),
        );
        let angle_out = ft_atan2(
            glyph.points[next as usize].x.wrapping_sub(point.x),
            glyph.points[next as usize].y.wrapping_sub(point.y),
        );
        if angle_in > angle_out {
            FT_ORIENTATION_POSTSCRIPT
        } else {
            FT_ORIENTATION_TRUETYPE
        }
    }

    #[test]
    fn orientation_null_or_degenerate_outline_is_truetype() {
        assert_eq!(
            unsafe { ft_outline_get_orientation(ptr::null()) },
            FT_ORIENTATION_TRUETYPE
        );
        let mut g = Glyph::polygon(&[(0, 0), (10, 0), (10, 10), (0, 10)]);
        let mut o = g.outline();
        o.n_points = 0;
        assert_eq!(
            unsafe { ft_outline_get_orientation(&o) },
            FT_ORIENTATION_TRUETYPE
        );
        o.n_points = -4;
        assert_eq!(
            unsafe { ft_outline_get_orientation(&o) },
            FT_ORIENTATION_TRUETYPE
        );
    }

    #[test]
    fn orientation_of_a_counter_clockwise_square_is_postscript() {
        // (0,0) -> (10,0) -> (10,10) -> (0,10): at the leftmost point
        // (0,0) the incoming edge points up (90 deg) and the outgoing
        // edge right (0 deg), so angle_in > angle_out.
        let mut g = Glyph::polygon(&[(0, 0), (10, 0), (10, 10), (0, 10)]);
        assert_eq!(g.orientation(), FT_ORIENTATION_POSTSCRIPT);
        assert_eq!(orientation_ref(&g), FT_ORIENTATION_POSTSCRIPT);
    }

    #[test]
    fn orientation_of_a_clockwise_square_is_truetype() {
        let mut g = Glyph::polygon(&[(0, 0), (0, 10), (10, 10), (10, 0)]);
        assert_eq!(g.orientation(), FT_ORIENTATION_TRUETYPE);
        assert_eq!(orientation_ref(&g), FT_ORIENTATION_TRUETYPE);
    }

    #[test]
    fn orientation_is_invariant_under_rotation_of_the_point_list() {
        // Which point index is "first" must not matter: the winner is
        // found by geometry, and the neighbor walk wraps.
        let base = [(0, 0), (10, 0), (14, 6), (10, 12), (2, 9)];
        for start in 0..base.len() {
            let rotated: Vec<(i32, i32)> =
                (0..base.len()).map(|i| base[(i + start) % base.len()]).collect();
            let mut g = Glyph::polygon(&rotated);
            assert_eq!(g.orientation(), FT_ORIENTATION_POSTSCRIPT, "start {start}");
            assert_eq!(orientation_ref(&g), FT_ORIENTATION_POSTSCRIPT);
            let mut reversed: Vec<(i32, i32)> = rotated.clone();
            reversed.reverse();
            let mut g = Glyph::polygon(&reversed);
            assert_eq!(g.orientation(), FT_ORIENTATION_TRUETYPE, "start {start}");
            assert_eq!(orientation_ref(&g), FT_ORIENTATION_TRUETYPE);
        }
    }

    #[test]
    fn orientation_matches_reference_on_randomized_polygons() {
        // Convex polygons on a circle, both windings, random radii and
        // offsets — plus their reference answers.
        let mut s: u32 = 0x9e37_79b9;
        let mut rnd = || {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s
        };
        for case in 0..400 {
            let n = 3 + (rnd() % 8) as usize;
            let radius = 1 + (rnd() % 5000) as i32;
            let (cx, cy) = ((rnd() % 2000) as i32 - 1000, (rnd() % 2000) as i32 - 1000);
            let clockwise = case % 2 == 0;
            let mut points = Vec::new();
            for k in 0..n {
                let step = if clockwise { -(k as f64) } else { k as f64 };
                let angle = step * core::f64::consts::TAU / n as f64;
                points.push((
                    cx + (radius as f64 * angle.cos()).round() as i32,
                    cy + (radius as f64 * angle.sin()).round() as i32,
                ));
            }
            let mut g = Glyph::polygon(&points);
            let want = orientation_ref(&g);
            assert_eq!(g.orientation(), want, "{points:?}");
            // Convex polygons: the winding is unambiguous, so the
            // reference must also agree with the geometry.
            assert_eq!(
                want,
                if clockwise {
                    FT_ORIENTATION_TRUETYPE
                } else {
                    FT_ORIENTATION_POSTSCRIPT
                },
                "{points:?}"
            );
        }
    }

    #[test]
    fn orientation_skips_contours_shorter_than_three_points() {
        // A two-point contour to the left of a real square: it must not
        // win, and the square decides.
        let mut g = Glyph {
            points: vec![
                v(-100, 0),
                v(-90, 0),
                v(0, 0),
                v(10, 0),
                v(10, 10),
                v(0, 10),
            ],
            tags: vec![1; 6],
            contours: vec![1, 5],
        };
        assert_eq!(g.orientation(), FT_ORIENTATION_POSTSCRIPT);
        assert_eq!(orientation_ref(&g), FT_ORIENTATION_POSTSCRIPT);
    }

    #[test]
    fn orientation_needs_more_than_two_on_curve_points() {
        // Leftmost contour has three points but only two on-curve, so
        // the count test rejects it and the right-hand square wins.
        let mut g = Glyph {
            points: vec![
                v(-100, 0),
                v(-90, 5),
                v(-95, 10),
                v(0, 0),
                v(10, 0),
                v(10, 10),
                v(0, 10),
            ],
            tags: vec![1, 0, 1, 1, 1, 1, 1],
            contours: vec![2, 6],
        };
        assert_eq!(g.orientation(), FT_ORIENTATION_POSTSCRIPT);
        assert_eq!(orientation_ref(&g), FT_ORIENTATION_POSTSCRIPT);
    }

    #[test]
    fn orientation_walks_past_off_curve_neighbors() {
        // The leftmost on-curve point (0,0) has off-curve control
        // points on both sides; the walk must reach (10,0) and (0,10).
        let mut g = Glyph {
            points: vec![
                v(0, 0),
                v(5, -3),  // off-curve
                v(10, 0),
                v(10, 10),
                v(0, 10),
                v(-3, 5),  // off-curve, wraps back to (0,0)
            ],
            tags: vec![1, 0, 1, 1, 1, 0],
            contours: vec![5],
        };
        assert_eq!(g.orientation(), FT_ORIENTATION_POSTSCRIPT);
        assert_eq!(orientation_ref(&g), FT_ORIENTATION_POSTSCRIPT);
    }

    #[test]
    fn orientation_uses_the_globally_leftmost_contour() {
        // Two squares with opposite windings: the left one decides.
        let mut g = Glyph {
            points: vec![
                // clockwise square at x = 0..10
                v(0, 0),
                v(0, 10),
                v(10, 10),
                v(10, 0),
                // counter-clockwise square further left
                v(-50, 0),
                v(-40, 0),
                v(-40, 10),
                v(-50, 10),
            ],
            tags: vec![1; 8],
            contours: vec![3, 7],
        };
        assert_eq!(g.orientation(), FT_ORIENTATION_POSTSCRIPT);
        assert_eq!(orientation_ref(&g), FT_ORIENTATION_POSTSCRIPT);
        // Swap the windings: now the left square is clockwise.
        g.points[4] = v(-50, 0);
        g.points[5] = v(-50, 10);
        g.points[6] = v(-40, 10);
        g.points[7] = v(-40, 0);
        assert_eq!(g.orientation(), FT_ORIENTATION_TRUETYPE);
        assert_eq!(orientation_ref(&g), FT_ORIENTATION_TRUETYPE);
    }

    #[test]
    fn orientation_ignores_points_at_or_above_the_32768_seed() {
        // The leftmost search is seeded with x < 32768, so a contour
        // living entirely to the right of that is never a candidate.
        let mut g = Glyph::polygon(&[(40000, 0), (40010, 0), (40010, 10), (40000, 10)]);
        assert_eq!(g.orientation(), FT_ORIENTATION_TRUETYPE);
        assert_eq!(orientation_ref(&g), FT_ORIENTATION_TRUETYPE);
    }

    #[test]
    fn orientation_negative_contour_count_is_truetype() {
        let mut g = Glyph::polygon(&[(0, 0), (10, 0), (10, 10), (0, 10)]);
        let mut o = g.outline();
        o.n_contours = -1; // wrapped limit: the contour loop never runs
        assert_eq!(
            unsafe { ft_outline_get_orientation(&o) },
            FT_ORIENTATION_TRUETYPE
        );
    }
}
