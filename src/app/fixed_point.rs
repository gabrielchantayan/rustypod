//! `fixed_point_set` — original: `FUN_08280184` @ **0x08280184** (8 bytes,
//! 0x08280184..0x0828018c; **12 direct `bl` call sites**, all unconditional,
//! zero predicated forms, and no tail `b` calls), verified by decoding every
//! ARM B/BL word in `osos.dec`.
//!
//! Raw ARM is `stm r0, {r1, r2}; bx lr`: store the two Q16.16 coordinate words
//! in ascending order, `x` then `y`, through an unguarded point pointer.
//! The four callers in `FUN_08142dac` make the unit-square corners, while the
//! eight in `FUN_0828c874` build two fixed-point quads. No aligned image word
//! contains 0x08280184, so the function is statically called rather than
//! vtable-dispatched.
//!
//! Deliberate deviations: none.

/// Two signed Q16.16 coordinates, stored as consecutive target words.
#[repr(C)]
pub struct FixedPoint {
    /// +0x00
    pub x: i32,
    /// +0x04
    pub y: i32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::size_of::<FixedPoint>()];

/// fixed_point_set — original: `FUN_08280184` @ 0x08280184 (8 bytes; 12
/// unconditional `bl` call sites, binary-scanned).
///
/// Stores Q16.16 `x` and `y` at the two consecutive words of `point`. There
/// is no NULL or alignment guard, matching the original `stm`.
///
/// # Safety
///
/// `point` must be writable and word-aligned for one [`FixedPoint`].
#[cfg_attr(target_os = "none", link_section = ".text.fixed_point_set")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed_point_set(point: *mut FixedPoint, x: i32, y: i32) {
    unsafe {
        (*point).x = x;
        (*point).y = y;
    }
}

/// q15_weighted_blend — original: `FUN_080a8f64` @ **0x080a8f64** (20 bytes;
/// **6 unconditional `bl` call sites**, zero predicated forms, and no tail
/// `b` calls), verified by decoding every ARM B/BL word in `osos.dec`.
///
/// Performs the four-register Q15 weighted blend
/// `(first * weight + second * complement_weight) * 2 >> 16`. ARM `mul`,
/// `mla`, and `lsl` retain only the low 32 bits before the final arithmetic
/// shift; the wrapping operations below preserve that behavior. All six
/// callers are in `FUN_0828ed6c`, which blends signed 16-bit coordinates
/// using weights that sum to `0x8000`. No aligned image word equals
/// `0x080a8f64`, so the helper is not virtually dispatched.
///
/// Deliberate deviations: none.
#[cfg_attr(target_os = "none", link_section = ".text.q15_weighted_blend")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn q15_weighted_blend(
    weight: i32,
    first: i32,
    complement_weight: i32,
    second: i32,
) -> i32 {
    let total = first
        .wrapping_mul(weight)
        .wrapping_add(second.wrapping_mul(complement_weight));
    total.wrapping_shl(1) >> 16
}


#[cfg(test)]
mod tests {
    use super::{fixed_point_set, q15_weighted_blend, FixedPoint};

    #[test]
    fn stores_signed_fixed_coordinates_without_touching_neighbors() {
        let mut words = [0xdead_beefu32, 0xa5a5_a5a5, 0x5a5a_5a5a, 0xc001_d00d];
        let point = unsafe { words.as_mut_ptr().add(1).cast::<FixedPoint>() };

        unsafe { fixed_point_set(point, -0x0001_8000, 0x7fff_ffff) };

        assert_eq!(words, [0xdead_beef, 0xfffe_8000, 0x7fff_ffff, 0xc001_d00d]);
    }

    #[test]
    fn overwrites_both_coordinate_words_on_each_call() {
        let mut point = FixedPoint { x: 0x0001_0000, y: -0x0001_0000 };

        unsafe { fixed_point_set(&mut point, 0, 0x0001_0000) };
        assert_eq!((point.x, point.y), (0, 0x0001_0000));

        unsafe { fixed_point_set(&mut point, -1, 0) };
        assert_eq!((point.x, point.y), (-1, 0));
    }

    fn reference_q15_blend(
        weight: i32,
        first: i32,
        complement_weight: i32,
        second: i32,
    ) -> i32 {
        let total = first as i64 * weight as i64 + second as i64 * complement_weight as i64;
        (total as u32).wrapping_shl(1) as i32 >> 16
    }

    #[test]
    fn q15_blend_selects_each_endpoint_and_interpolates_signed_coordinates() {
        assert_eq!(q15_weighted_blend(0, 1_234, 0x8000, -567), -567);
        assert_eq!(q15_weighted_blend(0x8000, -567, 0, 1_234), -567);
        assert_eq!(
            q15_weighted_blend(0x2000, 1_234, 0x6000, -567),
            reference_q15_blend(0x2000, 1_234, 0x6000, -567)
        );
    }

    #[test]
    fn q15_blend_retains_arm_intermediate_wraparound() {
        for (weight, first, complement_weight, second) in [
            (i32::MAX, i32::MAX, i32::MIN, i32::MIN),
            (0x7fff_ffff, -1, 0x4000_0001, 0x4000_0001),
            (-0x4000_0000, 0x6000_0000, 0x1234_5678, -0x2345_6789),
        ] {
            assert_eq!(
                q15_weighted_blend(weight, first, complement_weight, second),
                reference_q15_blend(weight, first, complement_weight, second)
            );
        }
    }
}
