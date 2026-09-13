//! Interpolation helpers for coordinate pairs carried in UI geometry records.

use crate::runtime::rt_div::__rt_sdiv;

/// Four-word geometry record accepted by [`interpolate_coordinate_delta`].
///
/// The original loads all four words, although only the signed low halves of
/// `start_y` and `end_y` affect this helper's result.
#[repr(C)]
pub struct CoordinateInterpolationBounds {
    pub unknown_00: i32,
    pub start_y: i32,
    pub unknown_08: i32,
    pub end_y: i32,
}

/// interpolate_coordinate_delta — original: `FUN_081c99ec` @ `0x081c99ec`
/// (132 bytes; 7 direct plain-`bl` call sites: 0x081c9778, 0x081c9884,
/// 0x081c9bd8, 0x081c9bf8, 0x081c9cac, 0x081c9df0, 0x081ca0e0).
///
/// Interpolates the signed-low-16-bit vertical span in `bounds` at
/// `sample_x` over `start_x..end_x`, truncates the quotient to a signed i16,
/// and returns that sign-extended delta. A zero horizontal span instead
/// returns the signed-low-16-bit vertical span when `end_x` is nonzero, or
/// zero when it is zero. Arithmetic before division wraps at 32 bits, as the
/// ARM `sub`/`mul` instructions do. Deliberate deviation: the ABI's unused
/// first argument is modeled as `context` rather than retaining the original
/// dead register value.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn interpolate_coordinate_delta(
    _context: *mut u8,
    start_x: i32,
    end_x: i32,
    sample_x: i32,
    bounds: *const CoordinateInterpolationBounds,
) -> i32 {
    let bounds = bounds.read();
    let horizontal_span = end_x.wrapping_sub(start_x);
    let vertical_delta = if horizontal_span == 0 {
        if end_x == 0 {
            0
        } else {
            bounds.end_y.wrapping_sub(bounds.start_y)
        }
    } else {
        let vertical_span = bounds.end_y.wrapping_sub(bounds.start_y);
        __rt_sdiv(
            vertical_span.wrapping_mul(sample_x.wrapping_sub(start_x)),
            horizontal_span,
        )
    };
    (vertical_delta as i16) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(start_y: i32, end_y: i32) -> CoordinateInterpolationBounds {
        CoordinateInterpolationBounds { unknown_00: 0xa5a5_a5a5u32 as i32, start_y, unknown_08: 0x5a5a_5a5a, end_y }
    }

    fn interpolate(start_x: i32, end_x: i32, sample_x: i32, start_y: i32, end_y: i32) -> i32 {
        let bounds = bounds(start_y, end_y);
        unsafe {
            interpolate_coordinate_delta(
                core::ptr::null_mut(),
                start_x,
                end_x,
                sample_x,
                &bounds,
            )
        }
    }

    #[test]
    fn interpolates_a_rising_coordinate_span() {
        assert_eq!(interpolate(100, 140, 110, 10, 50), 10);
        assert_eq!(interpolate(100, 140, 130, 10, 50), 30);
    }

    #[test]
    fn truncates_the_scaled_quotient_then_sign_extends_16_bits() {
        assert_eq!(interpolate(0, 3, 2, -3, 2), 3);
        assert_eq!(interpolate(0, 1, 1, 0, 0x0001_8000), -32768);
    }

    #[test]
    fn zero_span_uses_vertical_delta_only_for_nonzero_endpoint() {
        assert_eq!(interpolate(7, 7, 99, -9, 12), 21);
        assert_eq!(interpolate(0, 0, 99, -9, 12), 0);
    }

    #[test]
    fn preserves_wrapping_subtract_and_multiply_inputs() {
        let actual = interpolate(i32::MAX, i32::MIN, i32::MIN, 0, 2);
        let numerator = 2i32.wrapping_mul(i32::MIN.wrapping_sub(i32::MAX));
        let expected = unsafe { __rt_sdiv(numerator, i32::MIN.wrapping_sub(i32::MAX)) } as i16 as i32;
        assert_eq!(actual, expected);
    }
}
