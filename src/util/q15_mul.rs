//! Q15 fixed-point multiply — `FUN_08078400` @ 0x08078400 (16 bytes;
//! 12 `bl` call sites).
//!
//! A pure leaf used by the audio interpolation path (its callers weight a
//! sample against a Q15 fraction and its `0x8000 - frac` complement). It
//! multiplies two signed values, doubles, and takes the top 16 bits:
//! `(a * b * 2) >> 16`, i.e. a Q15×Q15→Q15 fractional multiply.
//!
//! The doubling happens in 32-bit and can overflow: the extreme
//! `(-0x8000) * (-0x8000)` forms `0x4000_0000`, whose `<< 1` wraps to
//! `0x8000_0000` and arithmetic-shifts down to **-32768**, not +32768.
//! The port preserves that 32-bit wrap exactly.
//!
//! The original is three instructions:
//!
//! ```text
//! mul r0, r1, r0
//! mov r0, r0, lsl #1
//! mov r0, r0, asr #0x10
//! bx  lr
//! ```

/// q15_mul — original: `FUN_08078400` @ 0x08078400 (16 bytes).
///
/// Signed Q15 fixed-point multiply: `(a * b * 2) >> 16`, evaluated with
/// 32-bit wrapping so the product doubling truncates exactly as the
/// original `mul; lsl #1; asr #16` does.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn q15_mul(a: i32, b: i32) -> i32 {
    (a.wrapping_mul(b) << 1) >> 16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_operand_yields_zero() {
        assert_eq!(q15_mul(0, 12345), 0);
        assert_eq!(q15_mul(12345, 0), 0);
    }

    #[test]
    fn half_times_half_is_a_quarter() {
        // 0.5 * 0.5 = 0.25 in Q15: 0x4000 * 0x4000 -> 8192 (0.25 * 32768).
        assert_eq!(q15_mul(0x4000, 0x4000), 8192);
    }

    #[test]
    fn near_unity_product() {
        assert_eq!(q15_mul(0x7fff, 0x7fff), 32766);
    }

    #[test]
    fn sign_is_carried_through() {
        assert_eq!(q15_mul(-0x4000, 0x4000), -8192);
        assert_eq!(q15_mul(-0x8000, 0x7fff), -32767);
    }

    #[test]
    fn sub_unit_products_round_toward_zero_to_nothing() {
        assert_eq!(q15_mul(1, 1), 0);
        assert_eq!(q15_mul(0x7fff, 1), 0);
    }

    #[test]
    fn the_min_square_overflow_corner_wraps_to_negative() {
        // (-0x8000)^2 * 2 overflows int32 and wraps: the answer is -32768,
        // NOT +32768. This is the whole reason the port must be exact.
        assert_eq!(q15_mul(-0x8000, -0x8000), -32768);
    }

    #[test]
    fn matches_reference_over_the_i16_range() {
        // Independent oracle: full-precision i64 product, doubled, then
        // truncated to 32 bits (as the hardware `lsl #1` does) and shifted.
        fn reference(a: i32, b: i32) -> i32 {
            let doubled = ((a as i64) * (b as i64)) << 1;
            (doubled as i32) >> 16
        }
        let mut x = -0x8000i32;
        while x <= 0x7fff {
            for &y in &[-0x8000, -0x4000, -1, 0, 1, 0x1234, 0x4000, 0x7fff] {
                assert_eq!(q15_mul(x, y), reference(x, y), "x={x:#x} y={y:#x}");
            }
            x += 0x101; // stride the range without a full 65k^2 sweep
        }
    }
}
