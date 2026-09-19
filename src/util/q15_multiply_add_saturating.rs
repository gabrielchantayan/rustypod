//! Saturating Q15 multiply-add — `FUN_080b0614` @ `0x080b0614` (40 bytes;
//! 4 plain `bl` call sites, 0 predicated `bl` call sites).
//!
//! The 36-byte instruction body multiplies `sample` and `gain` with ARM's
//! low-32-bit `mul`, arithmetic-shifts the wrapped product right 15 bits, and
//! adds it to `accumulator` with wrapping arithmetic. It then clamps that sum
//! to the signed Q15 interval `[-32768, 32767]`; the final `lsl #16; asr #16`
//! returns the saturated value as a sign-extended `i16`. The remaining four
//! bytes through `0x080b0640` are the two clamp literals; the next real
//! function begins at `0x080b0644`.
//!
//! Deliberate deviations: none.

/// `q15_multiply_add_saturating` — original: `FUN_080b0614` @ `0x080b0614`.
///
/// Multiplies two signed Q15 values, adds the scaled result to `accumulator`,
/// and saturates to the signed Q15 range. The product and addition wrap at
/// 32 bits exactly as the ARM `mul; add` sequence does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn q15_multiply_add_saturating(sample: i32, gain: i32, accumulator: i32) -> i32 {
    let scaled = sample.wrapping_mul(gain) >> 15;
    accumulator.wrapping_add(scaled).clamp(-0x8000, 0x7fff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(sample: i32, gain: i32, accumulator: i32) -> i32 {
        let product = ((sample as i64) * (gain as i64)) as i32;
        let sum = accumulator.wrapping_add(product >> 15);
        sum.clamp(-0x8000, 0x7fff)
    }

    #[test]
    fn scales_and_accumulates_q15_values() {
        assert_eq!(q15_multiply_add_saturating(0x4000, 0x4000, 100), 8292);
        assert_eq!(q15_multiply_add_saturating(-0x4000, 0x4000, 100), -8092);
    }

    #[test]
    fn clamps_both_q15_boundaries() {
        assert_eq!(q15_multiply_add_saturating(0x7fff, 0x7fff, 1), 0x7fff);
        assert_eq!(q15_multiply_add_saturating(-0x8000, 0x7fff, -1), -0x8000);
        assert_eq!(q15_multiply_add_saturating(0, 0, 0x1_0000), 0x7fff);
        assert_eq!(q15_multiply_add_saturating(0, 0, -0x1_0000), -0x8000);
    }

    #[test]
    fn preserves_arm_32_bit_product_and_addition_wraparound() {
        assert_eq!(
            q15_multiply_add_saturating(i32::MIN, i32::MIN, i32::MAX),
            reference(i32::MIN, i32::MIN, i32::MAX)
        );
        assert_eq!(
            q15_multiply_add_saturating(i32::MAX, i32::MAX, i32::MIN),
            reference(i32::MAX, i32::MAX, i32::MIN)
        );
    }

    #[test]
    fn matches_independent_reference_at_signed_and_boundary_inputs() {
        for &sample in &[i32::MIN, -0x8000, -1, 0, 1, 0x4000, 0x7fff, i32::MAX] {
            for &gain in &[i32::MIN, -0x8000, -1, 0, 1, 0x4000, 0x7fff, i32::MAX] {
                for &accumulator in &[i32::MIN, -0x8001, -0x8000, -1, 0, 0x7ffe, 0x7fff, i32::MAX] {
                    assert_eq!(
                        q15_multiply_add_saturating(sample, gain, accumulator),
                        reference(sample, gain, accumulator),
                        "sample={sample:#x}, gain={gain:#x}, accumulator={accumulator:#x}"
                    );
                }
            }
        }
    }
}
