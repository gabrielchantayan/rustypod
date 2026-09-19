//! Signed division quotient adjustment — original `FUN_0805009c` @ `0x0805009c` (60 bytes).
//!
//! Verified call count: one plain `bl` (`__aeabi_ldivmod` at `0x0802ee34`),
//! no predicated `bl`; four retail call sites. It divides the signed 64-bit
//! value assembled from `numerator_high:numerator_low` by the positive u32
//! divisor, then increments the quotient whenever the numerator high word is
//! nonzero or `quotient_low * divisor` does not recover the low word.
//!
//! Deliberate deviation: the retail ABI leaves divide-by-zero behavior to the
//! ADS divide-by-zero handler. The existing Rust `__aeabi_ldivmod` seam returns
//! zero for that unsupported input, so this wrapper inherits that seam's result.

use crate::runtime::aeabi_64div::__aeabi_ldivmod;

/// Retail signed-division quotient adjustment at `0x0805009c`.
///
/// The surrounding callers supply a non-negative numerator and non-zero
/// divisor. The separate word arguments preserve the target ARM register ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_div_quotient_round_up(
    numerator_low: u32,
    numerator_high: u32,
    divisor: u32,
) -> u32 {
    let numerator = ((numerator_high as u64) << 32 | numerator_low as u64) as i64;
    let quotient = __aeabi_ldivmod(numerator, divisor as i64) as u32;
    let product_low = divisor.wrapping_mul(quotient);

    if numerator_high != 0 || product_low != numerator_low {
        quotient.wrapping_add(1)
    } else {
        quotient
    }
}

#[cfg(test)]
mod tests {
    use super::signed_div_quotient_round_up;

    fn reference(numerator_low: u32, numerator_high: u32, divisor: u32) -> u32 {
        let numerator = ((numerator_high as u64) << 32 | numerator_low as u64) as i64;
        let quotient = (numerator / divisor as i64) as u32;
        quotient.wrapping_add(u32::from(
            numerator_high != 0 || divisor.wrapping_mul(quotient) != numerator_low,
        ))
    }

    #[test]
    fn rounds_exact_and_fractional_low_word_dividends() {
        for (numerator, divisor) in [(0, 1), (24, 6), (25, 6), (u32::MAX as u64, 7)] {
            let actual = unsafe { signed_div_quotient_round_up(numerator as u32, 0, divisor) };
            assert_eq!(actual, reference(numerator as u32, 0, divisor));
        }
    }

    #[test]
    fn increments_for_nonzero_high_word_even_when_low_product_matches() {
        let actual = unsafe { signed_div_quotient_round_up(12, 3, 6) };
        assert_eq!(actual, reference(12, 3, 6));
    }

    #[test]
    fn handles_largest_nonnegative_signed_numerator() {
        let numerator = i64::MAX as u64;
        let actual = unsafe {
            signed_div_quotient_round_up(numerator as u32, (numerator >> 32) as u32, u32::MAX)
        };
        assert_eq!(
            actual,
            reference(numerator as u32, (numerator >> 32) as u32, u32::MAX)
        );
    }
}
