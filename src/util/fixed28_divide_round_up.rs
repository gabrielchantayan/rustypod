//! Q4.28 fixed-point division with retailOS's quotient adjustment.
//!
//! `fixed28_divide_round_up` — original: `FUN_08256d40` @ 0x08256d40
//! (52 bytes).
//!
//! Raw `osos.dec` establishes the complete 13-instruction A32 body
//! 0x08256d40..0x08256d70; the `ldr r2,[r0]` at 0x08256d74 begins the next
//! function. The body has one plain outbound `bl` to the already ported
//! `__aeabi_ldivmod` at 0x0802ee34 and no predicated `bl` forms. Full-image
//! A32 decoding finds three plain inbound `bl` call sites (0x0824fd10,
//! 0x0824fd34, and 0x0824fee0) and no predicated inbound forms.
//!
//! # Algorithm
//!
//! Sign-extend `numerator` to i64, shift it left 29 bits, and divide by the
//! sign-extended `denominator`. Add one to the signed quotient and arithmetic
//! shift right one bit; return its low word. This computes the retail Q4.28
//! quotient with its asymmetric adjustment for negative quotients. Division
//! by zero remains the existing `__aeabi_ldivmod` port's documented deviation
//! (zero quotient) from the ADS divide-by-zero handler; no new deviation is
//! introduced here.

use crate::runtime::aeabi_64div::__aeabi_ldivmod;

/// fixed28_divide_round_up — retailOS `FUN_08256d40` at `0x08256d40`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn fixed28_divide_round_up(numerator: i32, denominator: i32) -> i32 {
    let scaled_numerator = (numerator as i64) << 29;
    let quotient = unsafe { __aeabi_ldivmod(scaled_numerator, denominator as i64) };
    (quotient.wrapping_add(1) >> 1) as i32
}

#[cfg(test)]
mod tests {
    use super::fixed28_divide_round_up;

    fn reference(numerator: i32, denominator: i32) -> i32 {
        let quotient = ((numerator as i64) << 29) / denominator as i64;
        (quotient.wrapping_add(1) >> 1) as i32
    }

    #[test]
    fn matches_signed_scaled_division_at_boundaries() {
        let numerators = [i32::MIN, i32::MIN + 1, -7, -2, -1, 0, 1, 2, 7, i32::MAX - 1, i32::MAX];
        let denominators = [i32::MIN, -7, -3, -2, -1, 1, 2, 3, 7, i32::MAX];

        for numerator in numerators {
            for denominator in denominators {
                assert_eq!(
                    fixed28_divide_round_up(numerator, denominator),
                    reference(numerator, denominator),
                    "numerator={numerator}, denominator={denominator}",
                );
            }
        }
    }

    #[test]
    fn preserves_the_quotient_adjustment_for_signed_remainders() {
        for (numerator, denominator) in [(1, 3), (-1, 3), (1, -3), (-1, -3), (7, 5), (-7, 5)] {
            let quotient = ((numerator as i64) << 29) / denominator as i64;
            assert_eq!(fixed28_divide_round_up(numerator, denominator), reference(numerator, denominator));
            assert_eq!(fixed28_divide_round_up(numerator, denominator) as i64, (quotient + 1) >> 1);
        }
    }
}
