//! Q16.16 fixed-point conversion layer.
//!
//! `f32_to_fixed16_sat` — original: `FUN_080a67dc` @ 0x080a67dc (48 bytes
//! of code at 0x080a67dc..0x080a680b plus one literal word at 0x080a680c).
//!
//! retailOS is SOFT-FLOAT: a float travels as its raw IEEE-754 bit pattern
//! in r0, which is why the argument is a `u32` and not an `f32`. This module
//! does pure integer work; the float manipulation is delegated to the ported
//! ADS runtime helpers `__fscalb` (0x083ed150) and `__f2i` (0x083ec898).
//!
//! Algorithm (decoded from osos.dec, not from Ghidra — Ghidra falsely marks
//! this function no-return and truncates its callers):
//! two saturation compares on the raw bit pattern, then a scale-and-truncate
//! tail that is a tail call (`b`, not `bl`) into `__f2i`:
//!
//! 1. `ldr r1, [pc, #40]` / `cmp r0, r1` / `mvnge r0, #0x80000000` — a
//!    SIGNED compare against the literal 0x46ffff00 at 0x080a680c. Positive bit patterns order the
//!    same as their float values, so this catches every `x >= 32767.5`,
//!    `+Inf`, and every positive NaN, all of which return `i32::MAX`.
//!    Negative floats have a negative bit pattern and never take this arm.
//! 2. `cmp r0, #0xc7000000` / `movcs r0, #0x80000000` — an UNSIGNED compare.
//!    Negative floats have bit patterns >= 0x80000000 that grow as the value
//!    falls, so `>= 0xc7000000` catches every `x <= -32768.0`, `-Inf`, and
//!    every negative NaN, all of which return `i32::MIN`. Positive patterns
//!    are all below 0xc7000000 and never take this arm.
//! 3. Otherwise `__f2i(__fscalb(x, 16))` = `trunc(x * 65536)`.
//!
//! Because both non-finite classes are absorbed by the saturation compares,
//! the helpers are only ever reached with a finite `|x| < 32768`:
//! `__fscalb`'s fast path applies (biased exponent <= 0x8d, so the +16
//! exponent add can neither overflow nor hit the NaN/Inf field) and `__f2i`
//! sees `|value| < 2^31`, so neither helper's error/trap path is live here.
//! Subnormal inputs flush to +0.0 inside `__fscalb` rather than scaling; the
//! truncation would have produced 0 for them regardless, so the flush is not
//! observable in the result.
//!
//! Quirk worth knowing (faithful, not a deviation): the two thresholds are
//! not symmetric. The negative one, -32768.0, is the exact point where the
//! Q16.16 result would reach -2^31, but the positive one is 32767.5 rather
//! than the largest float below 32768 — so the highest non-saturated output
//! is 0x7fff7f80 and everything above jumps straight to `i32::MAX`. The
//! original does exactly this; the port reproduces it. (names.yaml recorded
//! this literal as 32767.984375; the raw word 0x46ffff00 decodes to 32767.5.)

use crate::fp::fp_fconv::__f2i;
use crate::fp::fp_scalb::__fscalb;

/// Literal at 0x080a680c: 0x46ffff00 = 32767.5f. Compared SIGNED.
const POS_SAT_THRESHOLD: i32 = 0x46ff_ff00;

/// Inline immediate at 0x080a67f0: 0xc7000000 = -32768.0f. Compared UNSIGNED.
const NEG_SAT_THRESHOLD: u32 = 0xc700_0000;

/// Number of fractional bits in the Q16.16 result.
const FIXED16_SHIFT: i32 = 16;

/// f32_to_fixed16_sat — original: `FUN_080a67dc` @ 0x080a67dc (48 bytes).
///
/// Converts the IEEE-754 float whose bit pattern is `x` into a Q16.16
/// fixed-point s32, truncating toward zero and clamping to `i32::MAX` /
/// `i32::MIN` outside `(-32768.0, 32767.5)`. `+Inf` and positive NaNs
/// clamp high, `-Inf` and negative NaNs clamp low.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn f32_to_fixed16_sat(x: u32) -> i32 {
    if (x as i32) >= POS_SAT_THRESHOLD {
        return i32::MAX;
    }
    if x >= NEG_SAT_THRESHOLD {
        return i32::MIN;
    }
    __f2i(__fscalb(x, FIXED16_SHIFT))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Independent oracle: exact rational scaling in f64, truncated.
    /// Only valid on the non-saturating domain, which is asserted first.
    fn reference(bits: u32) -> i32 {
        let value = f32::from_bits(bits);
        assert!(value.is_finite() && value > -32768.0 && value < 32767.5);
        (f64::from(value) * 65536.0).trunc() as i32
    }

    fn convert(bits: u32) -> i32 {
        unsafe { f32_to_fixed16_sat(bits) }
    }

    fn of(value: f32) -> i32 {
        convert(value.to_bits())
    }

    #[test]
    fn firmware_witnessed_constants() {
        // Both constants and both expected results come from the
        // fixed16_sin/fixed16_cos literal pools (0x080e9900/0x080e9828),
        // where these exact words are what the sine reduction consumes.
        assert_eq!(convert(0x40c9_0fdb), 0x6487e); // 2*pi   -> 411774
        assert_eq!(convert(0x3e22_f983), 0x28be); // 1/(2*pi) ->  10430
    }

    #[test]
    fn zero_keeps_zero() {
        assert_eq!(of(0.0), 0);
        assert_eq!(of(-0.0), 0);
    }

    #[test]
    fn exact_powers_of_two() {
        assert_eq!(of(1.0), 0x1_0000);
        assert_eq!(of(-1.0), -0x1_0000);
        assert_eq!(of(0.5), 0x8000);
        assert_eq!(of(256.0), 0x100_0000);
        assert_eq!(of(f32::from_bits(0x3780_0000)), 1); // 2^-16, the ulp
        assert_eq!(of(f32::from_bits(0x3700_0000)), 0); // 2^-17 truncates away
        assert_eq!(of(f32::from_bits(0xb700_0000)), 0); // -2^-17 likewise
    }

    #[test]
    fn truncates_toward_zero_not_down() {
        assert_eq!(of(1.5), 0x1_8000);
        assert_eq!(of(-1.5), -0x1_8000);
        // 1/3 in Q16.16 is 21845.33..: both signs must land on 21845.
        assert_eq!(of(1.0 / 3.0), 21845);
        assert_eq!(of(-1.0 / 3.0), -21845);
        // A value whose Q16.16 expansion is exact takes no rounding at all.
        assert_eq!(of(0.25), 0x4000);
    }

    #[test]
    fn positive_saturation_boundary() {
        assert_eq!(convert(POS_SAT_THRESHOLD as u32), i32::MAX);
        assert_eq!(convert(POS_SAT_THRESHOLD as u32 + 1), i32::MAX);
        // One ulp below the threshold still converts, and lands well short
        // of i32::MAX — the documented gap in the original.
        let below = POS_SAT_THRESHOLD as u32 - 1;
        assert_eq!(convert(below), reference(below));
        assert_eq!(convert(below), 0x7fff_7f80);
        assert_eq!(of(32767.0), 0x7fff_0000);
    }

    #[test]
    fn negative_saturation_boundary() {
        assert_eq!(convert(NEG_SAT_THRESHOLD), i32::MIN); // -32768.0 exactly
        assert_eq!(convert(NEG_SAT_THRESHOLD + 1), i32::MIN); // more negative
        assert_eq!(of(-40000.0), i32::MIN);
        // Largest magnitude that still converts: one ulp above -32768.0.
        let inside = NEG_SAT_THRESHOLD - 1;
        assert_eq!(convert(inside), reference(inside));
        assert_eq!(of(-32767.0), -0x7fff_0000);
    }

    #[test]
    fn infinities_and_nans_clamp_by_sign() {
        assert_eq!(convert(0x7f80_0000), i32::MAX); // +Inf
        assert_eq!(convert(0xff80_0000), i32::MIN); // -Inf
        assert_eq!(convert(0x7fc0_0000), i32::MAX); // +qNaN
        assert_eq!(convert(0xffc0_0000), i32::MIN); // -qNaN
        assert_eq!(convert(0x7f80_0001), i32::MAX); // +sNaN
        assert_eq!(convert(0xff80_0001), i32::MIN); // -sNaN
        assert_eq!(convert(0x7fff_ffff), i32::MAX); // max NaN payload
        assert_eq!(convert(0xffff_ffff), i32::MIN);
    }

    #[test]
    fn subnormals_flush_to_zero() {
        assert_eq!(convert(0x0000_0001), 0); // smallest positive subnormal
        assert_eq!(convert(0x007f_ffff), 0); // largest positive subnormal
        assert_eq!(convert(0x8000_0001), 0);
        assert_eq!(convert(0x807f_ffff), 0);
        assert_eq!(convert(0x0080_0000), 0); // smallest normal, still 0
    }

    #[test]
    fn matches_reference_over_the_finite_domain() {
        let mut cases: Vec<u32> = Vec::new();
        // Every exponent, several mantissas, both signs.
        for exponent in 1u32..=0x8du32 {
            for mantissa in [0u32, 1, 0x1234, 0x40_0000, 0x7f_ffff] {
                cases.push((exponent << 23) | mantissa);
                cases.push(0x8000_0000 | (exponent << 23) | mantissa);
            }
        }
        // Dense sweep of the top decade, where truncation is coarsest.
        for step in 0..4096u32 {
            cases.push(0x4600_0000 + step * 0x40);
            cases.push(0xc600_0000 + step * 0x40);
        }
        let mut checked = 0;
        for bits in cases {
            let value = f32::from_bits(bits);
            if !(value.is_finite() && value > -32768.0 && value < 32767.5) {
                continue;
            }
            assert_eq!(convert(bits), reference(bits), "bits {bits:#010x}");
            checked += 1;
        }
        assert!(checked > 2000, "sweep covered only {checked} cases");
    }
}
