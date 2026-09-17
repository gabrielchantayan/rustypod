//! Q16.16 fixed-point conversion layer.
//!
//! `f32_to_fixed16_sat` — original: `FUN_080a67dc` @ 0x080a67dc (48 bytes
//! of code at 0x080a67dc..0x080a680b plus one literal word at 0x080a680c).
//!
//! `fixed16_to_f32` — original: `FUN_080a6810` @ 0x080a6810 (24 bytes).
//!
//! retailOS is SOFT-FLOAT: each f32 travels as its raw IEEE-754 bit pattern
//! in r0. The f32-to-fixed input is therefore `u32`, as is the
//! fixed-to-f32 result; the Q16.16 argument itself is a signed `i32`.
//! This module does pure integer work; its float manipulation delegates to
//! ported ADS runtime helpers.
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

use crate::fp::fp_dconv::__i2d;
use crate::fp::fp_fconv::{__d2f, __f2i};
use crate::fp::fp_scalb::{__dscalb, __fscalb};

/// Literal at 0x080a680c: 0x46ffff00 = 32767.5f. Compared SIGNED.
const POS_SAT_THRESHOLD: i32 = 0x46ff_ff00;

/// Inline immediate at 0x080a67f0: 0xc7000000 = -32768.0f. Compared UNSIGNED.
const NEG_SAT_THRESHOLD: u32 = 0xc700_0000;

/// Number of fractional bits in the Q16.16 result.
const FIXED16_SHIFT: i32 = 16;

/// fixed16_to_f32 — original: `FUN_080a6810` @ 0x080a6810 (24 bytes).
///
/// Converts a Q16.16 signed fixed-point value to an IEEE-754 f32 bit pattern.
/// The retail sequence converts the integer exactly with `__i2d`, scales that
/// double by 2^-16 through `__dscalb`, then tail-branches to `__d2f`; the
/// final narrowing therefore rounds to nearest-even. Raw `osos.dec` confirms
/// exactly six inbound calls, all unconditional `bl` (none predicated):
/// 0x0824ed3c, 0x082501bc, 0x082501c8, 0x082501d4, 0x082501e0, and
/// 0x0825d818. No deliberate behavioral deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fixed16_to_f32")]
pub unsafe extern "C" fn fixed16_to_f32(x: i32) -> u32 {
    __d2f(__dscalb(__i2d(x), -FIXED16_SHIFT))
}

/// fixed16_words_to_f32 — original: `FUN_0825d800` @ 0x0825d800 (44 bytes).
///
/// Converts `count` consecutive signed Q16.16 words from `src` to IEEE-754
/// f32 bit patterns in `dst`. The raw ARM body spans 0x0825d800..0x0825d82b;
/// the `stmdb` at 0x0825d82c starts the next function. It has one direct,
/// unconditional in-body `bl` to `fixed16_to_f32`, no predicated direct
/// calls, and four unconditional inbound `bl` call sites. The entry branch
/// decrements before the first load, so zero count returns without touching
/// either buffer. No deliberate behavioral deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fixed16_words_to_f32")]
pub unsafe extern "C" fn fixed16_words_to_f32(src: *const i32, dst: *mut u32, count: u32) {
    let mut src = src;
    let mut dst = dst;
    for _ in 0..count {
        *dst = fixed16_to_f32(*src);
        src = src.add(1);
        dst = dst.add(1);
    }
}

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
 
/// Fields read by [`fixed16_fog_factor`] from its opaque renderer state.
/// `repr(C)` preserves the 32-bit target's source offsets when host fixtures
/// allocate the state; no field is accessed through an integer byte offset.
#[repr(C)]
struct FogFactorState {
    _before_mode: [u8; 0x8b8],
    mode: u8,
    _between_mode_and_scale: [u8; 7],
    scale: i32,
    linear_base: i32,
    linear_multiplier: i32,
    linear_shift: u8,
}

/// fixed16_fog_factor — original: `FUN_082a0558` @ 0x082a0558 (124 bytes).
///
/// Selects a Q16.16 fog factor from an opaque renderer state and signed
/// distance. Mode 1 returns `exp(-distance * scale)`; mode 2 applies the
/// same exponential to the squared product; every other mode takes the
/// linear `fixed16_mul((linear_base - distance) >> linear_shift,
/// linear_multiplier)` path. It rounds by adding 0x80, then clamps the
/// returned Q16.16 factor to `[0, 1]`.
///
/// The exponential path negates with ARM wrapping semantics, converts the
/// scaled Q16.16 value to float, evaluates retailOS `expf`, then converts
/// back through the same `__fscalb(..., 16)` / `__f2i` sequence as
/// `f32_to_fixed16_sat`, including its asymmetric `32767.5` / `-32768.0`
/// saturation thresholds.
///
/// Raw `osos.dec` confirms the full extent 0x082a0558..0x082a05d3: the
/// `stmdb` at 0x082a05d4 starts the next sibling, and no literal pool
/// intervenes. Decoding every ARM B/BL-immediate word finds exactly six
/// inbound call sites, all unconditional `bl` (none predicated):
/// 0x0824d7dc, 0x0824d808, 0x0824f520, 0x08251c6c, 0x08251ca4, and
/// 0x08251cc4. No deliberate behavioral deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fixed16_fog_factor")]
pub unsafe extern "C" fn fixed16_fog_factor(state: *const u8, distance: i32) -> i32 {
    let state = unsafe { &*state.cast::<FogFactorState>() };
    let factor = match state.mode {
        1 => fixed16_exp_neg(crate::util::fixed::fixed16_mul(distance, state.scale)),
        2 => {
            let scaled = crate::util::fixed::fixed16_mul(distance, state.scale);
            fixed16_exp_neg(crate::util::fixed::fixed16_mul(scaled, scaled))
        }
        _ => crate::util::fixed::fixed16_mul(
            arm_asr(state.linear_base.wrapping_sub(distance), state.linear_shift),
            state.linear_multiplier,
        ),
    };
    let rounded = factor.wrapping_add(0x80);
    if rounded < 0 {
        0
    } else if rounded > 0x1_0000 {
        0x1_0000
    } else {
        rounded
    }
}

/// Evaluates the exponential portion of modes 1 and 2.
///
/// The original's `__i2d` / double scaling / `__d2f` sequence is
/// result-equivalent to `__i2f` then a power-of-two `__fscalb`: rounding an
/// integer to binary32 commutes with an exact exponent adjustment.
fn fixed16_exp_neg(n: i32) -> i32 {
    unsafe {
        let scaled_neg_n = crate::fp::fp_scalb::__fscalb(
            crate::fp::fp_fconv::__i2f(n.wrapping_neg()),
            -FIXED16_SHIFT,
        );
        f32_to_fixed16_sat(crate::libm::sqrt::expf(scaled_neg_n))
    }
}

/// ARM register arithmetic right shift, which uses only the low byte of the
/// shift count and yields sign fill for counts of 32 or greater.
fn arm_asr(value: i32, shift: u8) -> i32 {
    let shift = u32::from(shift);
    if shift < 32 { value >> shift } else if value < 0 { -1 } else { 0 }
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

    /// Independent oracle: Q16.16 is exactly representable in f64, then the
    /// cast supplies the required IEEE round-to-nearest-even narrowing.
    fn fixed16_to_float_reference(x: i32) -> u32 {
        (((x as f64) / 65536.0) as f32).to_bits()
    }

    fn fixed_to_float(x: i32) -> u32 {
        unsafe { fixed16_to_f32(x) }
    }

    #[test]
    fn fixed16_to_float_scales_sign_extremes_and_rounding_boundaries() {
        for x in [
            i32::MIN,
            -0x7fff_ffc0,
            -0x1_8000,
            -0x1,
            0,
            1,
            0x1_8000,
            0x1234_5678,
            0x7fff_ffbf,
            0x7fff_ffc0,
            i32::MAX,
        ] {
            assert_eq!(fixed_to_float(x), fixed16_to_float_reference(x), "x {x:#010x}");
        }

        // Adjacent Q16.16 values straddle the midpoint between the final two
        // binary32 values below 32768; the midpoint selects the even 32768.
        assert_eq!(fixed_to_float(0x7fff_ffbf), 0x46ff_ffff);
        assert_eq!(fixed_to_float(0x7fff_ffc0), 0x4700_0000);
        assert_eq!(fixed_to_float(i32::MIN), 0xc700_0000);
    }

    #[test]
    fn fixed16_words_to_f32_converts_consecutive_words_only() {
        let source = [
            0x55aa_55aai32,
            i32::MIN,
            -1,
            0,
            1,
            0x7fff_ffc0,
            i32::MAX,
        ];
        let mut destination = [0xfeed_face_u32; 7];

        unsafe {
            fixed16_words_to_f32(source.as_ptr().add(1), destination.as_mut_ptr().add(2), 4);
        }

        assert_eq!(destination[..2], [0xfeed_face; 2]);
        assert_eq!(destination[2], fixed16_to_float_reference(i32::MIN));
        assert_eq!(destination[3], fixed16_to_float_reference(-1));
        assert_eq!(destination[4], fixed16_to_float_reference(0));
        assert_eq!(destination[5], fixed16_to_float_reference(1));
        assert_eq!(destination[6], 0xfeed_face);

        unsafe {
            fixed16_words_to_f32(source.as_ptr(), destination.as_mut_ptr(), 0);
        }
        assert_eq!(destination, [
            0xfeed_face,
            0xfeed_face,
            fixed16_to_float_reference(i32::MIN),
            fixed16_to_float_reference(-1),
            fixed16_to_float_reference(0),
            fixed16_to_float_reference(1),
            0xfeed_face,
        ]);
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
    fn fog(state: &FogFactorState, distance: i32) -> i32 {
        unsafe { fixed16_fog_factor((state as *const FogFactorState).cast(), distance) }
    }

    fn fog_state(mode: u8, scale: i32, linear_base: i32, linear_multiplier: i32, linear_shift: u8) -> FogFactorState {
        FogFactorState {
            _before_mode: [0; 0x8b8],
            mode,
            _between_mode_and_scale: [0; 7],
            scale,
            linear_base,
            linear_multiplier,
            linear_shift,
        }
    }

    fn fixed16_mul_reference(a: i32, b: i32) -> i32 {
        (((a as i64) * (b as i64)) >> 16) as i32
    }

    fn finish_fog_reference(factor: i32) -> i32 {
        let rounded = factor.wrapping_add(0x80);
        if rounded < 0 {
            0
        } else if rounded > 0x1_0000 {
            0x1_0000
        } else {
            rounded
        }
    }

    #[test]
    fn fog_state_fields_match_retailos_offsets() {
        let state = fog_state(2, 3, 4, 5, 6);
        let base = (&state as *const FogFactorState) as usize;
        assert_eq!((&state.mode as *const u8) as usize - base, 0x8b8);
        assert_eq!((&state.scale as *const i32) as usize - base, 0x8c0);
        assert_eq!((&state.linear_base as *const i32) as usize - base, 0x8c4);
        assert_eq!((&state.linear_multiplier as *const i32) as usize - base, 0x8c8);
        assert_eq!((&state.linear_shift as *const u8) as usize - base, 0x8cc);
    }

    #[test]
    fn fog_linear_mode_scales_shifts_rounds_and_clamps() {
        let state = fog_state(0, 0, 0x1_8000, 0x1_0000, 0);
        assert_eq!(fog(&state, 0x1_0000), 0x8080);
        assert_eq!(fog(&state, 0), 0x1_0000);

        let shifted = fog_state(3, 0, 0x4_0000, 0x1_0000, 2);
        assert_eq!(fog(&shifted, 0x2_0000), 0x8080);

        let negative = fog_state(0, 0, 0, 0x1_0000, 0);
        assert_eq!(fog(&negative, 0x1_0000), 0);
    }

    #[test]
    fn fog_exponential_modes_cover_identity_decay_and_extremes() {
        let exp = fog_state(1, 0x1_0000, 0, 0, 0);
        assert_eq!(fog(&exp, 0), 0x1_0000);
        assert_eq!(fog(&exp, 0x1_0000), 0x5ead);
        assert_eq!(fog(&exp, i32::MAX), 0x80);
        assert_eq!(fog(&exp, i32::MIN), 0x80);
        assert_eq!(fog(&exp, -1), 0x1_0000);

        let exp2 = fog_state(2, 0x1_0000, 0, 0, 0);
        assert_eq!(fog(&exp2, 0x1_0000), 0x5ead);
        assert_eq!(fog(&exp2, 0x2_0000), 0x530);
    }

    #[test]
    fn fog_linear_mode_matches_independent_fixed_reference() {
        let state = fog_state(7, 0, 0x5_0000, -0x8000, 5);
        for distance in [-0x2_0000, -1, 0, 1, 0x1_0000, 0x7fff_ffff, i32::MIN] {
            let shifted = arm_asr(state.linear_base.wrapping_sub(distance), state.linear_shift);
            let factor = fixed16_mul_reference(shifted, state.linear_multiplier);
            assert_eq!(fog(&state, distance), finish_fog_reference(factor), "distance {distance:#x}");
        }
    }
}
