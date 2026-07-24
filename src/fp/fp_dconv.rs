//! Ports of the ARM ADS 1.0.1 soft-float double<->integer conversions:
//!
//! - `__d2i`   — original: `FUN_083eb7d0` @ 0x083eb7d0 (184 bytes, 55 callers).
//! - `__d2u`   — original: `FUN_083eb880` @ 0x083eb880 (132 bytes, 4 callers).
//! - `__i2d`   — original: `FUN_083eb908` @ 0x083eb908 (48 bytes, 65 callers).
//! - `__u2d`   — original: `FUN_083eb9b4` @ 0x083eb9b4 (12 bytes, 32 callers)
//!   — tail-branches into the `__i2d` core at 0x083eb918 with sign = +.
//! - `__ll2d`  — original: `FUN_083eb940` @ 0x083eb940 (116 bytes, 10 callers).
//! - `__ull2d` — original: `FUN_083eb938` @ 0x083eb938 (8 bytes, 7 callers)
//!   — tail-branches into the `__ll2d` core at 0x083eb954 with sign = +.
//! - `__d2ll`  — original: `FUN_083ece5c` @ 0x083ece5c (212 bytes, 4 callers).
//! - `__d2ull` — original: `FUN_083ecf34` @ 0x083ecf34 (148 bytes, 1 caller).
//!
//! retailOS is SOFT-FLOAT: doubles travel in register pairs / `u64` as raw
//! IEEE-754 bit patterns. This module is pure integer bit manipulation — no
//! f64 arithmetic anywhere (it would lower to the unported `__aeabi_d*`
//! helpers). Host tests use native `f64::from_bits`/`to_bits` as the oracle
//! (IEEE round-to-nearest-even, saturating `as` casts).
//!
//! Rounding / range behavior (mirrors the originals exactly):
//! - int -> double: `__i2d`/`__u2d` are always exact (<= 32 significant bits
//!   fit in the 53-bit mantissa). `__ll2d`/`__ull2d` keep 53 bits and round
//!   the residue to nearest, ties to even (guard = bit 10 of the shifted-out
//!   low word, sticky = bits 9:0, tie flips up only when the kept LSB is 1).
//! - double -> int: TRUNCATES toward zero (pure right shift of the
//!   hidden-bit-restored mantissa by `(1023 + 31) - exp` resp.
//!   `(1023 + 63) - exp`).
//! - Negative input to the unsigned conversions yields 0 (`__d2u`/`__d2ull`
//!   only take the shift path for non-negative inputs; negative values with
//!   |x| < 1.0 return 0 directly, |x| >= 1.0 falls into the overflow clamp,
//!   which for negative sign is also 0).
//! - Finite overflow (incl. +/-Inf) clamps to the destination's
//!   min/max: i32::MIN/MAX, u32::MAX, i64::MIN/MAX, u64::MAX (the original's
//!   `mvn rD, r1, asr #31` [+ `eor #0x80000000` for signed] saturation).
//!   `-2^31` / `-2^63` are in range and convert exactly; `-(2^31)-1` /
//!   `-(2^63)-1` take the overflow route and clamp to the same MIN values.
//! - NaN input raises the ADS error descriptor (0x040200c8 / e8 / d8 / f8,
//!   OR'd with the 0x10000 invalid-operation flag) via the double dispatcher
//!   @ 0x083eb144 into the trap decode @ 0x083ed080. All four descriptors
//!   have low nibble 8 with bit 6 set, so the decode yields +0 in both words
//!   — i.e. NaN converts to 0. This is routed through the
//!   [`crate::fp_scalb::FP_TRAP_HANDLER`] hook (default: return the decoded
//!   value, 0); replace the hook to observe the trap.
//!
//! Deliberate simplifications:
//! - The overflow path's NaN test (`adc r3, r1, r1; cmn r3, #0x200000`) is
//!   written semantically as `exponent == 0x7ff && mantissa != 0` — bit-for-
//!   bit equivalent.
//! - `__ll2d`'s rounding computes the round-up carry directly
//!   (guard && (sticky || lsb)) instead of the original's flag acrobatics
//!   (`lsls` carry-out for the sticky case, `and`+`lsrs` bit-10 carry for
//!   the tie case); the pushed-then-discarded sticky marker word (a leftover
//!   of ADS's shared rounding macro) is not modeled — it never affects the
//!   result.
//! - The on-device "print register dump and trap" for unhandled errors is
//!   represented by the FP_TRAP_HANDLER hook, same as `fp_scalb`.

/// Error descriptors raised by the double->int conversions on NaN input,
/// with the 0x10000 invalid-operation flag OR'd in (the original's
/// `orrhi ip, ip, #0x10000`). Low nibble 8 + bit 6 set => trap decode
/// yields +0.0 (both result words zeroed).
const D2I_NAN_DESCRIPTOR: u32 = 0x0403_00c8;
const D2U_NAN_DESCRIPTOR: u32 = 0x0403_00e8;
const D2LL_NAN_DESCRIPTOR: u32 = 0x0403_00d8;
const D2ULL_NAN_DESCRIPTOR: u32 = 0x0403_00f8;

/// The original's NaN test on the overflow path:
/// `cmp r0, #1; adc r3, r1, r1; cmn r3, #0x200000; bhi <trap>` — i.e.
/// exponent field all ones and any mantissa bit set.
#[inline(always)]
fn is_nan(hi: u32, lo: u32) -> bool {
    (hi >> 20) & 0x7ff == 0x7ff && (hi << 12) | lo != 0
}

/// NaN input to a double->int conversion: dispatcher 0x083eb144 loads the
/// canonical double qNaN (0x7ff80000:0) and enters the trap decode
/// @ 0x083ed080 with `descriptor`; nibble 8 + bit 6 rewrites the result to
/// +0 in both words, so the decoded value is 0. Routed through the shared
/// FP_TRAP_HANDLER hook (default returns the decoded value unchanged).
#[inline(always)]
unsafe fn nan_trap(descriptor: u32) -> u64 {
    (crate::fp_scalb::FP_TRAP_HANDLER)(descriptor, 0)
}

/// Hidden-bit-restored top mantissa word: fraction bits 51:21 with the
/// implicit leading 1 at bit 31 (only when the exponent field is nonzero;
/// the original's `orrne r3, r3, #0x80000000` keyed off `asrs r2, r1, #20`).
#[inline(always)]
fn mantissa_top(hi: u32, lo: u32) -> u32 {
    let mut top = (hi << 11) | (lo >> 21);
    if (hi as i32) >> 20 != 0 {
        top |= 0x8000_0000;
    }
    top
}

/// __d2i — original: `FUN_083eb7d0` @ 0x083eb7d0 (184 bytes).
///
/// double -> i32, truncation toward zero. `x` is the raw double bit pattern
/// (r1:r0 = hi:lo in the original). shift = (1023 + 31) - exp; the
/// hidden-bit-restored top mantissa word shifts right by that amount.
/// Negative inputs take the negate path (`sub r1, r1, r3, lsr r2` with the
/// "wrapped positive" result 0 - mantissa detecting the -(2^31)-1 overflow).
/// |x| >= 2^31, +/-Inf -> clamp to i32::MIN/MAX; NaN -> trap route (0).
#[no_mangle]
pub unsafe extern "C" fn __d2i(x: u64) -> i32 {
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    let mut top = mantissa_top(hi, lo);
    let exp_sign = (hi as i32) >> 20; // biased exponent, sign bit included

    if exp_sign >= 0 {
        // Positive: shift = 0x9e - (exp - 0x380) = 1054 - exp.
        let shift = 0x9e - (exp_sign - 0x380);
        if shift <= 0 {
            return d2i_overflow(hi, lo);
        }
        // ARM register LSR yields 0 for shift > 31 (the `movgt r1, #0` for
        // shift > 255 is subsumed).
        let mag = if shift > 31 { 0 } else { top >> shift };
        return mag as i32;
    }

    // Negative: clear the sign from the exponent field (`lsl/lsr #21`).
    let exp = exp_sign & 0x7ff;
    if exp == 0 {
        // Denormal/-0.0: drop the hidden bit back out (`biceq`).
        top &= 0x7fff_ffff;
    }
    let shift = 0x9e - (exp - 0x380);
    if shift < 0 {
        return d2i_overflow(hi, lo);
    }
    let shifted = if shift > 31 { 0 } else { top >> shift };
    let result = 0u32.wrapping_sub(shifted);
    // Result is 0 or negative: fine. A wrapped-positive result means
    // |x| > 2^31 (only -2^31 itself stays negative) -> overflow.
    if (result as i32) <= 0 {
        return result as i32;
    }
    d2i_overflow(hi, lo)
}

/// `__d2i` out-of-range path: NaN -> trap descriptor route (0); finite
/// overflow / +/-Inf -> `mvn r0, r1, asr #31; eor r0, r0, #0x80000000`
/// = i32::MAX / i32::MIN by sign.
unsafe fn d2i_overflow(hi: u32, lo: u32) -> i32 {
    if is_nan(hi, lo) {
        return nan_trap(D2I_NAN_DESCRIPTOR) as u32 as i32;
    }
    let sign_extend = !((hi as i32) >> 31) as u32;
    (sign_extend ^ 0x8000_0000) as i32
}

/// __d2u — original: `FUN_083eb880` @ 0x083eb880 (132 bytes).
///
/// double -> u32, truncation toward zero. Positive inputs share the `__d2i`
/// shift path. Negative inputs: |x| < 1.0 (incl. -0.0) returns 0 directly;
/// |x| >= 1.0 (test: `hi + 0x40000000 >= -0x100000` signed) falls into the
/// overflow clamp, which for negative sign is `mvn r0, r1, asr #31` = 0.
/// Overflow/Inf clamps to u32::MAX; NaN -> trap route (0).
#[no_mangle]
pub unsafe extern "C" fn __d2u(x: u64) -> u32 {
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    let top = mantissa_top(hi, lo);
    let exp_sign = (hi as i32) >> 20;

    if exp_sign >= 0 {
        let shift = 0x9e - (exp_sign - 0x380);
        // Unlike __d2i's `ble`, the unsigned version branches on `blt`:
        // shift == 0 is valid (2^31 fits in u32).
        if shift < 0 {
            return d2u_overflow(hi, lo);
        }
        return if shift > 31 { 0 } else { top >> shift };
    }

    // Negative: `add r2, r1, #0x40000000; cmn r2, #0x100000; bge overflow`
    // — |x| < 1.0 truncates to 0 without touching the clamp.
    if (hi.wrapping_add(0x4000_0000) as i32) < -0x10_0000 {
        return 0;
    }
    d2u_overflow(hi, lo)
}

/// `__d2u` out-of-range path: NaN -> trap (0); otherwise `mvn r0, r1,
/// asr #31` — u32::MAX for positive, 0 for negative.
unsafe fn d2u_overflow(hi: u32, lo: u32) -> u32 {
    if is_nan(hi, lo) {
        return nan_trap(D2U_NAN_DESCRIPTOR) as u32;
    }
    !((hi as i32) >> 31) as u32
}

/// Shared core of `__i2d`/`__u2d` (original @ 0x083eb918): clz-normalize
/// the magnitude, exponent base 1055 - clz with the hidden bit's 0x100000
/// folding one more into the field (`add r1, r3, r1, asr #11`) => biased
/// exponent 1054 - clz. Always exact — <= 32 significant bits.
#[inline(always)]
fn u32_to_d(mag: u32, sign: u32) -> u64 {
    if mag == 0 {
        // `bxeq lr` with r0:r1 = 0:0.
        return 0;
    }
    let clz = mag.leading_zeros();
    let norm = mag << clz; // leading 1 at bit 31
    let exponent = 1054 - clz;
    let hi = sign | (exponent << 20) | ((norm >> 11) & 0x000f_ffff);
    let lo = norm << 21;
    ((hi as u64) << 32) | lo as u64
}

/// __i2d — original: `FUN_083eb908` @ 0x083eb908 (48 bytes).
///
/// i32 -> double (exact). Negates first (`ands`/`rsbne`), so i32::MIN's
/// magnitude 0x80000000 converts fine. Returns the raw double bit pattern.
#[no_mangle]
pub unsafe extern "C" fn __i2d(x: i32) -> u64 {
    let sign = (x as u32) & 0x8000_0000;
    let mag = x.unsigned_abs();
    u32_to_d(mag, sign)
}

/// __u2d — original: `FUN_083eb9b4` @ 0x083eb9b4 (12 bytes).
///
/// u32 -> double (exact). Three instructions: sign = +, move value, branch
/// into the `__i2d` core. Returns the raw double bit pattern.
#[no_mangle]
pub unsafe extern "C" fn __u2d(x: u32) -> u64 {
    u32_to_d(x, 0)
}

/// Shared core of `__ll2d`/`__ull2d` (original @ 0x083eb954): normalize the
/// 64-bit magnitude into a 32+32 funnel (hidden bit at bit 31 of the top
/// word), then keep 53 bits and round the residue to nearest-even.
///
/// `base` is the original's r3: 32 when the high word holds the value, 0
/// when only the low word is nonzero (exponent base 1053 + base - clz, the
/// hidden bit's carry makes it 1054 + base - clz).
fn u64_to_d(mag: u64, sign: u32) -> u64 {
    if mag == 0 {
        // `bxeq lr` with r0:r1 = 0:0.
        return 0;
    }
    let hi_word = (mag >> 32) as u32;
    let lo_word = mag as u32;
    let (top, base): (u32, u32) = if hi_word != 0 { (hi_word, 32) } else { (lo_word, 0) };
    let clz = top.leading_zeros();
    let norm_top = top << clz;

    // Funnel the low word in from below: `orr ip, r1, r0, lsr r3` with
    // r3 = base - clz; ARM register LSR >= 32 yields 0.
    let cross_shift = base.wrapping_sub(clz);
    let cross = if cross_shift >= 32 { 0 } else { lo_word >> cross_shift };
    let mant_hi = norm_top | cross; // hidden bit at bit 31
    // Residue low word: `lsl r3, r0, 32 - r3` (shift >= 32 -> 0; note
    // r3 == 0 also yields a shift of 32 here).
    let residue_shift = 32u32.wrapping_sub(cross_shift);
    let residue = if residue_shift >= 32 {
        0
    } else {
        lo_word << residue_shift
    };

    // Round to nearest, ties to even: guard = residue bit 10,
    // sticky = bits 9:0, kept LSB = bit 11. The original derives the carry
    // from `lsls r0, r3, #22` (sticky case) or `(r3 & (r3 >> 1)) >> 11`
    // carry-out (tie case).
    let guard = residue >> 10 & 1;
    let sticky = residue & 0x3ff;
    let kept_lsb = residue >> 11 & 1;
    let round_up = (guard & (kept_lsb | (sticky != 0) as u32)) as u64;

    // Low result word: (residue >> 11) + (mant_hi << 21) + carry, with the
    // carry rippling into the high word (adcs/adc chain). High word: sign +
    // exponent base + (mant_hi >> 11) — the hidden bit's 0x100000 folds the
    // final +1 into the exponent field — plus the low-word carry.
    let low_sum = (residue >> 11) as u64 + ((mant_hi << 21) as u64) + round_up;
    let exponent = (1053 + base - clz) as u64;
    let hi = (sign as u64)
        .wrapping_add(exponent << 20)
        .wrapping_add((mant_hi >> 11) as u64)
        .wrapping_add(low_sum >> 32);
    (hi << 32) | (low_sum as u32 as u64)
}

/// __ll2d — original: `FUN_083eb940` @ 0x083eb940 (116 bytes).
///
/// i64 -> double, round-to-nearest-even. Negates first with 64-bit
/// `rsbs`/`rsc`, so i64::MIN converts exactly to -2^63. Returns the raw
/// double bit pattern.
#[no_mangle]
pub unsafe extern "C" fn __ll2d(x: i64) -> u64 {
    let sign = ((x >> 63) as u32) & 0x8000_0000;
    let mag = x.unsigned_abs();
    u64_to_d(mag, sign)
}

/// __ull2d — original: `FUN_083eb938` @ 0x083eb938 (8 bytes).
///
/// u64 -> double, round-to-nearest-even. Two instructions: sign = +
/// (`mov r2, #0x42000000`), branch into the `__ll2d` core. Returns the raw
/// double bit pattern.
#[no_mangle]
pub unsafe extern "C" fn __ull2d(x: u64) -> u64 {
    u64_to_d(x, 0)
}

/// Full 64-bit mantissa with the hidden bit restored at bit 63:
/// r3 = top word (bits 51:21 + hidden), ip = lo << 11 (bits 20:0 shifted up).
#[inline(always)]
fn mantissa64(hi: u32, lo: u32, exp_nonzero: bool) -> u64 {
    let mut top = (hi << 11) | (lo >> 21);
    if exp_nonzero {
        top |= 0x8000_0000;
    }
    ((top as u64) << 32) | ((lo << 11) as u64)
}

/// Truncating 64-bit right shift of the mantissa; the original clamps the
/// shift at 80 (`movge r2, #80`), past which the result is 0 anyway.
#[inline(always)]
fn shift_mantissa(mant: u64, shift: i32) -> u64 {
    if shift >= 64 {
        0
    } else {
        mant >> shift
    }
}

/// __d2ll — original: `FUN_083ece5c` @ 0x083ece5c (212 bytes).
///
/// double -> i64, truncation toward zero. shift = (1023 + 63) - exp applied
/// to the 64-bit hidden-bit mantissa (r3:ip). Negative path negates with
/// `rsbs`/`rsc`; shift == 0 is allowed only for exactly -2^63 (`teq ip, #0;
/// teqeq r3, #0x80000000`), anything larger overflows. Overflow/Inf clamps
/// to i64::MIN/MAX; NaN -> trap route (0).
#[no_mangle]
pub unsafe extern "C" fn __d2ll(x: u64) -> i64 {
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    let exp_sign = (hi as i32) >> 20;

    if exp_sign >= 0 {
        // shift = 0x3f0 - (exp - 0x4e) = 1086 - exp.
        let shift = 0x3f0 - (exp_sign - 0x4e);
        if shift <= 0 {
            return d2ll_overflow(hi, lo);
        }
        let mant = mantissa64(hi, lo, exp_sign != 0);
        return shift_mantissa(mant, shift) as i64;
    }

    let exp = exp_sign & 0x7ff;
    // Denormal: hidden bit back out (`biceq`); exp==0 also makes the shift
    // huge, so the result is 0 either way.
    let mant = mantissa64(hi, lo, exp != 0);
    let shift = 0x3f0 - (exp - 0x4e);
    if shift < 0 {
        return d2ll_overflow(hi, lo);
    }
    if shift == 0 && mant != 0x8000_0000_0000_0000 {
        // |x| > 2^63 (only -2^63 itself survives the shift==0 case).
        return d2ll_overflow(hi, lo);
    }
    let mag = shift_mantissa(mant, shift);
    (0u64.wrapping_sub(mag)) as i64
}

/// `__d2ll` out-of-range path: NaN -> trap (0); otherwise `mvn r1, r1,
/// asr #31; eor r1, r1, #0x80000000` replicated to both words — i64::MAX /
/// i64::MIN by sign.
unsafe fn d2ll_overflow(hi: u32, lo: u32) -> i64 {
    if is_nan(hi, lo) {
        return nan_trap(D2LL_NAN_DESCRIPTOR) as i64;
    }
    let sign_extend = !((hi as i32) >> 31) as u64;
    (sign_extend ^ 0x8000_0000_0000_0000) as i64
}

/// __d2ull — original: `FUN_083ecf34` @ 0x083ecf34 (148 bytes).
///
/// double -> u64, truncation toward zero. Same shift path as `__d2ll` for
/// non-negative inputs. Negative inputs: |x| < 1.0 (incl. -0.0) returns 0;
/// |x| >= 1.0 falls into the overflow clamp, which for negative sign is
/// `mvn r1, r1, asr #31` = 0. Overflow/+Inf clamps to u64::MAX; NaN ->
/// trap route (0).
#[no_mangle]
pub unsafe extern "C" fn __d2ull(x: u64) -> u64 {
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    let exp_sign = (hi as i32) >> 20;

    if exp_sign >= 0 {
        let shift = 0x3f0 - (exp_sign - 0x4e);
        // Unlike __d2ll's `ble`, the unsigned version branches on `blt`:
        // shift == 0 is valid (2^63 fits in u64).
        if shift < 0 {
            return d2ull_overflow(hi, lo);
        }
        let mant = mantissa64(hi, lo, exp_sign != 0);
        return shift_mantissa(mant, shift);
    }

    if (hi.wrapping_add(0x4000_0000) as i32) < -0x10_0000 {
        return 0;
    }
    d2ull_overflow(hi, lo)
}

/// `__d2ull` out-of-range path: NaN -> trap (0); otherwise `mvn r1, r1,
/// asr #31` to both words — u64::MAX for positive, 0 for negative.
unsafe fn d2ull_overflow(hi: u32, lo: u32) -> u64 {
    if is_nan(hi, lo) {
        return nan_trap(D2ULL_NAN_DESCRIPTOR);
    }
    let word = !((hi as i32) >> 31) as u32;
    ((word as u64) << 32) | word as u64
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    // ---- targeted bit-pattern checks -------------------------------------

    /// Interesting double values: zero, +/-1, fractions, int boundaries,
    /// infinities, NaNs, denormals.
    fn interesting_doubles() -> Vec<f64> {
        let mut v = vec![
            0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 1.5, -1.5, 2.5, 3.5,
            2147483647.0, 2147483648.0, -2147483648.0, -2147483649.0,
            4294967295.0, 4294967296.0,
            9223372036854775807.0, 9223372036854775808.0,
            -9223372036854775808.0, -9223372036854775809.0,
            18446744073709551615.0, 18446744073709551616.0,
            f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -f64::NAN,
            f64::MIN_POSITIVE, 5e-324, // denormal
            0.1, -0.1, 1e10, -1e10, 1e19, -1e19, 1e20, -1e20,
        ];
        // Values straddling the int boundaries.
        v.extend([
            2147483647.999999, 2147483647.9999998, -2147483648.999999,
            9223372036854775807.4999, 9223372036854775806.99999,
        ]);
        v
    }

    fn interesting_i32() -> Vec<i32> {
        vec![0, 1, -1, 2, -2, i32::MAX, i32::MIN, i32::MIN + 1, i32::MAX - 1,
             65536, -65536, 123456789, -123456789]
    }

    fn interesting_i64() -> Vec<i64> {
        vec![0, 1, -1, 2, -2, i64::MAX, i64::MIN, i64::MIN + 1, i64::MAX - 1,
             i32::MAX as i64, i32::MIN as i64, (1i64 << 32) + 1,
             (1i64 << 53) - 1, 1i64 << 53, (1i64 << 53) + 1, (1i64 << 53) + 2,
             -((1i64 << 53) + 1), 1234567890123456789, -1234567890123456789]
    }

    #[test]
    fn d2i_targeted() {
        for f in interesting_doubles() {
            // NaN goes through the global FP_TRAP_HANDLER (see
            // nan_and_inf_behavior); skip it here so a concurrently running
            // fp_scalb trap test (which swaps the handler) can't race us.
            if f.is_nan() {
                continue;
            }
            let bits = f.to_bits();
            let got = unsafe { __d2i(bits) };
            let want = f as i32; // host: saturating, NaN -> 0
            assert_eq!(got, want, "__d2i({f:e} / {bits:#018x})");
        }
    }

    #[test]
    fn d2u_targeted() {
        for f in interesting_doubles() {
            // NaN goes through the global FP_TRAP_HANDLER (see
            // nan_and_inf_behavior); skip it here so a concurrently running
            // fp_scalb trap test (which swaps the handler) can't race us.
            if f.is_nan() {
                continue;
            }
            let bits = f.to_bits();
            let got = unsafe { __d2u(bits) };
            let want = f as u32;
            assert_eq!(got, want, "__d2u({f:e} / {bits:#018x})");
        }
    }

    #[test]
    fn d2ll_targeted() {
        for f in interesting_doubles() {
            // NaN goes through the global FP_TRAP_HANDLER (see
            // nan_and_inf_behavior); skip it here so a concurrently running
            // fp_scalb trap test (which swaps the handler) can't race us.
            if f.is_nan() {
                continue;
            }
            let bits = f.to_bits();
            let got = unsafe { __d2ll(bits) };
            let want = f as i64;
            assert_eq!(got, want, "__d2ll({f:e} / {bits:#018x})");
        }
    }

    #[test]
    fn d2ull_targeted() {
        for f in interesting_doubles() {
            // NaN goes through the global FP_TRAP_HANDLER (see
            // nan_and_inf_behavior); skip it here so a concurrently running
            // fp_scalb trap test (which swaps the handler) can't race us.
            if f.is_nan() {
                continue;
            }
            let bits = f.to_bits();
            let got = unsafe { __d2ull(bits) };
            let want = f as u64;
            assert_eq!(got, want, "__d2ull({f:e} / {bits:#018x})");
        }
    }

    #[test]
    fn i2d_targeted() {
        for x in interesting_i32() {
            let got = unsafe { __i2d(x) };
            let want = (x as f64).to_bits();
            assert_eq!(got, want, "__i2d({x})");
        }
    }

    #[test]
    fn u2d_targeted() {
        for x in [0u32, 1, 2, u32::MAX, u32::MAX - 1, 65536, 123456789, 1 << 31] {
            let got = unsafe { __u2d(x) };
            let want = (x as f64).to_bits();
            assert_eq!(got, want, "__u2d({x})");
        }
    }

    #[test]
    fn ll2d_targeted() {
        for x in interesting_i64() {
            let got = unsafe { __ll2d(x) };
            let want = (x as f64).to_bits();
            assert_eq!(got, want, "__ll2d({x})");
        }
    }

    #[test]
    fn ull2d_targeted() {
        for x in [0u64, 1, 2, u64::MAX, u64::MAX - 1, (1u64 << 53) - 1,
                  1u64 << 53, (1u64 << 53) + 1, 1u64 << 63, (1u64 << 63) + 1,
                  12345678901234567890] {
            let got = unsafe { __ull2d(x) };
            let want = (x as f64).to_bits();
            assert_eq!(got, want, "__ull2d({x})");
        }
    }

    /// Round-to-nearest-EVEN in the 64-bit -> double conversions: 2.5 -> 2,
    /// 3.5 -> 4, and the same at 2^52 scale where ints stop being exact.
    #[test]
    fn ll2d_rounds_to_even() {
        // (2^52 + 1.5-ish): values 2^k + half-ulp patterns around 2^53.
        // At |x| >= 2^53 the double ulp is 2, so odd multiples of 2^k with
        // a half residue must tie-break to an even kept mantissa.
        let scale = 1i64 << 53; // ulp 2 above here
        // 2^53 + 3: nearest doubles are 2^53+2 and 2^53+4; tie? no — 3 is
        // 1.5 ulps... use exact ties: residue == half ulp.
        // ulp = 2 at 2^53: exact tie candidates are odd numbers: 2^53+1
        // sits exactly between 2^53 (even mantissa) and 2^53+2.
        let got = unsafe { __ll2d(scale + 1) };
        assert_eq!(f64::from_bits(got), 9007199254740992.0); // tie -> even (down)
        let got = unsafe { __ll2d(scale + 3) };
        assert_eq!(f64::from_bits(got), 9007199254740996.0); // tie -> even (up)
        let got = unsafe { __ll2d(scale + 2) };
        assert_eq!(f64::from_bits(got), 9007199254740994.0); // exact
        // Negative mirrors.
        let got = unsafe { __ll2d(-(scale + 1)) };
        assert_eq!(f64::from_bits(got), -9007199254740992.0);
        let got = unsafe { __ll2d(-(scale + 3)) };
        assert_eq!(f64::from_bits(got), -9007199254740996.0);
        // u64: u64::MAX = 2^64 - 1 -> rounds up to 2^64.
        let got = unsafe { __ull2d(u64::MAX) };
        assert_eq!(f64::from_bits(got), 18446744073709551616.0);
    }

    /// NaN converts to 0 through the trap-descriptor route; infinities and
    /// finite overflow clamp (documented behavior).
    #[test]
    fn nan_and_inf_behavior() {
        let nan = f64::NAN.to_bits();
        let nnan = (-f64::NAN).to_bits();
        // Also a signaling NaN with payload.
        let snan = 0x7ff4_0000_0000_0001u64;
        // NaN is routed through the global FP_TRAP_HANDLER hook with the
        // decoded default 0; assert against whatever handler is installed
        // (the default returns 0) so a concurrently running fp_scalb trap
        // test swapping the hook can't race this assertion.
        let h = unsafe { crate::fp_scalb::FP_TRAP_HANDLER };
        let e_i = unsafe { h(D2I_NAN_DESCRIPTOR, 0) } as u32 as i32;
        let e_u = unsafe { h(D2U_NAN_DESCRIPTOR, 0) } as u32;
        let e_ll = unsafe { h(D2LL_NAN_DESCRIPTOR, 0) } as i64;
        let e_ull = unsafe { h(D2ULL_NAN_DESCRIPTOR, 0) };
        for n in [nan, nnan, snan] {
            assert_eq!(unsafe { __d2i(n) }, e_i);
            assert_eq!(unsafe { __d2u(n) }, e_u);
            assert_eq!(unsafe { __d2ll(n) }, e_ll);
            assert_eq!(unsafe { __d2ull(n) }, e_ull);
        }
        assert_eq!(unsafe { __d2i(f64::INFINITY.to_bits()) }, i32::MAX);
        assert_eq!(unsafe { __d2i(f64::NEG_INFINITY.to_bits()) }, i32::MIN);
        assert_eq!(unsafe { __d2u(f64::INFINITY.to_bits()) }, u32::MAX);
        assert_eq!(unsafe { __d2u(f64::NEG_INFINITY.to_bits()) }, 0);
        assert_eq!(unsafe { __d2ll(f64::INFINITY.to_bits()) }, i64::MAX);
        assert_eq!(unsafe { __d2ll(f64::NEG_INFINITY.to_bits()) }, i64::MIN);
        assert_eq!(unsafe { __d2ull(f64::INFINITY.to_bits()) }, u64::MAX);
        assert_eq!(unsafe { __d2ull(f64::NEG_INFINITY.to_bits()) }, 0);
    }

    /// -2^31 / -2^63 convert exactly; one past them clamps to the same MIN.
    #[test]
    fn negative_boundaries() {
        assert_eq!(unsafe { __d2i((-2147483648.0f64).to_bits()) }, i32::MIN);
        assert_eq!(unsafe { __d2i((-2147483649.0f64).to_bits()) }, i32::MIN);
        assert_eq!(unsafe { __d2ll((-9223372036854775808.0f64).to_bits()) }, i64::MIN);
        // -(2^63) - 2 (next representable double below -2^63)
        assert_eq!(unsafe { __d2ll((-9223372036854775809.0f64).to_bits()) }, i64::MIN);
    }

    // ---- randomized sweeps vs host oracle --------------------------------

    /// xorshift64* — deterministic, no external deps.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    #[test]
    fn d2int_random_bit_patterns() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        for _ in 0..200_000 {
            let bits = rng.next();
            let f = f64::from_bits(bits);
            if f.is_nan() {
                continue; // trap-handler route; see nan_and_inf_behavior
            }
            assert_eq!(unsafe { __d2i(bits) }, f as i32, "__d2i({bits:#018x})");
            assert_eq!(unsafe { __d2u(bits) }, f as u32, "__d2u({bits:#018x})");
            assert_eq!(unsafe { __d2ll(bits) }, f as i64, "__d2ll({bits:#018x})");
            assert_eq!(unsafe { __d2ull(bits) }, f as u64, "__d2ull({bits:#018x})");
        }
    }

    /// Bias the exponent toward the conversion ranges so the shift paths
    /// (not just clamps) get heavy coverage.
    #[test]
    fn d2int_random_in_range() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        for _ in 0..200_000 {
            let exp = 0x3c0 + (rng.next() % 80) as u32; // ~2^-64 .. 2^80
            let hi = ((rng.next() as u32) & 0x800f_ffff) | (exp << 20);
            let bits = ((hi as u64) << 32) | rng.next();
            let f = f64::from_bits(bits);
            if f.is_nan() {
                continue; // trap-handler route; see nan_and_inf_behavior
            }
            assert_eq!(unsafe { __d2i(bits) }, f as i32, "__d2i({bits:#018x})");
            assert_eq!(unsafe { __d2u(bits) }, f as u32, "__d2u({bits:#018x})");
            assert_eq!(unsafe { __d2ll(bits) }, f as i64, "__d2ll({bits:#018x})");
            assert_eq!(unsafe { __d2ull(bits) }, f as u64, "__d2ull({bits:#018x})");
        }
    }

    #[test]
    fn int2d_random() {
        let mut rng = Rng(0x0f0f_0f0f_5555_aaaa);
        for _ in 0..200_000 {
            let x32 = rng.next() as u32;
            let x64 = rng.next();
            assert_eq!(unsafe { __i2d(x32 as i32) }, ((x32 as i32) as f64).to_bits());
            assert_eq!(unsafe { __u2d(x32) }, (x32 as f64).to_bits());
            assert_eq!(unsafe { __ll2d(x64 as i64) }, ((x64 as i64) as f64).to_bits());
            assert_eq!(unsafe { __ull2d(x64) }, (x64 as f64).to_bits());
        }
    }

    /// Small-magnitude ints stress the low-word-only `__ll2d`/`__ull2d`
    /// branch (base = 0) and small exponents.
    #[test]
    fn int2d_small_magnitudes() {
        let mut rng = Rng(0xabcd_1234_5678_9876);
        for _ in 0..100_000 {
            let x64 = rng.next() % 0x1_0000_0007; // mostly < 2^32
            assert_eq!(unsafe { __ll2d(x64 as i64) }, ((x64 as i64) as f64).to_bits());
            assert_eq!(unsafe { __ull2d(x64) }, (x64 as f64).to_bits());
            let neg = (x64 as i64).wrapping_neg();
            assert_eq!(unsafe { __ll2d(neg) }, (neg as f64).to_bits());
        }
    }
}
