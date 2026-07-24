//! Ports of the ARM ADS 1.0.1 soft-float conversion routines from osos:
//!
//! - `__f2i`  — original: `FUN_083ec898` @ 0x083ec898 (120 bytes): float -> s32
//! - `__f2u`  — original: `FUN_083ec90c` @ 0x083ec90c (92 bytes): float -> u32
//! - `__i2f`  — original: `FUN_083ec96c` @ 0x083ec96c (52 bytes): s32 -> float
//! - `__u2f`  — original: `FUN_083ec9a0` @ 0x083ec9a0 (8 bytes): u32 -> float
//!              (just clears the sign word and tail-branches into `__i2f`)
//! - `__f2ll` — original: `FUN_083ecffc` @ 0x083ecffc (204 bytes): float -> s64
//! - `__d2f`  — original: `FUN_083eae74` @ 0x083eae74 (180 bytes): double -> float
//! - `__f2d`  — original: `FUN_083ec450` @ 0x083ec450 (96 bytes): float -> double
//!
//! retailOS is SOFT-FLOAT: floats are `u32` and doubles `u64` raw IEEE-754
//! bit patterns (a double travels in r1:r0 and is returned in r1:r0, exactly
//! what a by-value `u64` lowers to under the soft-float AAPCS). The module
//! does pure integer bit manipulation — no f32/f64 arithmetic anywhere (it
//! would lower to the unported `__aeabi_d*`/`__aeabi_f*` helpers). Host
//! tests use native `f32::from_bits`/`f64::from_bits` casts as the oracle
//! (round-to-nearest-even, saturating int casts, NaN -> 0).
//!
//! Error/trap behavior: exceptional inputs load an error descriptor into
//! `ip` and branch to a dispatcher (0x083ec5f0 for float results, 0x083eb144
//! for double NaN) feeding the trap decode @ 0x083ed080. All descriptors
//! used here have low nibble 8, which makes the decode return a constant
//! directly (no trap handler, no register dump): bit 6 set -> +0, bit 6
//! clear -> canonical qNaN (float 0x7fc00000 / double 0x7ff80000:0 selected
//! by bit 4). Concretely:
//! - `__f2i`  NaN: descriptor 0x04020048 -> 0
//! - `__f2u`  NaN: descriptor 0x04020068 -> 0
//! - `__f2ll` NaN: descriptor 0x04020078 -> 0
//! - `__f2d`  NaN: descriptor 0x04000018 -> 0x7ff8000000000000 (payload and
//!   sign dropped)
//! - `__d2f`  NaN: descriptor 0x04000088 -> 0x7fc00000 (payload and sign
//!   dropped)
//!
//! Deviations from host IEEE casts (all faithful to the original binary):
//! - `__f2ll` is quirky (verified against the disassembly): any negative
//!   input with |x| >= 1 yields +0 (not the truncated negative value);
//!   positive values in [2^63, 2^64) wrap into negative s64 (mantissa lands
//!   in the high word unchecked); values >= 2^64 and +Inf yield -1
//!   (0xffffffffffffffff), *not* i64::MAX. NaN and |x| < 1 yield 0.
//! - `__d2f` never produces float denormals: results with float exponent
//!   < 1 flush to +0 *before* rounding (host would round to a denormal or
//!   up to the min normal), and the sign is dropped (+0 even for negative
//!   input). Double denormals flush to +0 as well; true ±0 keeps its sign.
//! - `__f2d` flushes float denormals to +0.0 (host converts them exactly);
//!   true ±0 keeps its sign.
//! - `__f2i`/`__f2u`/`__i2f`/`__u2f` match Rust's host cast semantics
//!   exactly: truncation toward zero, saturation on overflow (INT_MAX /
//!   INT_MIN / u32::MAX / 0), NaN -> 0, round-to-nearest-even.

/// ARM register-shift semantics: a logical right shift by >= 32 yields 0.
#[inline(always)]
fn shr_arm(value: u32, shift: u32) -> u32 {
    value.checked_shr(shift).unwrap_or(0)
}

/// __f2i — original: `FUN_083ec898` @ 0x083ec898 (120 bytes).
///
/// float (u32 bits) -> s32, truncation toward zero. The biased exponent
/// becomes the shift count `158 - exp` applied to the mantissa with the
/// hidden bit at bit 31. `exp >= 158` (|x| >= 2^31) takes the error path
/// (descriptor 0x04020048): NaN decodes to +0, everything else saturates to
/// `~(x asr 31) ^ 0x80000000` = INT_MAX / INT_MIN. Matches `f32 as i32`.
#[no_mangle]
pub unsafe extern "C" fn __f2i(x: u32) -> i32 {
    let raw_exp = (x as i32) >> 23; // sign bit rides along, like `asrs r2, r0, #23`
    let mut mantissa = x << 8;
    if raw_exp != 0 {
        mantissa |= 0x8000_0000; // hidden bit
    }
    if raw_exp >= 0 {
        // Positive: exp >= 158 (value >= 2^31) overflows (bls in the original).
        let shift = 158 - raw_exp;
        if shift <= 0 {
            if x << 1 > 0xff00_0000 {
                return 0; // NaN -> +0
            }
            return !(x as i32 >> 31) ^ (0x8000_0000u32 as i32); // INT_MAX
        }
        return shr_arm(mantissa, shift as u32) as i32;
    }
    // Negative: values below -2^31 overflow; -2^31 itself (0xcf000000) converts.
    if x > 0xcf00_0000 {
        if x << 1 > 0xff00_0000 {
            return 0; // NaN -> +0
        }
        return !(x as i32 >> 31) ^ (0x8000_0000u32 as i32); // INT_MIN
    }
    let exp = raw_exp & 0xff;
    if exp == 0 {
        mantissa &= 0x7fff_ffff; // negative denormal: no hidden bit
    }
    let magnitude = shr_arm(mantissa, (158 - exp) as u32);
    (magnitude as i32).wrapping_neg()
}

/// __f2u — original: `FUN_083ec90c` @ 0x083ec90c (92 bytes).
///
/// float (u32 bits) -> u32, truncation toward zero. Same shape as `__f2i`
/// but `exp > 158` overflows (bcc in the original — 2^31..2^32 converts
/// fine), negative inputs with |x| < 1 truncate to +0, and the saturation
/// is `~(x asr 31)`: u32::MAX for positive overflow/+Inf, 0 for negative
/// overflow/-Inf. NaN -> +0 (descriptor 0x04020068). Matches `f32 as u32`.
#[no_mangle]
pub unsafe extern "C" fn __f2u(x: u32) -> u32 {
    let raw_exp = (x as i32) >> 23;
    let mut mantissa = x << 8;
    if raw_exp != 0 {
        mantissa |= 0x8000_0000;
    }
    if raw_exp >= 0 {
        // Positive: exp > 158 (value >= 2^32) overflows.
        let shift = 158 - raw_exp;
        if shift < 0 {
            if x << 1 > 0xff00_0000 {
                return 0; // NaN -> +0
            }
            return !(x as i32 >> 31) as u32; // u32::MAX
        }
        return shr_arm(mantissa, shift as u32);
    }
    // Negative: |x| < 1 truncates to +0, anything larger saturates to 0.
    if x << 1 < 0x7f00_0000 {
        return 0;
    }
    if x << 1 > 0xff00_0000 {
        return 0; // NaN -> +0
    }
    !(x as i32 >> 31) as u32 // 0 for the negative sign
}

/// Shared core of `__i2f`/`__u2f`: normalize `magnitude` with CLZ so the
/// hidden bit sits at bit 31, exponent base (127+31) << 23 minus the
/// leading-zero count, then round to nearest even — the `adc` adds the
/// guard bit (bit 7 before the shift) onto the mantissa truncated with an
/// arithmetic >> 8, and an exact tie (guard set, sticky bits zero) clears
/// the result LSB to make it even.
fn int_to_f32_bits(sign: u32, magnitude: u32) -> u32 {
    let leading = magnitude.leading_zeros();
    let normalized = magnitude.wrapping_shl(leading); // 0 stays 0
    if normalized == 0 {
        return 0; // magnitude == 0 (bxeq lr in the original)
    }
    let biased = (sign | 0x4f80_0000).wrapping_sub(leading << 23);
    let sticky = normalized << 25; // zero exactly on a tie
    let guard = (normalized >> 7) & 1;
    let mut result = biased
        .wrapping_add(((normalized as i32) >> 8) as u32)
        .wrapping_add(guard);
    if sticky == 0 && guard == 1 {
        result &= !1; // tie: round to even
    }
    result
}

/// __i2f — original: `FUN_083ec96c` @ 0x083ec96c (52 bytes).
///
/// s32 -> float (u32 bits), round-to-nearest-even. Negates into a magnitude
/// (wrapping, so INT_MIN works), keeps the sign word, and shares the
/// normalize/round core with `__u2f`. Matches `x as f32`.
#[no_mangle]
pub unsafe extern "C" fn __i2f(x: i32) -> u32 {
    let sign = (x as u32) & 0x8000_0000;
    let magnitude = if sign != 0 {
        (x as u32).wrapping_neg()
    } else {
        x as u32
    };
    int_to_f32_bits(sign, magnitude)
}

/// __u2f — original: `FUN_083ec9a0` @ 0x083ec9a0 (8 bytes).
///
/// u32 -> float (u32 bits). The original is just `mov r2, #0x40000000;
/// b __i2f+12` — a zero sign word plus a tail-branch into the shared core.
/// Matches `x as f32`.
#[no_mangle]
pub unsafe extern "C" fn __u2f(x: u32) -> u32 {
    int_to_f32_bits(0, x)
}

/// __f2ll — original: `FUN_083ecffc` @ 0x083ecffc (204 bytes).
///
/// float (u32 bits) -> s64, truncation toward zero for positive input.
/// Shift count is `190 - exp` (190 = 127+63) applied to the mantissa with
/// the hidden bit at bit 31, split into hi/lo words exactly like the
/// original (`lsr`/`lsl` pair, no 64-bit shifts). Quirks (see module
/// header): negatives with |x| >= 1 -> +0, [2^63, 2^64) wraps negative,
/// >= 2^64 and +Inf -> -1, NaN -> +0 (descriptor 0x04020078).
#[no_mangle]
pub unsafe extern "C" fn __f2ll(x: u32) -> i64 {
    let raw_exp = (x as i32) >> 23;
    let mut mantissa = x << 8;
    if raw_exp != 0 {
        mantissa |= 0x8000_0000;
    }
    if raw_exp >= 0 {
        // Positive: exp > 190 (value >= 2^64) takes the error path.
        let shift = 190 - raw_exp;
        if shift < 0 {
            if x << 1 > 0xff00_0000 {
                return 0; // NaN -> +0
            }
            return -1; // +overflow / +Inf -> all ones (sic — not i64::MAX)
        }
        if shift >= 64 {
            return 0; // |x| < 1, +0, positive denormals
        }
        let (hi, lo) = if shift >= 32 {
            (0, shr_arm(mantissa, (shift - 32) as u32))
        } else {
            (
                shr_arm(mantissa, shift as u32),
                if shift == 0 { 0 } else { mantissa << (32 - shift) },
            )
        };
        // Note: exp == 190 puts the mantissa in the high word unchecked —
        // values in [2^63, 2^64) wrap into negative s64, as in the original.
        return (((hi as u64) << 32) | lo as u64) as i64;
    }
    // Negative: |x| < 1 truncates to +0, anything larger takes the error
    // path, whose saturation `~(x asr 31)` yields +0 for the negative sign.
    if x << 1 < 0x7f00_0000 {
        return 0;
    }
    if x << 1 > 0xff00_0000 {
        return 0; // NaN -> +0
    }
    !((x as i32) >> 31) as i64 // 0 for the negative sign
}

/// __d2f — original: `FUN_083eae74` @ 0x083eae74 (180 bytes).
///
/// double (u64 bits) -> float (u32 bits), round-to-nearest-even on bit 29
/// of the double mantissa (guard = bit 28, sticky = bits 0..28). Exponent
/// rebias is `-(1023-127) << 20` = -0x38000000. Overflow -> ±Inf; results
/// below 2^-126 flush to +0 with no rounding and no sign; NaN -> the
/// canonical positive qNaN 0x7fc00000 (descriptor 0x04000088, payload and
/// sign dropped). Matches `x as f32` for every input whose result is a
/// normal float, ±Inf, or true zero.
#[no_mangle]
pub unsafe extern "C" fn __d2f(x: u64) -> u32 {
    let mut lo = x as u32;
    let hi = (x >> 32) as u32;
    let sign = hi & 0x8000_0000;
    let mag_hi = hi & 0x7fff_ffff;
    // The original spots exp == 0x000 / 0x7ff by XORing the high word with
    // itself shifted left: bits 21..30 of the result vanish exactly when
    // all eleven exponent bits are equal.
    let exponent_transitions = mag_hi ^ (mag_hi << 1);
    if exponent_transitions & 0x7fe0_0000 == 0 {
        if mag_hi & 0x10_0000 == 0 {
            // exp == 0: true zero keeps its sign; denormals flush to +0.
            if lo == 0 && mag_hi == 0 {
                return sign;
            }
            return 0;
        }
        // exp == 0x7ff.
        if lo == 0 && mag_hi & 0xf_ffff == 0 {
            return sign | 0x7f80_0000; // ±Inf
        }
        return 0x7fc0_0000; // NaN -> canonical positive qNaN
    }
    // Normal double: rebias the exponent into float range.
    let mut rebased = mag_hi.wrapping_sub(0x3800_0000);
    if (rebased as i32) < 0x10_0000 {
        return 0; // underflow: flush to +0 — no denormals, sign dropped
    }
    // Round to nearest even: up on guard&(sticky|odd), even on a clean tie.
    let guard = lo & 0x1000_0000 != 0;
    let sticky = lo & 0x0fff_ffff != 0;
    let odd = lo & 0x2000_0000 != 0;
    if guard && (sticky || odd) {
        let (rounded, carry) = lo.overflowing_add(0x2000_0000);
        lo = rounded;
        rebased = rebased.wrapping_add(carry as u32);
    }
    if rebased >= 0x0ff0_0000 {
        return sign | 0x7f80_0000; // overflow -> ±Inf
    }
    sign | (rebased << 3) | (lo >> 29)
}

/// __f2d — original: `FUN_083ec450` @ 0x083ec450 (96 bytes).
///
/// float (u32 bits) -> double (u64 bits), exact for normals: mantissa
/// `lsl #29` into the low word, exponent rebias `+(1023-127) << 20` =
/// +0x38000000 into the high word (the original does it with an
/// arithmetic `asr #3` plus a conditional -0x70000000 for the sign).
/// ±0 keeps its sign; denormals flush to +0.0; ±Inf maps to ±Inf; NaN ->
/// the canonical double qNaN (descriptor 0x04000018, payload and sign
/// dropped).
#[no_mangle]
pub unsafe extern "C" fn __f2d(x: u32) -> u64 {
    // x + 0x800000 increments the exponent field in place; zero in bits
    // 24..30 means the field was 0x00 or 0xff, and bit 23 splits the two.
    let bumped = x.wrapping_add(0x80_0000);
    if bumped & 0x7f00_0000 != 0 {
        // Normal float.
        let hi = (((x >> 3) & 0x0fff_ffff) + 0x3800_0000) | (x & 0x8000_0000);
        return ((hi as u64) << 32) | (x << 29) as u64;
    }
    if bumped & 0x80_0000 != 0 {
        // exp == 0: ±0 keeps its sign; denormals flush to +0.0.
        if x << 1 == 0 {
            return (x as u64) << 32;
        }
        return 0;
    }
    // exp == 0xff.
    if x << 9 != 0 {
        return 0x7ff8_0000_0000_0000; // NaN -> canonical double qNaN
    }
    ((x | 0x70_0000) as u64) << 32 // ±Inf
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// xorshift64 for reproducible pseudo-random bit patterns.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
    }

    const INTERESTING_F32: &[u32] = &[
        0x0000_0000, 0x8000_0000, // ±0
        0x0000_0001, 0x007f_ffff, 0x8000_0001, 0x807f_ffff, // denormals
        0x0080_0000, 0x3f80_0000, 0xbf80_0000, 0x3f00_0000, 0xbf00_0000, // ~1.0
        0x4eff_ffff, 0x4f00_0000, 0xcf00_0000, 0xcf00_0001, // ±2^31 boundary
        0x4f7f_ffff, 0x4f80_0000, // 2^32 boundary
        0x5eff_ffff, 0x5f00_0000, 0x5f7f_ffff, 0x5f80_0000, // 2^63/2^64 boundary
        0x7f7f_ffff, 0xff7f_ffff, // ±max
        0x7f80_0000, 0xff80_0000, // ±Inf
        0x7fc0_0000, 0xffc0_0000, 0x7f80_0001, 0x7fff_ffff, // NaNs
    ];

    #[test]
    fn f2i_matches_host() {
        for &x in INTERESTING_F32 {
            assert_eq!(unsafe { __f2i(x) }, f32::from_bits(x) as i32, "x={x:#010x}");
        }
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..300_000 {
            let x = rng.next_u32();
            assert_eq!(unsafe { __f2i(x) }, f32::from_bits(x) as i32, "x={x:#010x}");
        }
    }

    #[test]
    fn f2u_matches_host() {
        for &x in INTERESTING_F32 {
            assert_eq!(unsafe { __f2u(x) }, f32::from_bits(x) as u32, "x={x:#010x}");
        }
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for _ in 0..300_000 {
            let x = rng.next_u32();
            assert_eq!(unsafe { __f2u(x) }, f32::from_bits(x) as u32, "x={x:#010x}");
        }
    }

    /// `__f2ll` agrees with the host only for positive values below 2^63
    /// and for fractions in (-1, 0]; everything else is original-specific
    /// and covered by f2ll_quirks below.
    fn f2ll_host_agrees(x: u32) -> bool {
        if x as i32 >= 0 {
            x < 0x5f00_0000 // positive, value < 2^63 (excludes Inf/NaN)
        } else {
            (x << 1) < 0x7f00_0000 // -1 < x <= 0
        }
    }

    #[test]
    fn f2ll_matches_host_where_defined() {
        let mut rng = Rng(0x6a09_e667_f3bc_c909);
        for &x in INTERESTING_F32 {
            if f2ll_host_agrees(x) {
                assert_eq!(unsafe { __f2ll(x) }, f32::from_bits(x) as i64, "x={x:#010x}");
            }
        }
        for _ in 0..300_000 {
            let x = rng.next_u32();
            if f2ll_host_agrees(x) {
                assert_eq!(unsafe { __f2ll(x) }, f32::from_bits(x) as i64, "x={x:#010x}");
            }
        }
    }

    #[test]
    fn f2ll_quirks() {
        // Negatives with |x| >= 1 yield +0 (host would truncate negative).
        assert_eq!(unsafe { __f2ll(0xbf80_0000) }, 0); // -1.0
        assert_eq!(unsafe { __f2ll(0xcf00_0000) }, 0); // -2^31
        assert_eq!(unsafe { __f2ll(0xdf7f_ffff) }, 0); // large negative
        assert_eq!(unsafe { __f2ll(0xff80_0000) }, 0); // -Inf
        // [2^63, 2^64) wraps into the sign bit (host: i64::MAX).
        assert_eq!(unsafe { __f2ll(0x5f00_0000) }, i64::MIN); // 2^63
        assert_eq!(unsafe { __f2ll(0x5f7f_ffff) }, 0xffff_ff00_0000_0000u64 as i64);
        // >= 2^64 and +Inf yield all ones (host: i64::MAX).
        assert_eq!(unsafe { __f2ll(0x5f80_0000) }, -1); // 2^64
        assert_eq!(unsafe { __f2ll(0x7f80_0000) }, -1); // +Inf
        // NaN -> +0 (same as the host).
        assert_eq!(unsafe { __f2ll(0x7fc0_0000) }, 0);
        assert_eq!(unsafe { __f2ll(0xffc0_0000) }, 0);
        // Just under 2^63 still converts exactly.
        assert_eq!(unsafe { __f2ll(0x5eff_ffff) }, 0x7fff_ff80_0000_0000u64 as i64);
    }

    #[test]
    fn i2f_matches_host() {
        let interesting: &[i32] = &[
            0, 1, -1, 2, -2, i32::MAX, i32::MIN,
            (1 << 24) - 1, 1 << 24, (1 << 24) + 1, (1 << 24) + 2, (1 << 24) + 3,
            -((1 << 24) - 1), -(1 << 24), -((1 << 24) + 1), -((1 << 24) + 3),
            0x0fff_ffff, 0x1000_0001, 0x5555_5555, -0x5555_5555, 0x0000_ffff,
        ];
        for &x in interesting {
            assert_eq!(unsafe { __i2f(x) }, (x as f32).to_bits(), "x={x}");
        }
        let mut rng = Rng(0xbb67_ae85_84ca_a73b);
        for _ in 0..300_000 {
            let x = rng.next_u32() as i32;
            assert_eq!(unsafe { __i2f(x) }, (x as f32).to_bits(), "x={x}");
        }
    }

    #[test]
    fn u2f_matches_host() {
        let interesting: &[u32] = &[
            0, 1, 2, u32::MAX,
            (1 << 24) - 1, 1 << 24, (1 << 24) + 1, (1 << 24) + 2, (1 << 24) + 3,
            0x0fff_ffff, 0x1000_0001, 0x5555_5555, 0xffff_ffff, 0x8000_0000,
        ];
        for &x in interesting {
            assert_eq!(unsafe { __u2f(x) }, (x as f32).to_bits(), "x={x}");
        }
        let mut rng = Rng(0x3c6e_f372_fe94_f82b);
        for _ in 0..300_000 {
            let x = rng.next_u32();
            assert_eq!(unsafe { __u2f(x) }, (x as f32).to_bits(), "x={x}");
        }
    }

    /// Host oracle for `__d2f`: only defined where the original does not
    /// deviate — NaN (payload dropped) and the underflow region below
    /// 2^-126 (flushed to +0 before rounding) are covered separately.
    fn d2f_host(x: u64) -> Option<u32> {
        let d = f64::from_bits(x);
        if d.is_nan() {
            return None;
        }
        let mag_hi = ((x >> 32) as u32) & 0x7fff_ffff;
        if mag_hi < 0x3810_0000 {
            return None; // original flushes this whole range to +0
        }
        Some((d as f32).to_bits())
    }

    #[test]
    fn d2f_matches_host_for_normal_results() {
        let interesting: &[u64] = &[
            0x0000_0000_0000_0000, 0x8000_0000_0000_0000, // ±0
            0x3ff0_0000_0000_0000, 0xbff0_0000_0000_0000, // ±1
            0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000, // ±Inf
            0x7fef_ffff_ffff_ffff, 0xffef_ffff_ffff_ffff, // ±max -> ±Inf
            0x47ef_ffff_ffff_ffff, 0x47e0_0000_0000_0000, // near float max
            0x3ff0_0000_1000_0000, 0x3ff0_0000_3000_0000, // rounding ties
            0x3fef_ffff_f000_0000, 0x3fef_ffff_d000_0000,
            0x3810_0000_0000_0000, 0x3810_0000_0000_0001, // min normal float
        ];
        for &x in interesting {
            if let Some(want) = d2f_host(x) {
                assert_eq!(unsafe { __d2f(x) }, want, "x={x:#018x}");
            }
        }
        let mut rng = Rng(0x510e_527f_ade6_82d1);
        for _ in 0..300_000 {
            let x = rng.next_u64();
            if let Some(want) = d2f_host(x) {
                assert_eq!(unsafe { __d2f(x) }, want, "x={x:#018x}");
            }
        }
    }

    #[test]
    fn d2f_special_cases() {
        // Underflow flushes to +0 before rounding: host rounds this to the
        // min normal float 0x00800000, the original yields +0.
        assert_eq!(unsafe { __d2f(0x380f_ffff_ffff_ffff) }, 0);
        assert_eq!(unsafe { __d2f(0xb80f_ffff_ffff_ffff) }, 0); // sign dropped
        // Double denormals flush to +0 (host would give ±0 — sign dropped).
        assert_eq!(unsafe { __d2f(0x000f_ffff_ffff_ffff) }, 0);
        assert_eq!(unsafe { __d2f(0x8000_0000_0000_0001) }, 0);
        // True zeros keep their sign.
        assert_eq!(unsafe { __d2f(0) }, 0);
        assert_eq!(unsafe { __d2f(0x8000_0000_0000_0000) }, 0x8000_0000);
        // NaN -> canonical positive qNaN; payload and sign dropped.
        assert_eq!(unsafe { __d2f(0x7ff8_0000_0000_0001) }, 0x7fc0_0000);
        assert_eq!(unsafe { __d2f(0xfff4_0000_0000_0000) }, 0x7fc0_0000);
        assert_eq!(unsafe { __d2f(0x7ff4_0000_0000_0000) }, 0x7fc0_0000); // sNaN
        // Round-to-nearest-even ties on the float mantissa LSB.
        assert_eq!(unsafe { __d2f(0x3ff0_0000_1000_0000) }, 0x3f80_0000); // 1+2^-24 -> down
        assert_eq!(unsafe { __d2f(0x3ff0_0000_3000_0000) }, 0x3f80_0002); // 1+3*2^-24 -> up
        assert_eq!(unsafe { __d2f(0x3fef_ffff_f000_0000) }, 0x3f80_0000); // 1-2^-25 -> up (carry)
        assert_eq!(unsafe { __d2f(0x3fef_ffff_d000_0000) }, 0x3f7f_fffe); // 1-3*2^-25 -> down
        // Just below a tie rounds down, just above rounds up.
        assert_eq!(unsafe { __d2f(0x3ff0_0000_0800_0000) }, 0x3f80_0000); // 1+2^-25
        assert_eq!(unsafe { __d2f(0x3ff0_0000_1800_0000) }, 0x3f80_0001); // 1+2^-24+2^-25
    }

    /// Host oracle for `__f2d`: defined for normals, zeros and infinities;
    /// denormals (flushed) and NaNs (payload dropped) are covered separately.
    fn f2d_host(x: u32) -> Option<u64> {
        let exp = (x >> 23) & 0xff;
        if exp == 0 && x << 1 != 0 {
            return None; // denormal: original flushes to +0.0
        }
        let f = f32::from_bits(x);
        if f.is_nan() {
            return None;
        }
        Some(f64::from(f).to_bits())
    }

    #[test]
    fn f2d_matches_host_for_normals() {
        let interesting: &[u32] = &[
            0x0000_0000, 0x8000_0000, // ±0
            0x0080_0000, 0x8080_0000, // min normal
            0x3f80_0000, 0xbf80_0000, 0x3fc0_0001, 0xc040_0001, // normals
            0x7f7f_ffff, 0xff7f_ffff, // ±max
            0x7f80_0000, 0xff80_0000, // ±Inf
        ];
        for &x in interesting {
            if let Some(want) = f2d_host(x) {
                assert_eq!(unsafe { __f2d(x) }, want, "x={x:#010x}");
            }
        }
        let mut rng = Rng(0x1f83_d9ab_fb41_bd6b);
        for _ in 0..300_000 {
            let x = rng.next_u32();
            if let Some(want) = f2d_host(x) {
                assert_eq!(unsafe { __f2d(x) }, want, "x={x:#010x}");
            }
        }
    }

    #[test]
    fn f2d_special_cases() {
        // Denormals flush to +0.0 (host converts them exactly — deviation).
        assert_eq!(unsafe { __f2d(0x0000_0001) }, 0);
        assert_eq!(unsafe { __f2d(0x007f_ffff) }, 0);
        assert_eq!(unsafe { __f2d(0x8000_0001) }, 0); // sign dropped
        assert_eq!(unsafe { __f2d(0x807f_ffff) }, 0);
        // NaN -> canonical positive double qNaN; payload and sign dropped.
        assert_eq!(unsafe { __f2d(0x7fc0_0001) }, 0x7ff8_0000_0000_0000);
        assert_eq!(unsafe { __f2d(0x7fa0_0000) }, 0x7ff8_0000_0000_0000); // sNaN
        assert_eq!(unsafe { __f2d(0xffc0_0000) }, 0x7ff8_0000_0000_0000);
        // Zeros and infinities.
        assert_eq!(unsafe { __f2d(0x8000_0000) }, 0x8000_0000_0000_0000);
        assert_eq!(unsafe { __f2d(0xff80_0000) }, 0xfff0_0000_0000_0000);
        // Spot-check exact conversions.
        assert_eq!(unsafe { __f2d(0x3f80_0000) }, 0x3ff0_0000_0000_0000); // 1.0
        assert_eq!(unsafe { __f2d(0xbf80_0000) }, 0xbff0_0000_0000_0000); // -1.0
    }
}
