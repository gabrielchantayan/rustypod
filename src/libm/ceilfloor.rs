//! Ports of the retailOS ceil/floor family — the classic fdlibm s_ceil.c /
//! s_floor.c bit-mask round, plus the float variant of ceil.
//!
//! Originals (retailOS osos, load base 0x08000000):
//!   ceil  @ 0x080317c4 (304 B) — double, rounds UP for positives
//!   ceilf @ 0x08031914 (136 B) — float
//!   floor @ 0x08031ab8 (312 B) — double, rounds DOWN for negatives
//!
//! Algorithm (all three share one shape): split the sign-magnitude bit
//! pattern, compute the unbiased exponent `e`, and:
//!   * `e >= 52` (double) / `e >= 23` (float): already integral — this also
//!     covers ±Inf and NaN (biased exponent all-ones), returned UNCHANGED.
//!   * `e < 0` (`|x| < 1`): negative (incl. -0 and negative denormals) ->
//!     -0.0 (ceil) / -1.0 (floor); +0 -> +0; positive -> +1.0 (ceil) /
//!     +0.0 (floor).
//!   * otherwise: mask off the fractional mantissa bits (high word when
//!     `e < 20`, low word otherwise); if any were set and the value has the
//!     sign that rounds away from zero, add one integer-LSB first (carry
//!     into the exponent field is the correct normalization).
//!
//! SIMPLIFICATION: each original body calls __dadd/__drsb with a huge
//! constant (~2^996, 0x7E37E43C8800759C — fdlibm's `huge+x` inexact-flag
//! trick) and then __dcmpgt against +0.0, returning `x` unchanged when the
//! sum is not > 0. For every input that can actually reach those paths the
//! sum is a finite positive ~2^996 (NaN/Inf have `e >= 52`/`e >= 23` and
//! exit earlier), so the branch is never taken: the calls exist only to
//! raise the ADS inexact flag, which retailOS has stubbed out
//! (__ieee_status always returns 0). They are result-dead and are dropped
//! here — that is why the committed fp_dadd/fp_compare ports are not
//! needed. `tools/match.py` therefore reports the missing `bl` sequences;
//! everything else tracks the original instruction-for-instruction.
//!
//! NaN behavior: any NaN is returned BIT-IDENTICAL (payload and sign
//! preserved, no canonicalization), because the `e >= max` early exit
//! catches it before any fplib call. This matches IEEE ceil/floor up to
//! payload preservation, which the host f64::ceil/f32::ceil oracle also
//! exhibits on aarch64.
//!
//! Doubles are u64 and floats are u32 IEEE bit patterns (soft-float
//! convention); pure integer bit manipulation only — no f32/f64 arithmetic,
//! no 64-bit division.

/// Sign mask shared by both widths.
const D_SIGN: u64 = 1 << 63;

/// +1.0 / -1.0 / -0.0 double bit patterns returned for |x| < 1.
const D_ONE: u64 = 0x3FF0_0000_0000_0000;
const D_NEG_ONE: u64 = 0xBFF0_0000_0000_0000;
const D_NEG_ZERO: u64 = D_SIGN;

/// ceil — original: `FUN_080317c4` @ 0x080317c4 (304 bytes).
///
/// Smallest integral value not less than `x`, per the original's
/// bit-manipulation algorithm (see module header). NaN is returned
/// bit-identical; ±Inf and |x| >= 2^52 pass through unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ceil(x: u64) -> u64 {
    let mut hi = (x >> 32) as u32;
    let mut lo = x as u32;
    // Unbiased exponent; the sign bit is shifted out by the <<1.
    let exp = ((hi << 1) >> 21) as i32 - 1023;

    if exp >= 52 {
        return x; // integral, ±Inf, or NaN
    }
    if exp < 0 {
        // |x| < 1.
        if (hi as i32) < 0 {
            return D_NEG_ZERO; // negatives, -0.0, negative denormals
        }
        if x == 0 {
            return x; // +0.0
        }
        return D_ONE;
    }
    if exp < 20 {
        // Fractional bits live in the high word (plus all of the low word).
        let mask = 0x000F_FFFFu32 >> exp;
        if (hi & mask) == 0 && lo == 0 {
            return x; // already integral
        }
        if (hi as i32) > 0 {
            hi = hi.wrapping_add(0x0010_0000u32 >> exp); // round up
        }
        hi &= !mask;
        return (hi as u64) << 32;
    }
    // 20 <= exp < 52: fractional bits live in the low word only.
    let mask = 0xFFFF_FFFFu32 >> (exp - 20);
    if (lo & mask) == 0 {
        return x; // already integral
    }
    if (hi as i32) > 0 {
        // Add one integer-LSB, carrying from the low word into the high.
        if exp == 20 {
            hi = hi.wrapping_add(1);
        } else {
            let (sum, carry) = lo.overflowing_add(1u32 << (52 - exp));
            lo = sum;
            if carry {
                hi = hi.wrapping_add(1);
            }
        }
    }
    lo &= !mask;
    ((hi as u64) << 32) | (lo as u64)
}

/// floor — original: `FUN_08031ab8` @ 0x08031ab8 (312 bytes).
///
/// Largest integral value not greater than `x`. Same shape as `ceil` with
/// the adjustment applied to negatives instead of positives.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn floor(x: u64) -> u64 {
    let mut hi = (x >> 32) as u32;
    let mut lo = x as u32;
    let exp = ((hi << 1) >> 21) as i32 - 1023;

    if exp >= 52 {
        return x; // integral, ±Inf, or NaN
    }
    if exp < 0 {
        // |x| < 1.
        if (hi as i32) >= 0 {
            return 0; // positives and +0.0 -> +0.0
        }
        if (x << 1) == 0 {
            return x; // -0.0
        }
        return D_NEG_ONE;
    }
    if exp < 20 {
        let mask = 0x000F_FFFFu32 >> exp;
        if (hi & mask) == 0 && lo == 0 {
            return x;
        }
        if (hi as i32) < 0 {
            hi = hi.wrapping_add(0x0010_0000u32 >> exp); // round down
        }
        hi &= !mask;
        return (hi as u64) << 32;
    }
    let mask = 0xFFFF_FFFFu32 >> (exp - 20);
    if (lo & mask) == 0 {
        return x;
    }
    if (hi as i32) < 0 {
        if exp == 20 {
            hi = hi.wrapping_add(1);
        } else {
            let (sum, carry) = lo.overflowing_add(1u32 << (52 - exp));
            lo = sum;
            if carry {
                hi = hi.wrapping_add(1);
            }
        }
    }
    lo &= !mask;
    ((hi as u64) << 32) | (lo as u64)
}

/// ceilf — original: `FUN_08031914` @ 0x08031914 (136 bytes).
///
/// Single-precision `ceil`: float bit pattern in, float bit pattern out.
/// NaN is returned bit-identical; ±Inf and |x| >= 2^23 pass through.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ceilf(x: u32) -> u32 {
    let mut bits = x;
    let exp = ((x << 1) >> 24) as i32 - 127;

    if exp >= 23 {
        return x; // integral, ±Inf, or NaN
    }
    if exp < 0 {
        // |x| < 1.
        if (x as i32) < 0 {
            return 0x8000_0000; // -0.0
        }
        if x != 0 {
            bits = 0x3F80_0000; // +1.0
        }
        return bits; // +0.0 stays +0.0
    }
    let mask = 0x007F_FFFFu32 >> exp;
    if (bits & mask) == 0 {
        return x; // already integral
    }
    if (bits as i32) > 0 {
        bits = bits.wrapping_add(0x0080_0000u32 >> exp); // round up
    }
    bits & !mask
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    // ---- directed double cases ------------------------------------------

    #[test]
    fn ceil_directed() {
        let cases: &[(f64, f64)] = &[
            (0.0, 0.0),
            (-0.0, -0.0),
            (0.5, 1.0),
            (-0.5, -0.0),
            (1.5, 2.0),
            (-1.5, -1.0),
            (1.0, 1.0),
            (-1.0, -1.0),
            (2.0, 2.0),
            (0.1, 1.0),
            (-0.1, -0.0),
            // Around the 2^20 hi/lo-word split.
            (1048575.5, 1048576.0),
            (-1048575.5, -1048575.0),
            (1048576.0000000002, 1048577.0),
            // Around 2^52: ulp = 1 here, ulp = 0.5 just below.
            (4503599627370496.0, 4503599627370496.0), // 2^52
            (-4503599627370496.0, -4503599627370496.0),
            (4503599627370495.5, 4503599627370496.0), // 2^52 - 0.5
            (-4503599627370495.5, -4503599627370495.0),
            (1.0e300, 1.0e300),
            (-1.0e300, -1.0e300),
            (f64::INFINITY, f64::INFINITY),
            (f64::NEG_INFINITY, f64::NEG_INFINITY),
            // Denormals: +tiny -> +1.0, -tiny -> -0.0.
            (f64::from_bits(1), 1.0),
            (f64::from_bits(1 << 63), -0.0),
            (f64::from_bits((1u64 << 52) - 1), 1.0),
        ];
        for &(input, want) in cases {
            let got = unsafe { ceil(input.to_bits()) };
            assert_eq!(
                got,
                want.to_bits(),
                "ceil({input:e}) bits {got:#x} != {:#x}",
                want.to_bits()
            );
        }
    }

    #[test]
    fn floor_directed() {
        let cases: &[(f64, f64)] = &[
            (0.0, 0.0),
            (-0.0, -0.0),
            (0.5, 0.0),
            (-0.5, -1.0),
            (1.5, 1.0),
            (-1.5, -2.0),
            (1.0, 1.0),
            (-1.0, -1.0),
            (0.1, 0.0),
            (-0.1, -1.0),
            (1048575.5, 1048575.0),
            (-1048575.5, -1048576.0),
            (4503599627370496.0, 4503599627370496.0),
            (-4503599627370496.0, -4503599627370496.0),
            (4503599627370495.5, 4503599627370495.0),
            (-4503599627370495.5, -4503599627370496.0),
            (1.0e300, 1.0e300),
            (f64::INFINITY, f64::INFINITY),
            (f64::NEG_INFINITY, f64::NEG_INFINITY),
            (f64::from_bits(1), 0.0),
            (f64::from_bits((1 << 63) | 1), -1.0), // negative denormal
        ];
        for &(input, want) in cases {
            let got = unsafe { floor(input.to_bits()) };
            assert_eq!(
                got,
                want.to_bits(),
                "floor({input:e}) bits {got:#x} != {:#x}",
                want.to_bits()
            );
        }
    }

    #[test]
    fn ceilf_directed() {
        let cases: &[(f32, f32)] = &[
            (0.0, 0.0),
            (-0.0, -0.0),
            (0.5, 1.0),
            (-0.5, -0.0),
            (1.5, 2.0),
            (-1.5, -1.0),
            (0.1, 1.0),
            (-0.1, -0.0),
            (8388607.5, 8388608.0),  // 2^23 - 0.5
            (-8388607.5, -8388607.0),
            (8388608.0, 8388608.0),  // 2^23
            (1.0e30, 1.0e30),
            (f32::INFINITY, f32::INFINITY),
            (f32::NEG_INFINITY, f32::NEG_INFINITY),
            (f32::from_bits(1), 1.0),          // +denormal
            (f32::from_bits(1 << 31), -0.0),   // -denormal
        ];
        for &(input, want) in cases {
            let got = unsafe { ceilf(input.to_bits()) };
            assert_eq!(
                got,
                want.to_bits(),
                "ceilf({input:e}) bits {got:#x} != {:#x}",
                want.to_bits()
            );
        }
    }

    // ---- NaN: returned bit-identical (documented behavior) ---------------

    #[test]
    fn nan_passes_through_bit_identical() {
        let dnans = [
            f64::NAN.to_bits(),
            0x7FF0_0000_0000_0001,                 // signaling
            0xFFF8_0000_0000_0000,                 // negative quiet
            0x7FF7_FFFF_FFFF_FFFF,                 // payload, quiet bit clear
        ];
        for &n in &dnans {
            assert_eq!(unsafe { ceil(n) }, n, "ceil NaN {n:#x}");
            assert_eq!(unsafe { floor(n) }, n, "floor NaN {n:#x}");
        }
        let fnans = [
            f32::NAN.to_bits(),
            0x7F80_0001,
            0xFFC0_0000,
            0x7FBF_FFFF,
        ];
        for &n in &fnans {
            assert_eq!(unsafe { ceilf(n) }, n, "ceilf NaN {n:#x}");
        }
    }

    // ---- randomized sweeps against the host oracle ------------------------

    #[test]
    fn ceil_floor_sweep_matches_host() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut pool: Vec<u64> = std::vec![
            0,
            1 << 63,
            1.0f64.to_bits(),
            (-1.0f64).to_bits(),
            0x432F_FFFF_FFFF_FFFF, // 2^52 - 0.5
            0x4330_0000_0000_0000, // 2^52
            0xC32F_FFFF_FFFF_FFFF,
            0x412F_FFFF_FFFF_FFFF, // just under 2^20
            0x7FEF_FFFF_FFFF_FFFF, // max finite
            1,
            1 << 63 | 1,
        ];
        for _ in 0..20000 {
            let r = next();
            // Bias half the samples into the "interesting" exponent range
            // [-2^60, 2^60] where rounding actually does something.
            pool.push(if r & 1 == 0 {
                r
            } else {
                let exp = 1023 + ((r >> 1) % 70) as u64; // e in [0, 69]
                (r & 0x800F_FFFF_FFFF_FFFF) | (exp << 52)
            });
        }
        for &bits in &pool {
            let v = f64::from_bits(bits);
            if v.is_nan() {
                // Documented: NaN passes through bit-identical.
                assert_eq!(unsafe { ceil(bits) }, bits, "ceil NaN {bits:#x}");
                assert_eq!(unsafe { floor(bits) }, bits, "floor NaN {bits:#x}");
            } else {
                assert_eq!(
                    unsafe { ceil(bits) },
                    v.ceil().to_bits(),
                    "ceil({v:e}) bits {bits:#x}"
                );
                assert_eq!(
                    unsafe { floor(bits) },
                    v.floor().to_bits(),
                    "floor({v:e}) bits {bits:#x}"
                );
            }
        }
    }

    #[test]
    fn ceilf_sweep_matches_host() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut pool: Vec<u32> = std::vec![
            0,
            1 << 31,
            1.0f32.to_bits(),
            (-1.0f32).to_bits(),
            0x4AFF_FFFF, // 2^23 - 0.5
            0x4B00_0000, // 2^23
            0xCAFF_FFFF,
            1,
            1 << 31 | 1,
        ];
        for _ in 0..40000 {
            let r = next() as u32;
            pool.push(if r & 1 == 0 {
                r
            } else {
                let exp = 127 + ((r >> 1) % 40); // e in [0, 39]
                (r & 0x807F_FFFF) | (exp << 23)
            });
        }
        for &bits in &pool {
            let v = f32::from_bits(bits);
            if v.is_nan() {
                assert_eq!(unsafe { ceilf(bits) }, bits, "ceilf NaN {bits:#x}");
            } else {
                assert_eq!(
                    unsafe { ceilf(bits) },
                    v.ceil().to_bits(),
                    "ceilf({v:e}) bits {bits:#x}"
                );
            }
        }
    }
}
