//! Port of `__kernel_rem_pio2` — original: `FUN_080338f4` @ 0x080338f4
//! (code ends 0x08033da4, literal pool to 0x08033dc8; pio2 hi/lo table @
//! 0x089860d8-0x08986108, huge-arg scale table @ 0x08986048-0x089860d8).
//!
//! Payne-Hanek-lite argument reduction x = y + n*pi/2 for the trig
//! kernels. retailOS is SOFT-FLOAT: `x` and `y[i]` travel as u64 bit
//! patterns; the return value is the quadrant count n. The original
//! farms the arithmetic out to the ADS soft-float helpers (__dadd
//! 0x083eaf2c, __dsub 0x083ec09c, __drsb 0x083ebed8, __dmul 0x083eba48,
//! __ddiv 0x083eb238, __d2i 0x083eb7d0, __i2d 0x083eb908, __dscalb
//! 0x083ed0dc) plus three calls to the remainder core __dmod @
//! 0x083ebc48 (already ported in crate::fp_misc — despite the name it is
//! IEEE 754 remainder(), NOT fmod). The helper calls are re-implemented
//! here as local round-to-nearest-even integer routines so this module
//! stays self-contained; only __dmod is imported.
//!
//! Four paths, on ix = high word of x with the sign bit cleared:
//!
//! - ix <= 0x3fe921fb (|x| <= ~pi/4): y[0] = x, n = 0.
//! - ix < 0x4002d97c (|x| < 3pi/4): n = +-1, y[0] = x -+ pio2_hi -
//!   pio2_lo; when |x| shares pi/2's high word (ix == 0x3ff921fb) the
//!   extended 3-term form (pio2_hi + pio2_2_hi + pio2_2_lo) is used.
//! - ix <= 0x413921fb (|x| <= 2^20*pi/2): n = (int)(|x|*(2/pi) + 0.5),
//!   r = |x| - n*pio2_hi, y[0] = r - n*pio2_lo, then up to two
//!   refinement passes with the pio2_2/pio2_3 hi/lo pairs while the
//!   exponent gap (ix>>20) - exp(y0) exceeds 33*i - 17. For negative x
//!   the result signs are flipped: y[0] = -y[0], y[1] = -0.0, n = -n.
//! - larger |x| (the "huge" path): a double-double hi+lo ~= x*K is
//!   formed with K = 0.42604189937999454 (split as C1 + C2; the v/w
//!   argument split makes all four products exact), then reduced via
//!   three __dmod calls: n = (int)(scalbn(rem(hi, K*2pi)/(K*2pi), 3) +
//!   9.0) >> 1 and y[0] = rem(rem(hi, K*pi/2) + lo, K*pi/2) / K. Since
//!   C3 = K*2pi and C4 = K*pi/2 hold to the last bit, the K cancels and
//!   y is x reduced mod pi/2; n comes out in [2, 6] and is only
//!   congruent to the true quadrant mod 4 (all trig callers need). For
//!   |x| >= 2^106 the argument is first scaled by
//!   HUGE_SCALE[(exp - 1129)/54].
//!
//! Constant provenance (all extracted from osos.dec):
//! - pio2_hi/lo, pio2_2_hi/lo, pio2_3_hi/lo @ 0x089860d8..0x08986108 —
//!   the textbook Sun fdlibm values (pio2_hi has the low word truncated
//!   to 0x54400000 so n*pio2_hi is exact for |n| < 2^20).
//! - 2/pi and 0.5 @ 0x08033cc4/0x08033ccc; K split C1/C2 @
//!   0x08033cdc/0x08033ce4 (C1+C2 == C5 to the last bit); K*2pi, 9.0,
//!   K*pi/2, K @ 0x08033da8/0x08033db0/0x08033db8/0x08033dc0
//!   (4*C4 == C3 and C4/C5 == pi/2 to the last bit).
//! - HUGE_SCALE[18] @ 0x08986048 — embedded verbatim. NOTE: the entries
//!   are NOT powers of two (entries 2, 5, 7 and 9 are negative), so for
//!   |x| >= 2^106 the original's result is deterministic but not a
//!   meaningful reduction; it is reproduced bug-for-bug. The intended
//!   mathematical identity of K itself is unclear (see above); the
//!   reduction is valid for any nonzero K, so this does not affect
//!   arguments below 2^106.
//!
//! Deviations from the original, all in the local soft-float helpers:
//! - Denormal inputs and would-be-denormal results flush to signed zero
//!   (mirrors the ADS flush-to-zero behavior documented in fp_misc);
//!   gradual underflow is not produced.
//! - Inf/NaN propagation is minimal IEEE-ish (canonical quiet NaN); the
//!   original routes special cases through __rt_raise exception stubs,
//!   so NaN payloads and any raised-condition side effects differ.
//! - The local d_div returns +-Inf on x/0 instead of raising SIGFPE.
//! - y[1] is always +-0.0, as in the original (the ADS kernel only
//!   delivers single-double precision).
//!
//! Behavioral verification: host-side `cargo test` compares the whole
//! function bit-for-bit against an f64 step-by-step simulation of the
//! original algorithm (host f64 ops and libm remainder() are exact RNE
//! oracles) on directed boundaries plus random sweeps of every path,
//! checks the reduction identity x ~= y + n*pi/2 (mod 2pi) with y in
//! [-pi/4, pi/4], and stress-tests the local helpers against host
//! f64 arithmetic. `tools/match.py` (ipod-decomp) reports the
//! mnemonic-level diff against the original machine code.

use crate::fp_misc::__dmod;

const SIGN: u64 = 0x8000_0000_0000_0000;
const HIDDEN: u64 = 0x0010_0000_0000_0000;
const FRAC: u64 = 0x000f_ffff_ffff_ffff;
const EXP_INF: i32 = 0x7ff;
const QNAN: u64 = 0x7ff8_0000_0000_0000;
const PINF: u64 = 0x7ff0_0000_0000_0000;

/// pi/2, high part (low word truncated so n*pio2_hi is exact).
const PIO2_HI: u64 = 0x3ff9_21fb_5440_0000;
/// pi/2 - pio2_hi.
const PIO2_LO: u64 = 0x3dd0_b461_1a62_6331;
/// pio2_lo, high part.
const PIO2_2_HI: u64 = 0x3dd0_b461_1a60_0000;
/// pio2_lo - pio2_2_hi.
const PIO2_2_LO: u64 = 0x3ba3_198a_2e03_7073;
/// pio2_2_lo, high part.
const PIO2_3_HI: u64 = 0x3ba3_198a_2e00_0000;
/// pio2_2_lo - pio2_3_hi.
const PIO2_3_LO: u64 = 0x397b_839a_2520_49c1;
/// 2/pi.
const TWO_OVER_PI: u64 = 0x3fe4_5f30_6dc9_c883;
/// 0.5, the rounding bias for the quadrant count.
const HALF: u64 = 0x3fe0_0000_0000_0000;
/// 9.0, the quadrant bias of the huge path.
const QUADRANT_BIAS: u64 = 0x4022_0000_0000_0000;
/// Reduction scale K, high part (30 low mantissa bits clear).
const REDUCE_K_HI: u64 = 0x3fdb_4445_4000_0000;
/// Reduction scale K, low part (negative).
const REDUCE_K_LO: u64 = 0xbe1d_bfb1_9000_0000;
/// K = REDUCE_K_HI + REDUCE_K_LO, to the last bit.
const REDUCE_K: u64 = 0x3fdb_4445_3e24_04e7;
/// K*(pi/2), to the last bit (C4/C5 == pi/2).
const K_PIO2: u64 = 0x3fe5_6a4a_a740_a5a7;
/// K*2*pi == 4*K_PIO2, to the last bit.
const K_TWO_PI: u64 = 0x4005_6a4a_a740_a5a7;

/// Huge-path pre-scale table @ 0x08986048, indexed by
/// (exp(x) - 1129) / 54 for exp(x) >= 1129 (|x| >= 2^106). Embedded
/// verbatim; entries are NOT powers of two (see module doc).
const HUGE_SCALE: [u64; 18] = [
    0x3ca0_3923_66c0_e65c,
    0x3954_c2b1_486f_5ba8,
    0xb625_4068_caf7_c76b,
    0x32e3_9207_84bd_9ac5,
    0x2fa6_702f_1efd_4be4,
    0xac49_1d0b_7ac6_5e97,
    0x2903_bd1a_aa3b_c92e,
    0xa5de_f596_c9a2_2250,
    0x22a2_b780_9555_fdd5,
    0x9f63_8c87_046a_611e,
    0x1bfe_c8dd_916f_a3b6,
    0x18d6_c252_dc0e_352b,
    0x9589_77f8_b54c_4d89,
    0x91ca_afb6_4c55_ac6b,
    0x8ef7_690b_593c_7f16,
    0x0be5_71a3_41e9_c6c7,
    0x88a3_bdd9_8851_aaad,
    0x0562_d533_94f3_de7d,
];

/// __kernel_rem_pio2 — original @ 0x080338f4. Argument reduction
/// x = y[0] + n*pi/2 (+ y[1], always +-0.0). Soft-float bit patterns
/// in/out; n is the quadrant count (exact for |x| <= 2^20*pi/2, correct
/// mod 4 above that).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __kernel_rem_pio2(x: u64, y: *mut u64) -> i32 {
    let x_hi = (x >> 32) as u32;
    let ix = x_hi & 0x7fff_ffff;
    *y.add(1) = 0;

    if ix <= 0x3fe9_21fb {
        // |x| <= ~pi/4: no reduction needed.
        *y = x;
        return 0;
    }

    if ix < 0x4002_d97c {
        // pi/4 < |x| < 3pi/4: n = +-1, y = x -+ pi/2 in hi/lo pieces.
        if (x_hi as i32) > 0 {
            let mut z = d_sub(x, PIO2_HI);
            if ix != 0x3ff9_21fb {
                z = d_sub(z, PIO2_LO);
            } else {
                z = d_sub(z, PIO2_2_HI);
                z = d_sub(z, PIO2_2_LO);
            }
            *y = z;
            1
        } else {
            let mut z = d_add(x, PIO2_HI);
            if ix != 0x3ff9_21fb {
                z = d_add(z, PIO2_LO);
            } else {
                z = d_add(z, PIO2_2_HI);
                z = d_add(z, PIO2_2_LO);
            }
            *y = z;
            -1
        }
    } else if ix > 0x4139_21fb {
        rem_pio2_huge(x, x_hi, y)
    } else {
        rem_pio2_medium(x, x_hi, ix, y)
    }
}

/// Medium path: 3pi/4 <= |x| <= 2^20*pi/2. Full-precision quadrant.
unsafe fn rem_pio2_medium(x: u64, x_hi: u32, ix: u32, y: *mut u64) -> i32 {
    let t = x & !SIGN; // |x|
    let n = d2i(d_add(d_mul(t, TWO_OVER_PI), HALF));
    let n_dbl = i2d(n);
    let mut resid = d_sub(t, d_mul(n_dbl, PIO2_HI));
    let mut corr_term = d_mul(n_dbl, PIO2_LO);
    let mut iter: i32 = 1;
    let mut y0;
    loop {
        y0 = d_sub(resid, corr_term);
        if iter == 3 {
            break;
        }
        let exp_gap = (ix >> 20) as i32 - (((y0 >> 52) as u32) & 0x7ff) as i32;
        if 33 * iter - 17 >= exp_gap {
            break;
        }
        // Refinement pass with the pio2_{iter+1} hi/lo pair.
        let (p_hi, p_lo) = if iter == 1 {
            (PIO2_2_HI, PIO2_2_LO)
        } else {
            (PIO2_3_HI, PIO2_3_LO)
        };
        let j = d_mul(n_dbl, p_hi);
        let resid_new = d_sub(resid, j);
        let roundoff = d_sub(d_sub(resid, resid_new), j);
        corr_term = d_sub(d_mul(n_dbl, p_lo), roundoff);
        resid = resid_new;
        iter += 1;
    }
    if (x_hi as i32) >= 0 {
        *y = y0;
        n
    } else {
        *y = y0 ^ SIGN;
        *y.add(1) = SIGN; // y[1] = -0.0
        -n
    }
}

/// Huge path: |x| > 2^20*pi/2. Double-double x*K reduced by the IEEE
/// remainder core; n is only correct mod 4.
unsafe fn rem_pio2_huge(x: u64, x_hi: u32, y: *mut u64) -> i32 {
    let mut scaled_x = x;
    let exp_field = ((x_hi >> 20) & 0x7ff) as i32;
    if exp_field >= 1129 {
        // |x| >= 2^106: pre-scale (table embedded verbatim, see doc).
        let idx = ((exp_field - 1129) as u32 / 54) as usize;
        scaled_x = d_mul(scaled_x, HUGE_SCALE[idx]);
    }
    // Split the (scaled) argument: hi_part keeps the top 27 mantissa
    // bits so that hi_part*K_HI, hi_part*K_LO, lo_part*K_HI and
    // lo_part*K_LO are all exact products.
    let hi_part = scaled_x & 0xffff_ffff_fc00_0000;
    let lo_part = d_sub(scaled_x, hi_part);
    let t1 = d_mul(hi_part, REDUCE_K_HI);
    let t2 = d_mul(hi_part, REDUCE_K_LO);
    let t3 = d_mul(lo_part, REDUCE_K_HI);
    let t4 = d_mul(lo_part, REDUCE_K_LO);
    let cross = d_add(t2, t3);
    let scaled_hi = d_add(t1, cross);
    let scaled_lo = d_add(d_sub(cross, d_sub(scaled_hi, t1)), t4);
    // Quadrant mod 4: rem(hi, K*2pi)/(K*2pi) is in [-1/2, 1/2].
    let period_rem = __dmod(scaled_hi, K_TWO_PI);
    let frac8 = d_scalb3(d_div(period_rem, K_TWO_PI));
    let n = d2i(d_add(frac8, QUADRANT_BIAS)) >> 1;
    // Reduced argument: y = rem(hi + lo, K*pi/2) / K, staged so the
    // low half is folded in before the final remainder.
    let quad_rem = __dmod(scaled_hi, K_PIO2);
    let y0 = __dmod(d_add(quad_rem, scaled_lo), K_PIO2);
    *y = d_div(y0, REDUCE_K);
    n
}

// ---------------------------------------------------------------------------
// Local soft-float helpers (stand-ins for the ADS __dadd/__dsub/__dmul/
// __ddiv/__d2i/__i2d/__dscalb calls, whose own ports live elsewhere).
// All arithmetic is round-to-nearest-even on the 53-bit significand with
// ADS-style flush-to-zero of denormals. Doubles are u64 bit patterns.
// Variable 64-bit shifts go through u32-limb helpers so LLVM never emits
// __aeabi_llsl/__aeabi_lsrl libcalls.
// ---------------------------------------------------------------------------

/// u64 left shift by `n` (n < 64) via u32 limbs.
fn shl64(v: u64, n: u32) -> u64 {
    debug_assert!(n < 64);
    if n == 0 {
        return v;
    }
    let hi = (v >> 32) as u32;
    let lo = v as u32;
    if n >= 32 {
        ((lo << (n - 32)) as u64) << 32
    } else {
        ((((hi << n) | (lo >> (32 - n))) as u64) << 32) | ((lo << n) as u64)
    }
}

/// u64 logical right shift by `n` (n < 64) via u32 limbs.
fn shr64(v: u64, n: u32) -> u64 {
    debug_assert!(n < 64);
    if n == 0 {
        return v;
    }
    let hi = (v >> 32) as u32;
    let lo = v as u32;
    if n >= 32 {
        (hi >> (n - 32)) as u64
    } else {
        (((hi >> n) as u64) << 32) | (((hi << (32 - n)) | (lo >> n)) as u64)
    }
}

/// Right shift by any `n`; bit 0 of the result is set if any bit was
/// shifted out (sticky).
fn shr64_sticky(v: u64, n: u32) -> u64 {
    if n == 0 {
        return v;
    }
    if n >= 64 {
        return (v != 0) as u64;
    }
    let lost = if n >= 32 {
        let mask = if n == 32 { 0 } else { (1u32 << (n - 32)) - 1 };
        (((v >> 32) as u32) & mask) != 0 || (v as u32) != 0
    } else {
        (v as u32) & ((1u32 << n) - 1) != 0
    };
    let shifted = shr64(v, n);
    if lost {
        shifted | 1
    } else {
        shifted
    }
}

/// Pack a rounded result: `sig` holds the significand with the hidden
/// bit at 55, guard at bit 2, round at bit 1, sticky at bit 0.
fn round_pack(sign: u64, mut exp: i32, sig: u64) -> u64 {
    let mut mant = shr64(sig, 3);
    let guard = (sig >> 2) & 1;
    let round_sticky = (sig & 3) != 0;
    if guard == 1 && (round_sticky || (mant & 1) == 1) {
        mant += 1;
        if mant == (HIDDEN << 1) {
            mant = HIDDEN;
            exp += 1;
        }
    }
    if exp >= EXP_INF {
        return sign | PINF;
    }
    if exp <= 0 {
        return sign; // flush would-be denormal to signed zero (ADS)
    }
    sign | ((exp as u64) << 52) | (mant & FRAC)
}

/// __dadd stand-in: round-to-nearest-even double add.
fn d_add(a: u64, b: u64) -> u64 {
    let sa = a & SIGN;
    let sb = b & SIGN;
    let ea = ((a >> 52) & 0x7ff) as i32;
    let eb = ((b >> 52) & 0x7ff) as i32;

    if ea == EXP_INF || eb == EXP_INF {
        let a_nan = ea == EXP_INF && (a & FRAC) != 0;
        let b_nan = eb == EXP_INF && (b & FRAC) != 0;
        if a_nan || b_nan {
            return QNAN;
        }
        if ea == EXP_INF && eb == EXP_INF && sa != sb {
            return QNAN; // Inf + -Inf
        }
        if ea == EXP_INF {
            return a;
        }
        return b;
    }

    // Denormal inputs flush to +0 (ADS); signed zeros stay signed.
    let a_zero = (a << 1) == 0 || ea == 0;
    let b_zero = (b << 1) == 0 || eb == 0;
    if a_zero && b_zero {
        // -0 + -0 = -0; everything else (incl. flushed denormals) = +0.
        if (a << 1) == 0 && (b << 1) == 0 && sa != 0 && sb != 0 {
            return SIGN;
        }
        return 0;
    }
    if a_zero {
        return b;
    }
    if b_zero {
        return a;
    }

    let fa = (a & FRAC) | HIDDEN;
    let fb = (b & FRAC) | HIDDEN;
    // Order so the first operand has the larger exponent.
    let (sa, mut ea, fa, sb, eb, fb) = if ea >= eb {
        (sa, ea, fa, sb, eb, fb)
    } else {
        (sb, eb, fb, sa, ea, fa)
    };
    let exp_diff = (ea - eb) as u32;
    // Significands with 3 guard bits; hidden bit at 55.
    let sig_a = fa << 3;
    let sig_b = shr64_sticky(fb << 3, exp_diff);
    if sa == sb {
        let mut sum = sig_a + sig_b;
        if sum & (1u64 << 56) != 0 {
            sum = shr64_sticky(sum, 1);
            ea += 1;
        }
        round_pack(sa, ea, sum)
    } else {
        if sig_a == sig_b {
            return 0; // exact cancellation: +0
        }
        let (mut diff, sign) = if sig_a > sig_b {
            (sig_a - sig_b, sa)
        } else {
            (sig_b - sig_a, sb)
        };
        // Normalize so the hidden bit is back at 55. The shift is exact:
        // cancellation by >= 2 bits only happens when the alignment
        // shift was <= 1, which loses no bits (fb << 3 has 3 low zeros).
        let shift = diff.leading_zeros() - 8;
        if shift > 0 {
            diff = shl64(diff, shift);
            ea -= shift as i32;
        }
        round_pack(sign, ea, diff)
    }
}

/// __dsub stand-in.
fn d_sub(a: u64, b: u64) -> u64 {
    d_add(a, b ^ SIGN)
}

/// __dmul stand-in: round-to-nearest-even double multiply.
fn d_mul(a: u64, b: u64) -> u64 {
    let sign = (a ^ b) & SIGN;
    let ea = ((a >> 52) & 0x7ff) as i32;
    let eb = ((b >> 52) & 0x7ff) as i32;

    if ea == EXP_INF || eb == EXP_INF {
        let a_nan = ea == EXP_INF && (a & FRAC) != 0;
        let b_nan = eb == EXP_INF && (b & FRAC) != 0;
        if a_nan || b_nan {
            return QNAN;
        }
        let a_zero = (a << 1) == 0 || ea == 0;
        let b_zero = (b << 1) == 0 || eb == 0;
        if (ea == EXP_INF && b_zero) || (eb == EXP_INF && a_zero) {
            return QNAN; // Inf * 0
        }
        return sign | PINF;
    }

    let a_zero = (a << 1) == 0 || ea == 0;
    let b_zero = (b << 1) == 0 || eb == 0;
    if a_zero || b_zero {
        return sign; // +-0 (denormals flush)
    }

    let fa = (a & FRAC) | HIDDEN;
    let fb = (b & FRAC) | HIDDEN;
    // 53x53 -> 106-bit product in u32 limbs (u32*u32 -> u64 is UMULL).
    let a_lo = fa & 0xffff_ffff;
    let a_hi = fa >> 32;
    let b_lo = fb & 0xffff_ffff;
    let b_hi = fb >> 32;
    let p0 = a_lo * b_lo;
    let mid = a_lo * b_hi + a_hi * b_lo;
    let p3 = a_hi * b_hi;
    let prod_lo = p0.wrapping_add((mid & 0xffff_ffff) << 32);
    let carry = (prod_lo < p0) as u64;
    let prod_hi = p3 + (mid >> 32) + carry;

    let mut exp = ea + eb - 1023;
    let mut mant;
    let guard;
    let sticky;
    if prod_hi & (1u64 << 41) != 0 {
        // Product bit 105 set: significand in [2^105, 2^106). The 53
        // result bits [105:53] straddle the prod_hi/prod_lo boundary.
        exp += 1;
        mant = (prod_hi << 11) | (prod_lo >> 53);
        guard = (prod_lo >> 52) & 1;
        sticky = prod_lo & 0x000f_ffff_ffff_ffff;
    } else {
        // Product bit 104 set: result bits [104:52].
        mant = (prod_hi << 12) | (prod_lo >> 52);
        guard = (prod_lo >> 51) & 1;
        sticky = prod_lo & 0x0007_ffff_ffff_ffff;
    }
    if guard == 1 && (sticky != 0 || (mant & 1) == 1) {
        mant += 1;
        if mant == (HIDDEN << 1) {
            mant = HIDDEN;
            exp += 1;
        }
    }
    if exp >= EXP_INF {
        return sign | PINF;
    }
    if exp <= 0 {
        return sign; // flush
    }
    sign | ((exp as u64) << 52) | (mant & FRAC)
}

/// __ddiv stand-in: round-to-nearest-even double divide.
fn d_div(a: u64, b: u64) -> u64 {
    let sign = (a ^ b) & SIGN;
    let ea = ((a >> 52) & 0x7ff) as i32;
    let eb = ((b >> 52) & 0x7ff) as i32;

    if ea == EXP_INF || eb == EXP_INF {
        let a_nan = ea == EXP_INF && (a & FRAC) != 0;
        let b_nan = eb == EXP_INF && (b & FRAC) != 0;
        if a_nan || b_nan || (ea == EXP_INF && eb == EXP_INF) {
            return QNAN;
        }
        if ea == EXP_INF {
            return sign | PINF;
        }
        return sign; // finite / Inf -> +-0
    }

    let a_zero = (a << 1) == 0 || ea == 0;
    let b_zero = (b << 1) == 0 || eb == 0;
    if b_zero {
        if a_zero {
            return QNAN; // 0/0
        }
        return sign | PINF; // x/0 -> +-Inf (original raises SIGFPE)
    }
    if a_zero {
        return sign;
    }

    let mut fa = (a & FRAC) | HIDDEN;
    let fb = (b & FRAC) | HIDDEN;
    let mut exp = ea - eb + 1023;
    if fa < fb {
        fa <<= 1;
        exp -= 1;
    }
    // Long division: fa in [fb, 2*fb), so the quotient is in [1, 2).
    // Produce 54 quotient bits (53 significand + guard); the leftover
    // remainder is the sticky.
    let mut rem = fa - fb;
    let mut quot: u64 = 1;
    let mut i = 0;
    while i < 53 {
        rem <<= 1;
        quot <<= 1;
        if rem >= fb {
            rem -= fb;
            quot |= 1;
        }
        i += 1;
    }
    let guard = quot & 1;
    let mut mant = quot >> 1;
    let sticky = rem != 0;
    if guard == 1 && (sticky || (mant & 1) == 1) {
        mant += 1;
        if mant == (HIDDEN << 1) {
            mant = HIDDEN;
            exp += 1;
        }
    }
    if exp >= EXP_INF {
        return sign | PINF;
    }
    if exp <= 0 {
        return sign; // flush
    }
    sign | ((exp as u64) << 52) | (mant & FRAC)
}

/// __d2i stand-in: double -> i32, truncation toward zero. Out-of-range
/// and Inf/NaN saturate (the original raises SIGFPE there; all call
/// sites here are bounded).
fn d2i(x: u64) -> i32 {
    let negative = x & SIGN != 0;
    let exp = ((x >> 52) & 0x7ff) as i32;
    if exp < 1023 {
        return 0; // |x| < 1 (also zeros/denormals)
    }
    let shift = exp - 1023;
    if exp == EXP_INF || shift > 30 {
        return if negative { i32::MIN } else { i32::MAX };
    }
    let sig = (x & FRAC) | HIDDEN;
    let v = shr64(sig, (52 - shift) as u32) as i32;
    if negative {
        -v
    } else {
        v
    }
}

/// __i2d stand-in: i32 -> double, exact.
fn i2d(n: i32) -> u64 {
    if n == 0 {
        return 0;
    }
    let sign = if n < 0 { SIGN } else { 0 };
    let mag = n.wrapping_abs() as u32;
    let lead = mag.leading_zeros();
    let exp = 1023 + 31 - lead as i32;
    let sig = shl64(mag as u64, 21 + lead);
    sign | ((exp as u64) << 52) | (sig & FRAC)
}

/// __dscalb stand-in for the only call site: scalbn(x, 3) == x * 8.
fn d_scalb3(x: u64) -> u64 {
    let exp = ((x >> 52) & 0x7ff) as i32;
    if exp == 0 || exp == EXP_INF {
        return x; // +-0/denormal (flushed) and Inf/NaN pass through
    }
    if exp + 3 >= EXP_INF {
        return (x & SIGN) | PINF;
    }
    x + (3u64 << 52)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn f(bits: u64) -> f64 {
        f64::from_bits(bits)
    }

    fn host_remainder(a: f64, b: f64) -> f64 {
        extern "C" {
            fn remainder(x: f64, y: f64) -> f64;
        }
        unsafe { remainder(a, b) }
    }

    /// Bit-exact f64 step-by-step simulation of the original algorithm
    /// (host f64 add/sub/mul/div are RNE like the ADS helpers; libm
    /// remainder() matches the __dmod core exactly).
    fn simulate(x: f64) -> (i32, f64, f64) {
        let x_bits = x.to_bits();
        let x_hi = (x_bits >> 32) as u32;
        let ix = x_hi & 0x7fff_ffff;
        let (pio2_hi, pio2_lo) = (f(PIO2_HI), f(PIO2_LO));
        let (pio2_2_hi, pio2_2_lo) = (f(PIO2_2_HI), f(PIO2_2_LO));
        let (pio2_3_hi, pio2_3_lo) = (f(PIO2_3_HI), f(PIO2_3_LO));
        if ix <= 0x3fe9_21fb {
            return (0, x, 0.0);
        }
        if ix < 0x4002_d97c {
            if (x_hi as i32) > 0 {
                let mut z = x - pio2_hi;
                if ix != 0x3ff9_21fb {
                    z -= pio2_lo;
                } else {
                    z -= pio2_2_hi;
                    z -= pio2_2_lo;
                }
                return (1, z, 0.0);
            }
            let mut z = x + pio2_hi;
            if ix != 0x3ff9_21fb {
                z += pio2_lo;
            } else {
                z += pio2_2_hi;
                z += pio2_2_lo;
            }
            return (-1, z, 0.0);
        }
        if ix > 0x4139_21fb {
            let (k_hi, k_lo) = (f(REDUCE_K_HI), f(REDUCE_K_LO));
            let (k, k_pio2, k_2pi) = (f(REDUCE_K), f(K_PIO2), f(K_TWO_PI));
            let mut scaled_x = x;
            let exp_field = ((x_hi >> 20) & 0x7ff) as i32;
            if exp_field >= 1129 {
                let idx = ((exp_field - 1129) as u32 / 54) as usize;
                scaled_x *= f(HUGE_SCALE[idx]);
            }
            let hi_part = f(scaled_x.to_bits() & 0xffff_ffff_fc00_0000);
            let lo_part = scaled_x - hi_part;
            let t1 = hi_part * k_hi;
            let t2 = hi_part * k_lo;
            let t3 = lo_part * k_hi;
            let t4 = lo_part * k_lo;
            let cross = t2 + t3;
            let scaled_hi = t1 + cross;
            let scaled_lo = (cross - (scaled_hi - t1)) + t4;
            let period_rem = host_remainder(scaled_hi, k_2pi);
            let n = (((period_rem / k_2pi) * 8.0 + 9.0) as i32) >> 1;
            let quad_rem = host_remainder(scaled_hi, k_pio2);
            let y0 = host_remainder(quad_rem + scaled_lo, k_pio2);
            return (n, y0 / k, 0.0);
        }
        let t = x.abs();
        let n = (t * f(TWO_OVER_PI) + 0.5) as i32;
        let n_dbl = n as f64;
        let mut resid = t - n_dbl * pio2_hi;
        let mut corr_term = n_dbl * pio2_lo;
        let mut iter: i32 = 1;
        let mut y0;
        loop {
            let z = resid - corr_term;
            y0 = z;
            if iter == 3 {
                break;
            }
            let exp_gap = (ix >> 20) as i32 - (((z.to_bits() >> 52) as u32) & 0x7ff) as i32;
            if 33 * iter - 17 >= exp_gap {
                break;
            }
            let (p_hi, p_lo) = if iter == 1 {
                (pio2_2_hi, pio2_2_lo)
            } else {
                (pio2_3_hi, pio2_3_lo)
            };
            let j = n_dbl * p_hi;
            let resid_new = resid - j;
            let roundoff = (resid - resid_new) - j;
            corr_term = n_dbl * p_lo - roundoff;
            resid = resid_new;
            iter += 1;
        }
        if (x_hi as i32) >= 0 {
            (n, y0, 0.0)
        } else {
            (-n, -y0, -0.0)
        }
    }

    fn port(x: f64) -> (i32, f64, f64) {
        let mut y = [0xdead_beef_dead_beefu64; 2];
        let n = unsafe { __kernel_rem_pio2(x.to_bits(), y.as_mut_ptr()) };
        (n, f(y[0]), f(y[1]))
    }

    /// xorshift64* for reproducible random bit patterns.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    // ---- constants ----

    #[test]
    fn constants_are_the_extracted_doubles() {
        // pio2 table @ 0x089860d8: hi/lo pairs sum towards pi/2.
        assert_eq!(PIO2_HI, 0x3ff9_21fb_5440_0000);
        assert_eq!(PIO2_LO, 0x3dd0_b461_1a62_6331);
        assert_eq!(PIO2_2_HI, 0x3dd0_b461_1a60_0000);
        assert_eq!(PIO2_2_LO, 0x3ba3_198a_2e03_7073);
        assert_eq!(PIO2_3_HI, 0x3ba3_198a_2e00_0000);
        assert_eq!(PIO2_3_LO, 0x397b_839a_2520_49c1);
        let pio2 = f(PIO2_HI) + f(PIO2_LO) + f(PIO2_2_LO) + f(PIO2_3_LO);
        assert!((pio2 - core::f64::consts::FRAC_PI_2).abs() < 1e-30);
        // Reduction constants: K split is exact, C4/C5 == pi/2, C3 == 4*C4.
        assert_eq!((f(REDUCE_K_HI) + f(REDUCE_K_LO)).to_bits(), REDUCE_K);
        assert_eq!((f(K_PIO2) / f(REDUCE_K)).to_bits(), core::f64::consts::FRAC_PI_2.to_bits());
        assert_eq!((4.0 * f(K_PIO2)).to_bits(), K_TWO_PI);
        assert_eq!(f(TWO_OVER_PI), 2.0 / core::f64::consts::PI);
        // Scale table @ 0x08986048, verbatim (18 entries, then pio2_hi).
        assert_eq!(HUGE_SCALE.len(), 18);
        assert_eq!(HUGE_SCALE[0], 0x3ca0_3923_66c0_e65c);
        assert_eq!(HUGE_SCALE[17], 0x0562_d533_94f3_de7d);
    }

    // ---- local soft-float helpers vs host f64 (RNE oracle) ----

    /// Random normal finite pair; skips operand/result shapes where the
    /// original deliberately diverges (denormal flush, x/0 raise).
    fn random_normal_pair(rng: &mut Rng) -> (u64, u64) {
        loop {
            let a = rng.next() & 0x7fff_ffff_ffff_ffff;
            let b = rng.next() & 0x7fff_ffff_ffff_ffff;
            let (fa, fb) = (f(a), f(b));
            if fa.is_finite() && fb.is_finite() && fa.abs() >= f64::MIN_POSITIVE && fb.abs() >= f64::MIN_POSITIVE
            {
                return (a, b);
            }
        }
    }

    #[test]
    fn helpers_match_host_random() {
        let mut rng = Rng(0x243f_6a88_85a3_08d3);
        let mut checked = 0u32;
        while checked < 100_000 {
            let (a, b) = random_normal_pair(&mut rng);
            let (fa, fb) = (f(a), f(b));
            for (got, want) in [
                (d_add(a, b), (fa + fb).to_bits()),
                (d_sub(a, b), (fa - fb).to_bits()),
                (d_mul(a, b), (fa * fb).to_bits()),
                (d_div(a, b), (fa / fb).to_bits()),
            ] {
                let fw = f(want);
                // Denormal results flush to zero in the original (and here).
                if fw != 0.0 && fw.abs() < f64::MIN_POSITIVE {
                    assert_eq!(got & !SIGN, 0, "flush a={a:#x} b={b:#x}");
                } else if fw.is_finite() {
                    assert_eq!(got, want, "a={a:#x} b={b:#x}");
                } else {
                    // Overflow to Inf: bits must match too.
                    assert_eq!(got, want, "inf a={a:#x} b={b:#x}");
                }
            }
            checked += 1;
        }
    }

    #[test]
    fn helpers_directed() {
        // Add: exact cancellation and round-half-even ties.
        assert_eq!(d_add(1.0f64.to_bits(), (-1.0f64).to_bits()), 0);
        let one = 1.0f64.to_bits();
        let half_ulp = (2f64.powi(-53)).to_bits();
        assert_eq!(d_add(one, half_ulp), one); // tie -> even (down)
        let one_odd = (1.0 + 2f64.powi(-52)).to_bits();
        assert_eq!(d_add(one_odd, half_ulp), (1.0 + 2f64.powi(-51)).to_bits()); // tie -> even (up)
        // Sub: sticky collection across a wide exponent gap.
        assert_eq!(d_sub(one, (2f64.powi(-60)).to_bits()), one); // below half ulp
        assert_eq!(
            d_sub(one, (3f64 * 2f64.powi(-54)).to_bits()),
            (1.0f64 - 3f64 * 2f64.powi(-54)).to_bits()
        );
        // Mul: overflow, exact powers, signed zero.
        assert_eq!(d_mul(0x7fef_ffff_ffff_ffff, (1.5f64).to_bits()), PINF);
        assert_eq!(d_mul((-2.0f64).to_bits(), (0.0f64).to_bits()), SIGN);
        // Div: x/0 -> +-Inf, 0/0 -> NaN.
        assert_eq!(d_div(one, 0), PINF);
        assert_eq!(d_div(0, 0), QNAN);
        // d2i / i2d.
        assert_eq!(d2i((13.9f64).to_bits()), 13);
        assert_eq!(d2i((-13.9f64).to_bits()), -13);
        assert_eq!(d2i((0.5f64).to_bits()), 0);
        assert_eq!(i2d(0), 0);
        assert_eq!(i2d(1_048_576), (1_048_576f64).to_bits());
        assert_eq!(i2d(-636_620), (-636_620f64).to_bits());
        let mut rng = Rng(0xdead_beef_1234_5678);
        for _ in 0..10_000 {
            let n = (rng.next() as i32) >> 8; // keep within +-2^23 for exact host cast
            assert_eq!(i2d(n), (n as f64).to_bits(), "i2d({n})");
            assert_eq!(d2i(i2d(n)), n, "d2i(i2d({n}))");
        }
        // scalb3: normal, zero, overflow.
        assert_eq!(d_scalb3((0.125f64).to_bits()), (1.0f64).to_bits());
        assert_eq!(d_scalb3(0), 0);
        assert_eq!(d_scalb3(0x7fe0_0000_0000_0000), PINF);
    }

    // ---- path boundary / directed cases ----

    #[test]
    fn tiny_and_small_paths() {
        // |x| <= 0x3fe921fb...: n = 0, y = x verbatim.
        for x in [0.5f64, -0.5, 0.0, -0.0, f(0x3fe9_21fb_5444_2d18)] {
            let (n, y0, y1) = port(x);
            assert_eq!(n, 0, "x={x}");
            assert_eq!(y0.to_bits(), x.to_bits(), "x={x}");
            assert_eq!(y1.to_bits(), 0.0f64.to_bits(), "x={x}");
        }
        // pi/4 < |x| < 3pi/4: n = +-1.
        for (x, want_n) in [(1.0f64, 1), (-1.0, -1), (2.0, 1), (-2.0, -1)] {
            let (n, y0, y1) = port(x);
            let (sn, sy0, sy1) = simulate(x);
            assert_eq!((n, y0.to_bits(), y1.to_bits()), (sn, sy0.to_bits(), sy1.to_bits()), "x={x}");
            assert_eq!(n, want_n, "x={x}");
        }
        // |x| sharing pi/2's high word: extended 3-term subtraction.
        let x = f(0x3ff9_21fb_5444_2d18); // the pi/2 double itself
        let (n, y0, _) = port(x);
        let (sn, sy0, _) = simulate(x);
        assert_eq!(n, 1);
        assert_eq!(y0.to_bits(), sy0.to_bits());
        assert_eq!(sn, 1);
        assert!(y0.abs() < 1e-15, "y0={y0}"); // pi/2 - pi/2 ~ 3.5e-17
    }

    #[test]
    fn moderate_args_vs_host() {
        for x in [1.0f64, 10.0, 100.0, -1.0, -10.0, -100.0] {
            let (n, y0, y1) = port(x);
            let (sn, sy0, sy1) = simulate(x);
            assert_eq!((n, y0.to_bits(), y1.to_bits()), (sn, sy0.to_bits(), sy1.to_bits()), "x={x}");
            // Identity x ~ y + n*pi/2 with y in [-pi/4, pi/4]. y carries
            // ~pi/2 * 2^-53 absolute error from the hi/lo scheme; the
            // residual tolerance below is generous at 1e-13.
            assert!(y0.abs() <= core::f64::consts::FRAC_PI_4 + 1e-15, "x={x} y={y0}");
            let resid = (x - y0) - n as f64 * core::f64::consts::FRAC_PI_2;
            assert!(resid.abs() < 1e-13, "x={x} resid={resid}");
            // y[1] is flipped to -0.0 only by the medium path (|x| >=
            // 3pi/4) for negative x; the small path leaves +0.0.
            let medium = ((x.to_bits() >> 32) as u32) & 0x7fff_ffff >= 0x4002_d97c;
            assert_eq!(y1.to_bits(), if x < 0.0 && medium { SIGN } else { 0 }, "x={x}");
        }
    }

    #[test]
    fn large_args_fmod_path_end_to_end() {
        // NOTE: 1e6 is below the huge-path threshold 2^20*pi/2 ~
        // 1.647e6, so it exercises the medium path (full quadrant);
        // 2e6 and 1e12 go through the huge path with the real __dmod.
        for x in [1e6f64, -1e6, 2e6, -2e6, 1e12, -1e12] {
            let (n, y0, y1) = port(x);
            let (sn, sy0, sy1) = simulate(x);
            assert_eq!((n, y0.to_bits(), y1.to_bits()), (sn, sy0.to_bits(), sy1.to_bits()), "x={x}");
            let n_true = (x * (2.0 / core::f64::consts::PI)).round() as i64;
            let huge = ((x.to_bits() >> 32) as u32) & 0x7fff_ffff > 0x4139_21fb;
            if huge {
                // Huge path: n lands in [2, 6], matching the true
                // quadrant mod 4; y[1] is never sign-flipped there.
                assert!((2..=6).contains(&n), "x={x} n={n}");
                assert_eq!((n as i64 - n_true) % 4, 0, "x={x} n={n} n_true={n_true}");
                assert_eq!(y1.to_bits(), 0.0f64.to_bits(), "x={x}");
            } else {
                assert_eq!(n as i64, n_true, "x={x} n={n} n_true={n_true}");
            }
            assert!(y0.abs() <= core::f64::consts::FRAC_PI_4 * (1.0 + 1e-12), "x={x} y={y0}");
            // Identity mod 2pi, evaluated with compensated summation so
            // the check itself is not the noise source (n is small, so
            // n*pi/2 is nearly exact; the residual is accurate to ~ulp(x)
            // * 2^-53). Tolerance 1e-8 on the 2pi-normalized residual.
            let c = n as f64 * core::f64::consts::FRAC_PI_2;
            let (s1, e1) = two_sum(x, -y0);
            let (s2, e2) = two_sum(s1, -c);
            let frac = ((s2 + e1 + e2) / core::f64::consts::TAU).fract();
            let frac = if frac > 0.5 { frac - 1.0 } else { frac };
            assert!(frac.abs() < 1e-8, "x={x} frac={frac}");
        }
    }

    fn two_sum(a: f64, b: f64) -> (f64, f64) {
        let s = a + b;
        let bb = s - a;
        let err = (a - (s - bb)) + (b - bb);
        (s, err)
    }

    #[test]
    fn path_boundaries() {
        // ix straddling the small/medium and medium/huge thresholds.
        for bits in [
            0x3fe9_21fb_0000_0000u64, // tiny boundary (<=)
            0x3fe9_21fc_0000_0000,    // small path
            0x4002_d97b_ffff_ffff,    // small path, top
            0x4002_d97c_0000_0000,    // medium path, bottom
            0x4139_21fb_0000_0000,    // medium path, top (2^20*pi/2-ish)
            0x4139_21fc_0000_0000,    // huge path, bottom
        ] {
            for x in [f(bits), -f(bits)] {
                let (n, y0, y1) = port(x);
                let (sn, sy0, sy1) = simulate(x);
                assert_eq!(
                    (n, y0.to_bits(), y1.to_bits()),
                    (sn, sy0.to_bits(), sy1.to_bits()),
                    "x={x}"
                );
            }
        }
    }

    #[test]
    fn random_all_paths_match_sim() {
        let mut rng = Rng(0x0123_4567_89ab_cdef);
        let mut counts = [0u32; 4];
        for _ in 0..40_000 {
            // Random finite double with exponents in [-2, 40]: hits the
            // tiny, small, medium and huge (unscaled) paths.
            let exp = 1021 + (rng.next() % 43) as u64;
            let bits = (rng.next() & SIGN) | (exp << 52) | (rng.next() & FRAC);
            let x = f(bits);
            if !x.is_finite() {
                continue;
            }
            let (n, y0, y1) = port(x);
            let (sn, sy0, sy1) = simulate(x);
            assert_eq!(
                (n, y0.to_bits(), y1.to_bits()),
                (sn, sy0.to_bits(), sy1.to_bits()),
                "x={x} ({bits:#x})"
            );
            let ix = ((bits >> 32) as u32) & 0x7fff_ffff;
            let path = if ix <= 0x3fe9_21fb {
                0
            } else if ix < 0x4002_d97c {
                1
            } else if ix <= 0x4139_21fb {
                2
            } else {
                3
            };
            counts[path] += 1;
        }
        // Every path got meaningful coverage.
        assert!(counts[0] > 100, "{counts:?}");
        assert!(counts[1] > 100, "{counts:?}");
        assert!(counts[2] > 1000, "{counts:?}");
        assert!(counts[3] > 1000, "{counts:?}");
    }

    #[test]
    fn huge_scaled_path_match_sim() {
        // |x| >= 2^106 exercises HUGE_SCALE[idx] (verbatim table; the
        // result is deterministic but not a meaningful reduction — the
        // check pins bug-for-bug equivalence with the original flow).
        let mut rng = Rng(0x0fed_cba9_8765_4321);
        for bits in [0x42b0_0000_0000_0000u64, 0x4320_0000_0000_0000, 0x4629_3456_789a_bcde] {
            let x = f(bits);
            let (n, y0, _) = port(x);
            let (sn, sy0, _) = simulate(x);
            assert_eq!((n, y0.to_bits()), (sn, sy0.to_bits()), "x={x}");
            assert!((2..=6).contains(&n), "x={x} n={n}");
        }
        let mut checked = 0u32;
        while checked < 2_000 {
            let exp = 1129 + (rng.next() % 120) as u64;
            let bits = (rng.next() & SIGN) | (exp << 52) | (rng.next() & FRAC);
            let x = f(bits);
            let (n, y0, _) = port(x);
            let (sn, sy0, _) = simulate(x);
            assert_eq!((n, y0.to_bits()), (sn, sy0.to_bits()), "x={x} ({bits:#x})");
            checked += 1;
        }
    }
}
