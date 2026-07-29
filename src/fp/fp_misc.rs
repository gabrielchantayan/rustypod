//! Port of the ARM ADS 1.0.1 soft-float square-root core and the
//! remainder core used by `__kernel_rem_pio2`.
//!
//! retailOS is SOFT-FLOAT: doubles travel as u64 bit patterns (r0:r1
//! register pairs). This module does pure integer bit manipulation — no
//! f64 arithmetic, which would lower to unported __aeabi_d* helpers.
//! Variable 64-bit shifts are done as u32-limb shifts so LLVM never
//! emits __aeabi_llsl/__aeabi_lsrl calls.
//!
//! `_dsqrt` — original: `FUN_083ebf28` @ 0x083ebf28 (348 bytes).
//! Correctly rounded double square root. Exponent is adjusted by
//! ((e + 253) >> 1) + 384 with the mantissa doubled when (e + 253) is
//! odd, then a shift-subtract (digit recurrence) root loop extracts
//! 29 high root bits into the top word and 23 more into the low word,
//! finishing with round-to-nearest-even from a round bit plus sticky
//! (remainder nonzero). Result is EXACTLY rounded — host f64::sqrt is
//! a perfect oracle.
//!
//! `__dmod` — original: `FUN_083ebc48` @ 0x083ebc48 (484 bytes).
//! Called only from the __kernel_rem_pio2 region (bl sites
//! 0x08033d30/68/84). IMPORTANT: despite the traditional name, this is
//! NOT fmod. It computes the IEEE 754 `remainder()` — the quotient is
//! rounded to NEAREST (ties to even), not truncated. Verified against
//! host libm remainder() on 20k+ random cases and all tie cases; it
//! diverges from fmod on ~25% of random inputs (e.g. dmod(5.5, 2.0) =
//! -0.5 where fmod gives +1.5). The core keeps both significands
//! normalized, subtracts |a_sig - b_sig|, negating and flipping a sign
//! track bit on borrow, renormalizes (chunked clz on the rare deep
//! path, single shifts otherwise) and repeats while a_exp >= b_exp;
//! the tail handles the final half-way comparison including the
//! round-half-even tie flip.
//!
//! `iabs` — original: `FUN_080e9788` @ 0x080e9788 (12 bytes).
//! Plain 32-bit integer absolute value: `cmp r0,#0; rsblt r0,r0,#0;
//! bx lr`. The rsb computes `0 - x` in 32 bits, so iabs(INT_MIN) wraps
//! back to INT_MIN (mirrored with wrapping_neg). 3 bl call sites
//! (0x08241e4c/0x08241e58 in FUN_08241acc, 0x082424cc in FUN_0824039c),
//! all in 0x0824xxxx graphics-region code that compares two |deltas|
//! and keeps the larger. The two immediately following functions
//! 0x080e9794 and 0x080e97a0 are byte-identical duplicate emissions;
//! they are separate assignments and have no Rust symbols here.
//!
//! Behavioral deviations from IEEE 754, mirrored from the original:
//! - _dsqrt: denormal inputs flush to +0 (even negative denormals;
//!   -0.0 returns -0.0). sqrt(NaN) returns the canonical quiet NaN
//!   0x7ff80000_00000000 (payload/sign dropped, via the shared
//!   exception stub @ 0x083ed080 which returns immediately for error
//!   descriptor 0x04000017). sqrt of a negative finite or -Inf returns
//!   the NaN 0x7ff80000_00000001 (NOT the canonical NaN — r0 is loaded
//!   with 1 in that tail). sqrt(+Inf) = +Inf.
//! - __dmod: any NaN input returns the canonical quiet NaN
//!   0x7ff80000_00000000 (error descriptor 0x04000015, no traps).
//!   +-Inf % finite and Inf % Inf return the NaN 0x7ff80000_00000001.
//!   finite % +-Inf returns the finite dividend unchanged. A zero or
//!   denormal DIVISOR returns the NaN 0x7ff80000_00000001 (denormal
//!   divisor flushes to zero first). A denormal dividend flushes to
//!   +0; +-0 % normal preserves the signed zero. A result whose
//!   exponent underflows (would-be denormal remainder) flushes to +0.
//!
//! Behavioral verification: host-side `cargo test` compares _dsqrt
//! against native aarch64 f64::sqrt (correctly rounded oracle) and
//! __dmod against host libm remainder() (exact operation), plus
//! directed tests pinning the deviations above; `tools/match.py`
//! (ipod-decomp) reports the mnemonic-level diff against the original
//! machine code.

/// Canonical quiet NaN (hi 0x7ff80000, lo 0): NaN inputs to either core.
const QNAN: u64 = 0x7ff8_0000_0000_0000;
/// Quiet NaN with low word 1: sqrt(negative)/sqrt(-Inf) and
/// __dmod's Inf % x / x % 0 results (the original loads r0 with 1).
const QNAN_LO1: u64 = 0x7ff8_0000_0000_0001;

/// _dsqrt — original @ 0x083ebf28. Double square root, soft-float
/// bit pattern in/out. Correctly rounded (round-to-nearest-even).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _dsqrt(x: u64) -> u64 {
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    let exp_field = hi & 0x7ff0_0000;

    if exp_field == 0 {
        // Zero or denormal: +-0 returns unchanged (sqrt(-0) = -0);
        // any nonzero denormal flushes to +0 (sign not tested here).
        if (hi << 12) | lo == 0 {
            return x;
        }
        return 0;
    }
    if exp_field == 0x7ff0_0000 {
        // Inf/NaN: NaN input -> canonical qNaN (exception stub tail);
        // +Inf returns unchanged; -Inf -> qNaN with low word 1.
        if (hi << 12) | lo != 0 {
            return QNAN;
        }
        if hi & 0x8000_0000 == 0 {
            return x;
        }
        return QNAN_LO1;
    }
    if hi & 0x8000_0000 != 0 {
        // Negative finite -> qNaN with low word 1.
        return QNAN_LO1;
    }

    // Split exponent and 53-bit significand (hidden bit restored).
    let biased_exp = hi >> 20;
    let mut sig = (x & 0x000f_ffff_ffff_ffff) | 0x0010_0000_0000_0000;
    let halved = biased_exp + 253;
    if halved & 1 != 0 {
        // Odd exponent: double the mantissa first (root exponent even).
        sig <<= 1;
    }
    let out_exp = ((halved >> 1) + 384) as u64;

    // Remainder register: sig scaled so the root emerges aligned to
    // bit 52; sig >= 2^52 so this never underflows.
    let mut rem = (sig << 10) - (1u64 << 62);
    let mut root: u64 = 0x4000_0000u64 << 32;

    // First root loop: 29 iterations extract the high root word
    // (root low word stays 0, so trials live entirely in the top half).
    let mut bit: u64 = 0x1000_0000;
    while bit != 0 {
        let trial = root + (bit << 32);
        if rem >= trial {
            rem -= trial;
            root += bit << 33;
        }
        rem <<= 1;
        bit >>= 1;
    }
    // One refinement step straddling the word boundary (root low = 0).
    let trial = root + 0x8000_0000;
    if rem >= trial {
        rem -= trial;
        root += 1u64 << 32;
    }
    rem <<= 1;

    // Second root loop: 23 iterations extract the low root word.
    let mut bit: u64 = 0x4000_0000;
    loop {
        let trial = root + bit;
        if rem >= trial {
            rem -= trial;
            root += bit << 1;
        }
        rem <<= 1;
        bit >>= 1;
        if bit == 0x80 {
            break;
        }
    }

    // Round to nearest even: round bit = root bit 9, sticky = leftover.
    let sticky = rem != 0;
    let round = (root >> 9) & 1 != 0;
    let mut result = (root >> 10) + (out_exp << 52);
    if round || sticky {
        result += round as u64;
        if !sticky {
            result &= !1; // exact tie: round to even
        }
    }
    result
}

/// __dmod — original @ 0x083ebc48. IEEE 754 remainder core (NOT fmod:
/// the quotient rounds to nearest, ties to even). Soft-float bit
/// patterns in/out. Exact operation — host libm remainder() oracle.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __dmod(a: u64, b: u64) -> u64 {
    let a_hi = (a >> 32) as u32;
    let a_lo = a as u32;
    let b_hi = (b >> 32) as u32;
    let b_lo = b as u32;
    // Exponent fields in "<<16" units (the original keeps (hi >> 4) &
    // 0x07ff0000 so exponent arithmetic mixes with sign-track bits).
    const EXP_SHIFTED_MASK: u32 = 0x07ff_0000;
    let a_exp = (a_hi >> 4) & EXP_SHIFTED_MASK;
    let b_exp = (b_hi >> 4) & EXP_SHIFTED_MASK;

    if a_exp == EXP_SHIFTED_MASK || b_exp == EXP_SHIFTED_MASK {
        // Inf/NaN involved. NaN anywhere -> canonical qNaN.
        let a_nan = a_exp == EXP_SHIFTED_MASK && ((a_hi & 0x000f_ffff) | a_lo) != 0;
        let b_nan = b_exp == EXP_SHIFTED_MASK && ((b_hi & 0x000f_ffff) | b_lo) != 0;
        if a_nan || b_nan {
            return QNAN;
        }
        if a_exp == EXP_SHIFTED_MASK {
            // +-Inf % anything -> qNaN with low word 1.
            return QNAN_LO1;
        }
        // b = +-Inf, a finite: normal a returns unchanged; +-0 returns
        // unchanged; denormal a flushes to +0.
        if a_exp != 0 || (a_hi & 0x7fff_ffff) | a_lo == 0 {
            return a;
        }
        return 0;
    }

    // Sign track: bit 0 = running result sign (flipped whenever the
    // remainder is negated), bit 2 = sign of a (used for zero results).
    let a_negative = a_hi & 0x8000_0000 != 0;
    let mut sign_track: i32 = (b_exp | if a_negative { 5 } else { 0 }) as i32;

    if a_exp == 0 || b_exp == 0 {
        if b_exp != 0 {
            // a is zero/denormal, b normal: +-0 returns unchanged,
            // denormal dividend flushes to +0.
            if (a_hi & 0x7fff_ffff) | a_lo == 0 {
                return a;
            }
            return 0;
        }
        // Zero/denormal divisor -> qNaN with low word 1.
        return QNAN_LO1;
    }

    let mut a_x: i32 = a_exp as i32; // remainder exponent (<<16 units)
    let mut prev_x: i32 = sign_track; // exponent before last subtraction
    let mut b_m1: i32 = sign_track - 0x1_0000; // b exponent - 1 | sign bits

    // Significands with hidden bit restored (top bit = bit 52).
    let mut rem: u64 = ((((a_hi & 0x000f_ffff) as u64) | 0x10_0000) << 32) | a_lo as u64;
    let mut div: u64 = ((((b_hi & 0x000f_ffff) as u64) | 0x10_0000) << 32) | b_lo as u64;

    loop {
        if a_x <= b_m1 {
            // Tail: remainder exponent is below the divisor's.
            if rem == 0 {
                // Exact multiple: signed zero, sign of the dividend.
                return (sign_track as u64 & 4) << 61;
            }
            if a_x >> 16 < b_m1 >> 16 {
                break;
            }
            // a_exp == b_exp - 1: compare significands for the final
            // half-way step.
            if rem > div {
                // rem in [div, 2*div): scale divisor up and subtract.
                div <<= 1;
            } else {
                if rem == div && (prev_x as u32) >> 16 == (a_x as u32) >> 16 {
                    // Exact tie (rem == b/2): round half to even —
                    // flip the result sign when the quotient is odd.
                    sign_track ^= 1;
                }
                break;
            }
        }

        // rem = |rem - div|, flipping the running sign on borrow.
        let diff;
        if rem >= div {
            diff = rem - div;
        } else {
            diff = div - rem;
            sign_track ^= 1;
        }
        prev_x = a_x - 0x1_0000;
        rem = diff;

        // Renormalize so bit 52 is set again.
        let mut hi = (rem >> 32) as u32;
        let mut lo = rem as u32;
        if hi & 0x001e_0000 == 0 {
            // Deep shift (>= 4 places): the original counts via 20/40
            // chunk shifts plus a binary clz; equivalent to a single
            // clz here. diff == 0 shifts 71 places in the original
            // (20 + 20 + 31) — the zero is caught at the tail above,
            // only the exponent debit matters.
            if rem == 0 {
                a_x -= 71 * 0x1_0000;
            } else {
                let shift = 52 - (63 - rem.leading_zeros());
                if shift >= 32 {
                    hi = lo << (shift - 32);
                    lo = 0;
                } else {
                    hi = (hi << shift) | (lo >> (32 - shift));
                    lo <<= shift;
                }
                rem = ((hi as u64) << 32) | lo as u64;
                a_x -= (shift as i32) * 0x1_0000;
            }
        } else {
            while hi & 0x0010_0000 == 0 {
                hi = (hi << 1) | (lo >> 31);
                lo <<= 1;
                a_x -= 0x1_0000;
            }
            rem = ((hi as u64) << 32) | lo as u64;
        }
    }

    // Merge exponent back over the hidden bit and apply the sign.
    // Exponent underflow (denormal remainder) flushes to +0.
    let exp_minus_1 = a_x - 0x1_0000;
    if exp_minus_1 >= 0 {
        let hi = ((rem >> 32) as u32)
            .wrapping_add((exp_minus_1 as u32) << 4)
            ^ ((sign_track as u32) << 31);
        return ((hi as u64) << 32) | (rem & 0xffff_ffff);
    }
    0
}

/// iabs — original @ 0x080e9788 (12 bytes). 32-bit integer absolute
/// value: `cmp r0,#0; rsblt r0,r0,#0; bx lr`. Negative inputs are
/// negated with a 32-bit reverse subtract, so iabs(INT_MIN) wraps to
/// INT_MIN — wrapping_neg mirrors the original exactly.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iabs(x: i32) -> i32 {
    if x < 0 { x.wrapping_neg() } else { x }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const INF: u64 = 0x7ff0_0000_0000_0000;
    const MIN_NORMAL: u64 = 0x0010_0000_0000_0000;
    const MAX_DENORM: u64 = 0x000f_ffff_ffff_ffff;

    fn sqrt(x: u64) -> u64 {
        unsafe { _dsqrt(x) }
    }

    fn dmod(a: u64, b: u64) -> u64 {
        unsafe { __dmod(a, b) }
    }

    /// Host IEEE oracle: aarch64 f64::sqrt is correctly rounded.
    fn host_sqrt(x: u64) -> u64 {
        f64::from_bits(x).sqrt().to_bits()
    }

    /// Host libm remainder(): exact operation, perfect oracle.
    fn host_remainder(a: u64, b: u64) -> u64 {
        extern "C" {
            fn remainder(x: f64, y: f64) -> f64;
        }
        unsafe { remainder(f64::from_bits(a), f64::from_bits(b)) }.to_bits()
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

    // ---- _dsqrt ----

    #[test]
    fn sqrt_perfect_squares() {
        for i in 1..=1000u64 {
            let v = i as f64 * i as f64;
            let bits = v.to_bits();
            assert_eq!(sqrt(bits), (i as f64).to_bits(), "sqrt({v})");
            assert_eq!(sqrt(bits), host_sqrt(bits));
        }
    }

    #[test]
    fn sqrt_directed_normals() {
        let cases: &[u64] = &[
            0x3ff0_0000_0000_0000, // 1.0
            0x4000_0000_0000_0000, // 2.0
            0x3fe0_0000_0000_0000, // 0.5
            MIN_NORMAL,
            0x7fef_ffff_ffff_ffff, // DBL_MAX
            0x3e69_1234_5678_9abc, // random-ish small
            0x7fe0_0000_0000_0001, // just above 2^1023
            0x0010_0000_0000_0001, // just above min normal
        ];
        for &x in cases {
            assert_eq!(sqrt(x), host_sqrt(x), "x={x:#x}");
        }
    }

    #[test]
    fn sqrt_zero_inf_nan_negative() {
        assert_eq!(sqrt(0), 0); // +0
        assert_eq!(sqrt(0x8000_0000_0000_0000), 0x8000_0000_0000_0000); // -0
        assert_eq!(sqrt(INF), INF); // +Inf
        // -Inf -> qNaN with low word 1 (NOT the canonical NaN).
        assert_eq!(sqrt(INF | 0x8000_0000_0000_0000), QNAN_LO1);
        // Negative finite -> qNaN with low word 1.
        assert_eq!(sqrt(0xbff0_0000_0000_0000), QNAN_LO1); // -1.0
        assert_eq!(sqrt(0xc4f8_7654_3210_fedc), QNAN_LO1);
        // NaN inputs -> canonical qNaN, payload and sign dropped.
        assert_eq!(sqrt(0x7ff8_0000_0000_0000), QNAN);
        assert_eq!(sqrt(0x7ff4_0000_dead_beef), QNAN);
        assert_eq!(sqrt(0xfff8_0000_0000_0001), QNAN);
        assert_eq!(sqrt(0x7ff0_0000_0000_0001), QNAN); // sNaN
    }

    #[test]
    fn sqrt_denormals_flush_to_zero() {
        assert_eq!(sqrt(1), 0); // smallest positive denormal -> +0
        assert_eq!(sqrt(MAX_DENORM), 0);
        // Even negative denormals flush to +0 (sign never tested).
        assert_eq!(sqrt(0x8000_0000_0000_0001), 0);
    }

    #[test]
    fn sqrt_random_matches_host() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        for _ in 0..100_000 {
            let x = rng.next() & 0x7fff_ffff_ffff_ffff; // positive only
            if f64::from_bits(x).is_nan() {
                continue; // NaN payload behavior differs by design
            }
            if x != 0 && x < MIN_NORMAL {
                assert_eq!(sqrt(x), 0, "denormal x={x:#x} flushes to +0");
                continue;
            }
            assert_eq!(sqrt(x), host_sqrt(x), "x={x:#x}");
        }
    }

    // ---- __dmod (IEEE remainder core) ----

    #[test]
    fn dmod_is_remainder_not_fmod() {
        // Pin the semantics: quotient rounds to NEAREST, not truncated.
        let five_half = 0x4016_0000_0000_0000u64; // 5.5
        let two = 0x4000_0000_0000_0000u64; // 2.0
        // fmod(5.5, 2) = +1.5, remainder(5.5, 2) = -0.5.
        assert_eq!(dmod(five_half, two), 0xbfe0_0000_0000_0000);
        assert_eq!(dmod(five_half, two), host_remainder(five_half, two));
        // Truncated cases agree with fmod.
        let ten = 0x4024_0000_0000_0000u64;
        let three = 0x4008_0000_0000_0000u64;
        assert_eq!(dmod(ten, three), 0x3ff0_0000_0000_0000); // 1.0
    }

    #[test]
    fn dmod_ties_round_half_even() {
        for &(a, b, expect) in &[
            (2.0f64, 4.0f64, 2.0f64),   // q = 0.5 -> 0 (even): rem = 2
            (6.0f64, 4.0f64, -2.0f64),  // q = 1.5 -> 2 (even): rem = -2
            (10.0f64, 4.0f64, 2.0f64),  // q = 2.5 -> 2 (even): rem = 2
            (14.0f64, 4.0f64, -2.0f64), // q = 3.5 -> 4 (even): rem = -2
            (1.5f64, 1.0f64, -0.5f64),  // q = 1.5 -> 2
            (2.5f64, 1.0f64, 0.5f64),   // q = 2.5 -> 2
            (3.5f64, 1.0f64, -0.5f64),  // q = 3.5 -> 4
        ] {
            let (ab, bb) = (a.to_bits(), b.to_bits());
            assert_eq!(dmod(ab, bb), expect.to_bits(), "remainder({a}, {b})");
            assert_eq!(dmod(ab, bb), host_remainder(ab, bb));
        }
    }

    #[test]
    fn dmod_sign_cases() {
        let a = 5.5f64.to_bits();
        let neg_a = (-5.5f64).to_bits();
        let b = 2.0f64.to_bits();
        let neg_b = (-2.0f64).to_bits();
        // Sign follows the dividend; divisor sign is irrelevant.
        assert_eq!(dmod(a, b), (-0.5f64).to_bits());
        assert_eq!(dmod(a, neg_b), (-0.5f64).to_bits());
        assert_eq!(dmod(neg_a, b), 0.5f64.to_bits());
        assert_eq!(dmod(neg_a, neg_b), 0.5f64.to_bits());
        // Zero results carry the dividend's sign.
        let four = 4.0f64.to_bits();
        assert_eq!(dmod(four, b), 0.0f64.to_bits());
        assert_eq!(dmod((-4.0f64).to_bits(), b), (-0.0f64).to_bits());
        assert_eq!(dmod((-4.0f64).to_bits(), b), host_remainder((-4.0f64).to_bits(), b));
    }

    #[test]
    fn dmod_special_values() {
        let one = 1.0f64.to_bits();
        // x % 0 -> qNaN with low word 1 (payload differs from host).
        assert_eq!(dmod(one, 0), QNAN_LO1);
        assert_eq!(dmod(one, 0x8000_0000_0000_0000), QNAN_LO1); // -0
        assert_eq!(dmod(0, 0), QNAN_LO1); // 0 % 0
        // Inf % x -> qNaN low word 1.
        assert_eq!(dmod(INF, one), QNAN_LO1);
        assert_eq!(dmod(INF | 0x8000_0000_0000_0000, one), QNAN_LO1);
        assert_eq!(dmod(INF, INF), QNAN_LO1); // Inf % Inf
        // NaN anywhere -> canonical qNaN.
        assert_eq!(dmod(0x7ff8_0000_dead_beef, one), QNAN);
        assert_eq!(dmod(one, 0xfff0_0000_0000_0001), QNAN);
        assert_eq!(dmod(0x7ff8_0000_0000_0000, 0x7ff8_0000_0000_0000), QNAN);
        // finite % Inf -> the finite dividend unchanged.
        assert_eq!(dmod(one, INF), one);
        assert_eq!(dmod((-5.5f64).to_bits(), INF | 0x8000_0000_0000_0000), (-5.5f64).to_bits());
        assert_eq!(dmod(0, INF), 0); // +0 % Inf
        assert_eq!(dmod(0x8000_0000_0000_0000, INF), 0x8000_0000_0000_0000); // -0 % Inf
        // +-0 % normal -> signed zero unchanged.
        assert_eq!(dmod(0, one), 0);
        assert_eq!(dmod(0x8000_0000_0000_0000, one), 0x8000_0000_0000_0000);
    }

    #[test]
    fn dmod_denormals() {
        let one = 1.0f64.to_bits();
        // Denormal dividend, normal divisor -> +0 (host gives the
        // denormal itself; the original flushes).
        assert_eq!(dmod(1, one), 0);
        assert_eq!(dmod(MAX_DENORM, one), 0);
        // Denormal divisor flushes to zero -> NaN low word 1.
        assert_eq!(dmod(one, 1), QNAN_LO1);
        assert_eq!(dmod(one, MAX_DENORM), QNAN_LO1);
        assert_eq!(dmod(1, 1), QNAN_LO1); // both denormal
        // Denormal dividend % Inf -> +0.
        assert_eq!(dmod(1, INF), 0);
        // Result that would be denormal flushes to +0: min_normal is an
        // exact multiple of 2^-1040-ish divisors; use remainder of
        // min_normal * 3 by min_normal * 2 -> min_normal (normal), and
        // a genuinely-denormal result: remainder(3 * 2^-1074-ish)...
        // Simpler: remainder(DBL_MIN, 3.0) = DBL_MIN (normal); craft
        // underflow: remainder(min_normal + denorm...) is flushed by
        // input rule, so instead check a normal pair whose remainder
        // underflows: remainder(2^-1022 * (1+2^-52), 2^-1022) = tiny
        // denormal -> +0.
        let x = MIN_NORMAL | 1; // min_normal * (1 + 2^-52)
        assert!(f64::from_bits(host_remainder(x, MIN_NORMAL)) > 0.0); // host: denormal
        assert_eq!(dmod(x, MIN_NORMAL), 0); // original flushes to +0
    }

    #[test]
    fn dmod_random_matches_host_remainder() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        let mut checked = 0u32;
        while checked < 100_000 {
            let a = rng.next() & 0x7fff_ffff_ffff_ffff;
            let b = rng.next() & 0x7fff_ffff_ffff_ffff;
            let (fa, fb) = (f64::from_bits(a), f64::from_bits(b));
            // Skip cases where the original deliberately diverges:
            // NaNs, non-finite, zero/denormal operands (flush rules).
            if !fa.is_finite() || !fb.is_finite() {
                continue;
            }
            // Zero/denormal operands follow flush rules (directed tests).
            if fa == 0.0 || fb == 0.0 || fa.abs() < f64::MIN_POSITIVE || fb.abs() < f64::MIN_POSITIVE
            {
                continue;
            }
            let got = dmod(a, b);
            let want = host_remainder(a, b);
            // Underflowing results flush to +0 in the original.
            if f64::from_bits(want) != 0.0 && f64::from_bits(want).abs() < f64::MIN_POSITIVE {
                assert_eq!(got, 0, "underflow a={a:#x} b={b:#x}");
            } else {
                assert_eq!(got, want, "a={a:#x} b={b:#x}");
            }
            checked += 1;
        }
    }

    #[test]
    fn dmod_extreme_exponent_spans() {
        // Very large % very small exercises the full exponent walk.
        let cases: &[(f64, f64)] = &[
            (1e300, 1e-300),
            (1e-300, 1e300),
            (f64::MAX, f64::MIN_POSITIVE),
            (f64::MIN_POSITIVE, f64::MAX),
            (1.0, f64::MIN_POSITIVE),
            (0.1, 0.03),
            (123456.789, 0.00001234),
        ];
        for &(x, y) in cases {
            let (a, b) = (x.to_bits(), y.to_bits());
            let want = host_remainder(a, b);
            if f64::from_bits(want) != 0.0 && f64::from_bits(want).abs() < f64::MIN_POSITIVE {
                assert_eq!(dmod(a, b), 0, "underflow x={x} y={y}");
            } else {
                assert_eq!(dmod(a, b), want, "x={x} y={y}");
            }
        }
    }

    #[test]
    fn dmod_exact_multiples_ping_pong() {
        // a = b * 2^k for large k walks the rem==div ping-pong path.
        let b = (2.0f64).to_bits();
        for k in [1, 10, 100, 500, 1000] {
            let a = (2.0f64 * 2f64.powi(k)).to_bits();
            assert_eq!(dmod(a, b), 0.0f64.to_bits(), "k={k}");
            assert_eq!(dmod(a, b), host_remainder(a, b));
        }
        // Negative dividend: -0 with dividend sign.
        let a = (-8.0f64).to_bits();
        assert_eq!(dmod(a, b), (-0.0f64).to_bits());
        assert_eq!(dmod(a, b), host_remainder(a, b));
        // Odd multiples land on +-b/2 style residues.
        let mut rng = Rng(0x0ddc_0ffe_e15e_5eed);
        let mut vals: Vec<u64> = Vec::new();
        for _ in 0..1000 {
            let y = f64::from_bits(rng.next() & 0x7fff_ffff_ffff_ffff);
            if !y.is_finite() || y == 0.0 {
                continue;
            }
            let n = (rng.next() % 2000) as i32 - 1000;
            let x = y * n as f64;
            if !x.is_finite() {
                continue;
            }
            let (ab, bb) = (x.to_bits(), y.to_bits());
            let want = host_remainder(ab, bb);
            if f64::from_bits(want) != 0.0 && f64::from_bits(want).abs() < f64::MIN_POSITIVE {
                assert_eq!(dmod(ab, bb), 0);
            } else {
                assert_eq!(dmod(ab, bb), want, "x={x} y={y}");
            }
            vals.push(dmod(ab, bb));
        }
        assert!(!vals.is_empty());
    }

    // ---- iabs ----

    fn abs32(x: i32) -> i32 {
        unsafe { iabs(x) }
    }

    /// Reference: the original's `rsblt r0,r0,#0` is a 32-bit `0 - x`,
    /// which wraps for INT_MIN.
    fn ref_abs(x: i32) -> i32 {
        if x < 0 { 0i32.wrapping_sub(x) } else { x }
    }

    #[test]
    fn iabs_directed() {
        assert_eq!(abs32(0), 0);
        assert_eq!(abs32(1), 1);
        assert_eq!(abs32(-1), 1);
        assert_eq!(abs32(42), 42);
        assert_eq!(abs32(-42), 42);
        assert_eq!(abs32(i32::MAX), i32::MAX);
        assert_eq!(abs32(-i32::MAX), i32::MAX);
        // INT_MIN edge: 0 - INT_MIN wraps back to INT_MIN, matching
        // the original rsb; i32::abs would overflow.
        assert_eq!(abs32(i32::MIN), i32::MIN);
        assert_eq!(abs32(i32::MIN + 1), i32::MAX);
    }

    #[test]
    fn iabs_random_matches_reference() {
        let mut rng = Rng(0x5eed_5eed_5eed_5eed);
        for _ in 0..100_000 {
            let x = rng.next() as i32;
            assert_eq!(abs32(x), ref_abs(x), "x={x}");
            assert_eq!(abs32(x), x.wrapping_abs(), "x={x}");
        }
    }
}
