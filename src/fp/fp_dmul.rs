//! Port of the ARM ADS 1.0.1 soft-float double multiply.
//!
//! retailOS is SOFT-FLOAT: doubles travel as u64 bit patterns (r0:r1
//! register pairs). This module does pure integer bit manipulation — no
//! f64 arithmetic, which would lower to unported __aeabi_d* helpers.
//! The 52x52 mantissa product uses u32-limb widening multiplies, which
//! LLVM lowers to inline `umull` on armv5te (no __aeabi_lmul exists).
//!
//! Algorithm of the original: split both mantissas into u32 halves,
//! restore the hidden bit, form the 106-bit product as three u32 words
//! (4x umull; the low word of lo*lo folds in as a sticky bit), normalize
//! by 20 or 21 places depending on the top product bit, add the biased
//! exponent (via the hidden-bit carry trick), then round to nearest-even
//! using a guard/sticky word. Exponent overflow yields +-Inf, underflow
//! flushes to zero.
//!
//! Behavioral deviations from IEEE 754, mirrored from the original:
//! - Underflow flushes to +0.0 ALWAYS — the sign of the product is
//!   dropped (the original executes `movlt r1, #0`). It never produces
//!   a denormal result.
//! - A zero/denormal INPUT flushes the product to a signed zero whose
//!   sign is `signA ^ signB`, XORed once more for each operand that is a
//!   *negative denormal* (the original's `cmp r5, rN, lsr #19` quirk).
//!   So (-denormal) * (+normal) = +0 and (-denormal) * (-normal) = -0.
//! - Inf * (zero or denormal) returns the NaN 0x7ff80000_00000001
//!   (Inf * denormal is Inf in IEEE, NaN here).
//! - Any NaN input returns the canonical quiet NaN 0x7ff80000_00000000;
//!   input payload and sign are not propagated. (The original tail-calls
//!   a shared exception stub that returns immediately for the runtime
//!   fp-status word 0x04000013 — no traps.)
//!
//! Behavioral verification: host-side `cargo test` compares against
//! native aarch64 f64 multiplication (IEEE round-to-nearest-even oracle)
//! for all cases where the original is IEEE-conformant, plus directed
//! tests pinning the deviations above; `tools/match.py` (ipod-decomp)
//! reports the mnemonic-level diff against the original machine code.

/// Canonical quiet NaN returned for any NaN input (hi 0x7ff80000, lo 0).
const QNAN: u64 = 0x7ff8_0000_0000_0000;

/// NaN returned for Inf * (zero|denormal) (hi 0x7ff80000, lo 1).
const QNAN_INF_TIMES_ZERO: u64 = 0x7ff8_0000_0000_0001;

/// __dmul — original: `FUN_083eba48` @ 0x083eba48 (448 bytes, 106
/// callers — the hottest fp op in retailOS).
///
/// Doubles are u64 bit patterns (soft-float). Multiplies the 53-bit
/// mantissas as a 106-bit product, normalizes, and rounds to
/// nearest-even. See the module header for the non-IEEE edge behavior
/// that is mirrored from the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __dmul(a: u64, b: u64) -> u64 {
    let a_hi = (a >> 32) as u32;
    let a_lo = a as u32;
    let b_hi = (b >> 32) as u32;
    let b_lo = b as u32;

    let a_exp = (a_hi >> 20) & 0x7ff;
    let b_exp = (b_hi >> 20) & 0x7ff;

    // Either exponent field all ones: Inf or NaN involved.
    if a_exp == 0x7ff || b_exp == 0x7ff {
        let a_nan = a_exp == 0x7ff && ((a_hi & 0xf_ffff) | a_lo) != 0;
        let b_nan = b_exp == 0x7ff && ((b_hi & 0xf_ffff) | b_lo) != 0;
        if a_nan || b_nan {
            return QNAN;
        }
        // Inf present, no NaNs. The original treats any operand with a
        // zero exponent field (zero OR denormal) as a NaN producer here.
        if a_exp == 0 || b_exp == 0 {
            return QNAN_INF_TIMES_ZERO;
        }
        let sign = (a_hi ^ b_hi) & 0x8000_0000;
        return ((sign | 0x7ff0_0000) as u64) << 32;
    }

    // Zero or denormal input: flush the product to a signed zero. The
    // sign is flipped once per negative-denormal operand (original
    // quirk: `cmp 0x1001, rN >> 19; eoreq sign, #1`).
    if a_exp == 0 || b_exp == 0 {
        let mut sign = (a_hi ^ b_hi) >> 31;
        if is_negative_denormal(a_hi, a_lo) {
            sign ^= 1;
        }
        if is_negative_denormal(b_hi, b_lo) {
            sign ^= 1;
        }
        return (sign as u64) << 63;
    }

    // Both operands normal.
    let sign = ((a_hi ^ b_hi) & 0x8000_0000) as u64;

    // Restore hidden bits; mantissas are a_mant_hi:a_lo, 53 bits each.
    let a_mant_hi = (a_hi & 0xf_ffff) | 0x10_0000;
    let b_mant_hi = (b_hi & 0xf_ffff) | 0x10_0000;

    // 53x53 -> 106-bit product as three u32 words (bits 32..105); the
    // low 32 bits of a_lo*b_lo fold into bit 0 as the sticky bit.
    let cross_lo = a_lo as u64 * b_lo as u64;
    let cross_mid = a_lo as u64 * b_mant_hi as u64
        + a_mant_hi as u64 * b_lo as u64
        + (cross_lo >> 32);
    let cross_hi = a_mant_hi as u64 * b_mant_hi as u64 + (cross_mid >> 32);

    let prod_top = (cross_hi >> 32) as u32; // product bits 96..105
    let prod_mid = cross_hi as u32; // bits 64..95
    let prod_low = (cross_mid as u32) | ((cross_lo as u32 != 0) as u32); // 32..63 + sticky

    // Normalize: product in [1,4). Top word >= 0x200 means bit 105 set,
    // i.e. product >= 2: take one more bit and bump the exponent.
    let product_ge_two = prod_top >= 0x200;
    let shift = if product_ge_two { 21 } else { 20 };
    let mant_hi = (prod_top << (32 - shift)) | (prod_mid >> shift);
    let mant_lo = (prod_mid << (32 - shift)) | (prod_low >> shift);
    // Guard bit in bit 31, everything below it sticky.
    let round_bits = prod_low << (32 - shift);
    let mut mantissa = ((mant_hi as u64) << 32) | mant_lo as u64;

    // Biased result exponent, before rounding.
    let exp = a_exp as i32 + b_exp as i32 - 1023 + product_ge_two as i32;

    // Round to nearest, ties to even: increment when the guard bit is
    // set; on an exact tie (guard set, no sticky) clear bit 0 after.
    if round_bits != 0 && round_bits >> 31 != 0 {
        mantissa += 1;
        if round_bits << 1 == 0 {
            mantissa &= !1;
        }
    }

    // Underflow, checked on the pre-rounding exponent like the original:
    // flush to +0.0 (the original drops the sign: `movlt r1, #0`).
    if exp <= 0 {
        return 0;
    }

    // A mantissa of all ones plus a round-up ripples the hidden bit into
    // the exponent field; mantissa >> 52 is then 2 instead of 1.
    let exp_field = exp - 1 + (mantissa >> 52) as i32;
    if exp_field >= 0x7ff {
        // Overflow: +-Inf with the product sign.
        return (sign << 32) | 0x7ff0_0000_0000_0000;
    }

    (sign << 32) | ((exp_field as u64) << 52) | (mantissa & 0xf_ffff_ffff_ffff)
}

/// True for a negative denormal bit pattern (sign set, exponent field
/// zero, mantissa nonzero).
fn is_negative_denormal(hi: u32, lo: u32) -> bool {
    hi & 0x8000_0000 != 0 && hi & 0x7ff0_0000 == 0 && ((hi & 0xf_ffff) | lo) != 0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn mul(a: u64, b: u64) -> u64 {
        unsafe { __dmul(a, b) }
    }

    /// Host IEEE oracle (aarch64 f64 mul, round-to-nearest-even).
    fn host(a: u64, b: u64) -> u64 {
        (f64::from_bits(a) * f64::from_bits(b)).to_bits()
    }

    const INF: u64 = 0x7ff0_0000_0000_0000;

    #[test]
    fn normals_match_host() {
        let cases: &[(u64, u64)] = &[
            (0x3ff8_0000_0000_0000, 0x4002_0000_0000_0000), // 1.5 * 2.25
            (0x4008_0000_0000_0000, 0xc01c_0000_0000_0000), // 3.0 * -7.0
            (0x3ff0_0000_0000_0000, 0x3ff0_0000_0000_0000), // 1.0 * 1.0
            (0x7fef_ffff_ffff_ffff, 0x3fe0_0000_0000_0000), // DBL_MAX * 0.5
            (0x0010_0000_0000_0000, 0x3ff0_0000_0000_0000), // min normal * 1
            (0x3e69_1234_5678_9abc, 0x41ff_edcb_a987_6543), // random-ish
            (0x43e0_0000_0000_0001, 0x3c90_0000_0000_0001), // huge * tiny
            (0xbff0_0000_0000_0001, 0x3ff0_0000_0000_0001), // just off 1.0
        ];
        for &(a, b) in cases {
            assert_eq!(mul(a, b), host(a, b), "a={a:#x} b={b:#x}");
            assert_eq!(mul(b, a), host(b, a), "commuted a={a:#x} b={b:#x}");
        }
    }

    /// Exact ties (guard bit set, sticky clear) round to even. Cases
    /// verified numerically against the host oracle.
    #[test]
    fn ties_round_to_even() {
        // Tie with odd mantissa, product < 2 (shift-20 path): round up.
        // ma = 2^52 + 2^26, mb = 2^52 + 3*2^25.
        let a = 0x3ff0_0000_0400_0000u64;
        let b = 0x3ff0_0000_0600_0000u64;
        assert_eq!(mul(a, b), 0x3ff0_0000_0a00_0002);
        assert_eq!(mul(a, b), host(a, b));

        // Tie with EVEN mantissa, product < 2: round down (no change).
        // ma = 2^52 + 2^26, mb = 2^52 + 2^25.
        let b = 0x3ff0_0000_0200_0000u64;
        assert_eq!(mul(a, b), 0x3ff0_0000_0600_0000);
        assert_eq!(mul(a, b), host(a, b));

        // Tie with odd mantissa, product >= 2 (shift-21 path): round up.
        // ma = 2^52 + 2^26, mb = 2^53 - 2^26.
        let b = 0x3fff_ffff_fc00_0000u64;
        assert_eq!(mul(a, b), 0x4000_0000_0200_0000);
        assert_eq!(mul(a, b), host(a, b));

        // Tie with EVEN mantissa, product >= 2: round down.
        // 1.5 * (1.5 + 3*2^-52).
        let a = 0x3ff8_0000_0000_0000u64;
        let b = 0x3ff8_0000_0000_0003u64;
        assert_eq!(mul(a, b), 0x4002_0000_0000_0002);
        assert_eq!(mul(a, b), host(a, b));

        // Sticky bit below the guard forces round-up of an odd mantissa.
        let a = 0x3ff0_0000_0000_0001u64; // (1+2^-52)^2 = 1+2^-51+2^-104
        assert_eq!(mul(a, a), host(a, a));
        assert_eq!(mul(a, a), 0x3ff0_0000_0000_0002);
    }

    #[test]
    fn overflow_to_infinity() {
        let max = 0x7fef_ffff_ffff_ffffu64; // DBL_MAX
        let two = 0x4000_0000_0000_0000u64;
        assert_eq!(mul(max, two), INF);
        assert_eq!(mul(max, two), host(max, two));
        assert_eq!(mul(max | 1 << 63, two), INF | 1 << 63); // -DBL_MAX * 2
        assert_eq!(mul(max | 1 << 63, two), host(max | 1 << 63, two));
        // Rounding ripple pushes 0x7fe mantissa all-ones over the edge.
        let near_max = 0x7fef_ffff_ffff_ffffu64;
        let up = 0x3ff0_0000_0000_0001u64; // 1 + 2^-52
        assert_eq!(mul(near_max, up), host(near_max, up));
    }

    /// Underflow flushes to +0.0 — always, dropping the sign. The
    /// original never emits a denormal result. These intentionally do
    /// NOT match the host (IEEE) oracle.
    #[test]
    fn underflow_flushes_to_positive_zero() {
        let min_normal = 0x0010_0000_0000_0000u64;
        let half = 0x3fe0_0000_0000_0000u64;
        assert_eq!(mul(min_normal, half), 0); // host: min denormal
        assert_eq!(mul(min_normal | 1 << 63, half), 0); // sign dropped!

        // True product just below 2^-1022 that IEEE rounds UP to the
        // smallest normal; the original flushes on the pre-round exponent.
        let below = 0x3fef_ffff_ffff_ffffu64; // 1 - 2^-53
        assert_eq!(mul(min_normal, below), 0); // host: min normal

        // Barely-normal results still work: min_normal * (2 - 2^-52).
        let almost_two = 0x3fff_ffff_ffff_ffffu64;
        assert_eq!(mul(min_normal, almost_two), host(min_normal, almost_two));
    }

    #[test]
    fn infinity_and_nan_specials() {
        let one = 0x3ff0_0000_0000_0000u64;
        // Inf * Inf and Inf * finite: +-Inf by sign xor.
        assert_eq!(mul(INF, INF), INF);
        assert_eq!(mul(INF, INF | 1 << 63), INF | 1 << 63);
        assert_eq!(mul(INF | 1 << 63, INF | 1 << 63), INF);
        assert_eq!(mul(INF, one), INF);
        assert_eq!(mul(INF | 1 << 63, one), INF | 1 << 63);
        assert_eq!(mul(INF, one | 1 << 63), INF | 1 << 63);

        // Inf * 0 -> NaN 0x7ff80000_00000001 (sign-independent).
        assert_eq!(mul(INF, 0), QNAN_INF_TIMES_ZERO);
        assert_eq!(mul(INF | 1 << 63, 1 << 63), QNAN_INF_TIMES_ZERO);
        assert_eq!(mul(0, INF), QNAN_INF_TIMES_ZERO);

        // Quirk: Inf * denormal is also that NaN (IEEE says Inf).
        assert_eq!(mul(INF, 1), QNAN_INF_TIMES_ZERO);
        assert_eq!(mul(0x000f_ffff_ffff_ffff, INF | 1 << 63), QNAN_INF_TIMES_ZERO);

        // Any NaN input -> canonical qNaN, payload/sign not propagated.
        let nan = 0x7ff8_1234_5678_9abcu64;
        let neg_nan = 0xfff4_0000_0000_0000u64;
        assert_eq!(mul(nan, one), QNAN);
        assert_eq!(mul(neg_nan, INF), QNAN);
        assert_eq!(mul(nan, neg_nan), QNAN);
        assert_eq!(mul(nan, 0), QNAN); // NaN beats the Inf*0 rule? no Inf here
        assert_eq!(mul(INF, nan), QNAN); // NaN beats Inf
    }

    /// Zero/denormal INPUTS flush the product to a signed zero, with the
    /// negative-denormal sign-XOR quirk mirrored from the original.
    #[test]
    fn denormal_inputs_flush_with_sign_quirk() {
        let one = 0x3ff0_0000_0000_0000u64;
        let denorm = 0x0008_0000_0000_0001u64;
        let neg_denorm = denorm | 1 << 63;

        // Plain zeros follow sign xor, IEEE-conformant.
        assert_eq!(mul(0, one), 0);
        assert_eq!(mul(0, one | 1 << 63), 1 << 63);
        assert_eq!(mul(1 << 63, one | 1 << 63), 0);

        // Positive denormal: sign xor only.
        assert_eq!(mul(denorm, one), 0);
        assert_eq!(mul(denorm, one | 1 << 63), 1 << 63);

        // Negative denormal flips the sign once more (quirk).
        assert_eq!(mul(neg_denorm, one), 0); // IEEE: -0
        assert_eq!(mul(neg_denorm, one | 1 << 63), 1 << 63); // IEEE: +0
        assert_eq!(mul(neg_denorm, neg_denorm), 0); // two flips cancel
        assert_eq!(mul(neg_denorm, 1 << 63), 1 << 63); // -denorm * -0 -> -0 (quirk; IEEE: +0)

        // Lo-word-only denormal is still a denormal (flip applies).
        assert_eq!(mul(1 | 1 << 63, one), 0);
        assert_eq!(mul(denorm & 0x0000_0000_ffff_ffff, one | 1 << 63), 1 << 63);
    }

    /// xorshift64* PRNG, deterministic across hosts.
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

    /// 100k random normal-range pairs: exact bit equality with the host
    /// f64 oracle. Pairs whose IEEE result underflows to a denormal are
    /// skipped (the original flushes those to +0 — pinned separately).
    #[test]
    fn random_pairs_match_host() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut checked = 0u32;
        let mut skipped = 0u32;
        while checked < 100_000 {
            let a = rng.next();
            let b = rng.next();
            let a_exp = (a >> 52) & 0x7ff;
            let b_exp = (b >> 52) & 0x7ff;
            // Both operands normal (denormal/Inf/NaN pinned elsewhere).
            if a_exp == 0 || a_exp == 0x7ff || b_exp == 0 || b_exp == 0x7ff {
                continue;
            }
            let want = host(a, b);
            // Skip pairs the original flushes to +0: anything whose
            // pre-rounding exponent is <= 0 (IEEE gives a denormal or
            // the rounded-up smallest normal; deviation pinned above).
            if a_exp + b_exp <= 1023 {
                skipped += 1;
                continue;
            }
            assert!((want >> 52) & 0x7ff != 0, "filter leak {want:#x}");
            assert_eq!(mul(a, b), want, "a={a:#x} b={b:#x}");
            checked += 1;
        }
        // Sanity: the exponent filter must not skew the sample away.
        assert!(skipped < 50_000, "too many skipped: {skipped}");
    }

    /// Exhaustive sweep over a dense grid of exponent/mantissa shapes,
    /// biased toward the rounding and overflow boundaries.
    #[test]
    fn grid_near_boundaries() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        let mut mantissas: Vec<u64> = vec![
            0,
            1,
            2,
            0x000f_ffff_ffff_ffff,
            0x000f_ffff_ffff_fffe,
            0x0008_0000_0000_0000,
            0x0008_0000_0000_0001,
            0x0000_0000_0000_0003,
        ];
        for _ in 0..24 {
            mantissas.push(rng.next() & 0x000f_ffff_ffff_ffff);
        }
        let exps: [u64; 8] = [1, 2, 0x3fe, 0x3ff, 0x400, 0x7fd, 0x7fe, 0x555];
        for &ea in &exps {
            for &eb in &exps {
                for ma in &mantissas[..12] {
                    for mb in &mantissas[..12] {
                        let a = ea << 52 | ma;
                        let b = eb << 52 | mb;
                        if ea + eb <= 1023 {
                            continue; // underflow flush deviation
                        }
                        let want = host(a, b);
                        assert_eq!(mul(a, b), want, "a={a:#x} b={b:#x}");
                        let an = a | 1 << 63;
                        assert_eq!(mul(an, b), host(an, b), "neg a={an:#x} b={b:#x}");
                    }
                }
            }
        }
    }
}
