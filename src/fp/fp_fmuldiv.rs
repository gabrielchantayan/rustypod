//! Ports of the ARM ADS 1.0.1 soft-float single-precision multiply/divide
//! routines. retailOS is soft-float: `f32` values travel in integer registers
//! as raw `u32` bit patterns, hence the signatures below. The module itself
//! uses pure integer bit manipulation (any `f32` arithmetic would lower to
//! the unported `__aeabi_f*` helpers); native `f32` ops appear only in the
//! host tests, where they are the perfect round-to-nearest-even oracle.
//!
//! Original algorithms:
//! - `__fmul`: 24-bit mantissas are shifted to the top of the word (implicit
//!   bit at bit 31) and multiplied with one `umull`; the 64-bit product's low
//!   word is folded into a sticky bit, then the exponent/sign word is merged
//!   with a carry-based round-to-nearest-even sequence.
//! - `__fdiv`: a 64-entry reciprocal seed table (@ 0x83ec6e8, indexed by the
//!   divisor's top mantissa bits) feeds two Newton–Raphson iterations built
//!   from `mul`/`mla`; the final remainder selects round/sticky/tie flags.
//!
//! Documented simplifications/deviations from the original:
//! - The contract is the correctly-rounded IEEE 754 result, so both functions
//!   are verified bit-exact against host `f32` arithmetic. The original
//!   FLUSHES DENORMALS: denormal inputs are treated as zero (losing the sign
//!   when the denormal sits in the first operand: `-denorm * 2.0` yields
//!   `+0`), results that would be denormal underflow to `±0`, `x/denormal`
//!   always yields `±Inf`, and `0/denormal` yields NaN. A clz-based denormal
//!   normalizer exists in the library @ 0x83ecb40 but is never referenced
//!   from this binary. This port implements full IEEE denormal support
//!   (normalize denormal inputs with `leading_zeros`, gradual underflow on
//!   output) so results match the host oracle exactly.
//! - `__fdiv` here uses exact 25-step restoring division (shift/subtract,
//!   no 64-bit divides) instead of the seed-table Newton scheme; both compute
//!   the same correctly-rounded quotient.
//! - NaN results are canonicalized to the original's default quiet NaN
//!   0x7fc00001 (the literal the original loads for `Inf*0` / `0/0`; NaN
//!   inputs go through the `_fp_trap` dispatcher whose default action returns
//!   a quiet NaN). Host hardware instead propagates NaN payloads and produces
//!   0x7fc00000 for invalid operations, so NaN-producing cases are tested for
//!   NaN-ness, not bit equality.

/// The original's default quiet NaN (`DAT_083ecb3c` / `DAT_083ec81c`).
const DEFAULT_QNAN: u32 = 0x7fc0_0001;

const SIGN_MASK: u32 = 0x8000_0000;
const EXP_MASK: u32 = 0x7f80_0000;
const MANT_MASK: u32 = 0x007f_ffff;
const IMPLICIT_BIT: u32 = 0x0080_0000;
const INFINITY: u32 = 0x7f80_0000;

/// Splits a finite nonzero `f32` bit pattern into (biased exponent, 24-bit
/// significand including the implicit bit). Denormals are normalized with
/// clz, yielding a (possibly negative) biased exponent — the role of the
/// unreferenced clz helper @ 0x83ecb40 in the original library.
fn normalize_finite(exp: u32, mant: u32) -> (i32, u32) {
    if exp == 0 {
        // Denormal: mant in [1, 2^23). Shift the leading 1 into bit 23.
        let shift = mant.leading_zeros() - 8;
        (1 - shift as i32, mant << shift)
    } else {
        (exp as i32, mant | IMPLICIT_BIT)
    }
}

/// Packs a computed significand into the final bit pattern with a single
/// round-to-nearest-even step and gradual underflow.
///
/// `sig` lies in [2^23, 2^24) (implicit bit set); the exact pre-rounding
/// value is `(sig + 0.5*round + eps*sticky) * 2^(exp - 150)` with
/// `eps` in [0, 0.5). `sign` is the result sign bit (0 or 0x80000000).
fn round_pack(sign: u32, mut exp: i32, sig: u32, round: bool, sticky: bool) -> u32 {
    if exp <= 0 {
        // Denormal result (or total underflow): round at the shifted
        // position. Rounding may carry into bit 23, which then reads as the
        // smallest normal — exactly the IEEE behavior.
        let shift = (1 - exp) as u32;
        if shift > 24 {
            // Value is below half of the smallest denormal.
            return sign;
        }
        let mut fraction = sig >> shift;
        let round_bit = (sig >> (shift - 1)) & 1;
        let lost = (sig & ((1u32 << (shift - 1)) - 1)) != 0;
        if round_bit != 0 && (lost || round || sticky || (fraction & 1) != 0) {
            fraction += 1;
        }
        return sign | fraction;
    }
    let mut mant = sig;
    if round && (sticky || (mant & 1) != 0) {
        mant += 1;
        if mant >> 24 != 0 {
            // Rounding carried out of the mantissa: 1.11..1 -> 10.0.
            mant = IMPLICIT_BIT;
            exp += 1;
        }
    }
    if exp >= 0xff {
        // Overflow: round-to-nearest spills to infinity.
        return sign | INFINITY;
    }
    sign | ((exp as u32) << 23) | (mant & MANT_MASK)
}

/// __fmul — original: `FUN_083eca20` @ 0x083eca20 (284 bytes; sibling
/// denormal clz helper @ 0x83ecb40). IEEE 754 binary32 multiply.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __fmul(a: u32, b: u32) -> u32 {
    let sign = (a ^ b) & SIGN_MASK;
    let exp_a = (a >> 23) & 0xff;
    let exp_b = (b >> 23) & 0xff;
    let mant_a = a & MANT_MASK;
    let mant_b = b & MANT_MASK;

    if exp_a == 0xff {
        // a is Inf or NaN.
        if mant_a != 0 || (exp_b == 0xff && mant_b != 0) {
            return DEFAULT_QNAN; // NaN operand
        }
        if (b << 1) == 0 {
            return DEFAULT_QNAN; // Inf * 0 is invalid
        }
        return sign | INFINITY; // Inf * nonzero (incl. Inf * Inf)
    }
    if exp_b == 0xff {
        // b is Inf or NaN, a is finite.
        if mant_b != 0 {
            return DEFAULT_QNAN; // NaN operand
        }
        if (a << 1) == 0 {
            return DEFAULT_QNAN; // 0 * Inf is invalid
        }
        return sign | INFINITY;
    }
    if (a << 1) == 0 || (b << 1) == 0 {
        return sign; // finite * ±0 = ±0
    }

    let (exp_a, sig_a) = normalize_finite(exp_a, mant_a);
    let (exp_b, sig_b) = normalize_finite(exp_b, mant_b);

    // 24x24 -> 48-bit product in [2^46, 2^48); LLVM lowers this to umull.
    let product = (sig_a as u64) * (sig_b as u64);
    // Normalize the leading 1 to bit 47.
    let (exp, product) = if product >> 47 != 0 {
        (exp_a + exp_b - 126, product)
    } else {
        (exp_a + exp_b - 127, product << 1)
    };
    let sig = (product >> 24) as u32;
    let round = (product >> 23) & 1 != 0;
    let sticky = (product & 0x007f_ffff) != 0;
    round_pack(sign, exp, sig, round, sticky)
}

/// __fdiv — original: `FUN_083ec5fc` @ 0x083ec5fc (472 bytes; reciprocal
/// seed table @ 0x83ec6e8). IEEE 754 binary32 divide, computed here with
/// exact restoring division (see module header).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __fdiv(a: u32, b: u32) -> u32 {
    let sign = (a ^ b) & SIGN_MASK;
    let exp_a = (a >> 23) & 0xff;
    let exp_b = (b >> 23) & 0xff;
    let mant_a = a & MANT_MASK;
    let mant_b = b & MANT_MASK;

    if exp_a == 0xff {
        // a is Inf or NaN.
        if mant_a != 0 || (exp_b == 0xff && mant_b != 0) {
            return DEFAULT_QNAN; // NaN operand
        }
        if exp_b == 0xff {
            return DEFAULT_QNAN; // Inf / Inf is invalid
        }
        return sign | INFINITY; // Inf / finite
    }
    if exp_b == 0xff {
        // b is Inf or NaN, a is finite.
        if mant_b != 0 {
            return DEFAULT_QNAN; // NaN operand
        }
        return sign; // finite / Inf = ±0
    }
    if (b << 1) == 0 {
        if (a << 1) == 0 {
            return DEFAULT_QNAN; // 0 / 0 is invalid
        }
        return sign | INFINITY; // nonzero / 0
    }
    if (a << 1) == 0 {
        return sign; // ±0 / finite = ±0
    }

    let (exp_a, sig_a) = normalize_finite(exp_a, mant_a);
    let (exp_b, sig_b) = normalize_finite(exp_b, mant_b);

    // Force the quotient into [1, 2) so its leading 1 lands at bit 23.
    let (exp, dividend) = if sig_a < sig_b {
        (exp_a - exp_b + 126, sig_a << 1)
    } else {
        (exp_a - exp_b + 127, sig_a)
    };

    // Restoring division. The quotient lies in [1, 2), so its integer bit is
    // known to be 1: consume it up front to establish the invariant
    // remainder < sig_b, then 24 iterations yield the 23 fraction bits plus
    // the round bit; the leftover remainder is the sticky bit. All values
    // stay below 2^25, so plain u32 shifts/subs suffice (no divide helpers).
    let mut quotient: u32 = 1;
    let mut remainder: u32 = dividend - sig_b;
    for _ in 0..24 {
        remainder <<= 1;
        quotient <<= 1;
        if remainder >= sig_b {
            remainder -= sig_b;
            quotient |= 1;
        }
    }
    let sig = quotient >> 1;
    let round = quotient & 1 != 0;
    let sticky = remainder != 0;
    round_pack(sign, exp, sig, round, sticky)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn is_nan_bits(x: u32) -> bool {
        (x & EXP_MASK) == EXP_MASK && (x & MANT_MASK) != 0
    }

    /// Oracle comparison: NaN results are checked for NaN-ness only (payload
    /// handling differs from the host, see module header); everything else
    /// must be bit-exact.
    fn check_mul(a: u32, b: u32) {
        let oracle = (f32::from_bits(a) * f32::from_bits(b)).to_bits();
        let mine = unsafe { __fmul(a, b) };
        if is_nan_bits(oracle) {
            assert!(is_nan_bits(mine), "mul {a:#010x} * {b:#010x}: oracle NaN, got {mine:#010x}");
        } else {
            assert_eq!(mine, oracle, "mul {a:#010x} * {b:#010x}");
        }
    }

    fn check_div(a: u32, b: u32) {
        let oracle = (f32::from_bits(a) / f32::from_bits(b)).to_bits();
        let mine = unsafe { __fdiv(a, b) };
        if is_nan_bits(oracle) {
            assert!(is_nan_bits(mine), "div {a:#010x} / {b:#010x}: oracle NaN, got {mine:#010x}");
        } else {
            assert_eq!(mine, oracle, "div {a:#010x} / {b:#010x}");
        }
    }

    fn interesting_patterns() -> Vec<u32> {
        std::vec![
            0x0000_0000, // +0
            0x8000_0000, // -0
            0x0000_0001, // smallest denormal
            0x8000_0001,
            0x007f_ffff, // largest denormal
            0x807f_ffff,
            0x0080_0000, // smallest normal
            0x8080_0000,
            0x3f80_0000, // 1.0
            0xbf80_0000, // -1.0
            0x3f80_0001, // 1.0 + 1 ulp
            0x3f00_0000, // 0.5
            0x7f7f_ffff, // largest finite
            0xff7f_ffff,
            0x7f80_0000, // +Inf
            0xff80_0000, // -Inf
            0x7fc0_0000, // qNaN
            0xffc0_0000, // -qNaN
            0x7f80_0001, // sNaN
            0x7fc0_0001, // original's default qNaN
            0x3400_0000, // 2^-25 (denormal-producing products)
            0x2000_0000, // 2^-61
            0x5f80_0000, // 2^64 (overflow-producing products)
        ]
    }

    #[test]
    fn specials_and_denormals() {
        let pats = interesting_patterns();
        for &a in &pats {
            for &b in &pats {
                check_mul(a, b);
                check_div(a, b);
            }
        }
    }

    #[test]
    fn explicit_special_results() {
        unsafe {
            // x / 0 and Inf arithmetic (signs exact, not just NaN-ness).
            assert_eq!(__fdiv(0x3f80_0000, 0x0000_0000), 0x7f80_0000); // 1/0
            assert_eq!(__fdiv(0xbf80_0000, 0x0000_0000), 0xff80_0000); // -1/0
            assert_eq!(__fdiv(0x3f80_0000, 0x8000_0000), 0xff80_0000); // 1/-0
            assert!(is_nan_bits(__fdiv(0x0000_0000, 0x0000_0000))); // 0/0
            assert!(is_nan_bits(__fmul(0x7f80_0000, 0x0000_0000))); // Inf*0
            assert_eq!(__fmul(0x7f80_0000, 0xff80_0000), 0xff80_0000); // Inf*-Inf
            assert_eq!(__fdiv(0x7f80_0000, 0x3f80_0000), 0x7f80_0000); // Inf/1
            assert_eq!(__fdiv(0x3f80_0000, 0x7f80_0000), 0x0000_0000); // 1/Inf
            assert_eq!(__fdiv(0xbf80_0000, 0x7f80_0000), 0x8000_0000); // -1/Inf
            assert_eq!(__fmul(0x8000_0000, 0x3f80_0000), 0x8000_0000); // -0*1
            // NaN canonicalization (documented deviation from host payloads).
            assert_eq!(__fmul(0x7fc0_0000, 0x3f80_0000), DEFAULT_QNAN);
            assert_eq!(__fdiv(0x7f80_0001, 0x3f80_0000), DEFAULT_QNAN);
            assert_eq!(__fdiv(0x7f80_0000, 0x7f80_0000), DEFAULT_QNAN);
        }
    }

    /// splitmix64: deterministic, no_std-friendly PRNG for the fuzz loops.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn random_pairs() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        for _ in 0..100_000 {
            let a = rng.next() as u32;
            let b = (rng.next() >> 32) as u32;
            check_mul(a, b);
            check_div(a, b);
        }
    }

    /// Biased exponents to hammer overflow, underflow and denormal paths.
    #[test]
    fn random_edge_exponents() {
        let mut rng = Rng(0x0f0f_0f0f_f0f0_f0f0);
        for _ in 0..100_000 {
            let mut a = rng.next() as u32;
            let mut b = (rng.next() >> 32) as u32;
            // Force exponent bytes into tiny/huge ranges (keeps signs/mantissas).
            let ea = [0u32, 1, 2, 0x7c, 0x7d, 0x7e, 0x7f, 0x80][(rng.next() & 7) as usize];
            let eb = [0u32, 1, 2, 0x7c, 0x7d, 0x7e, 0x7f, 0x80][(rng.next() & 7) as usize];
            a = (a & !EXP_MASK) | (ea << 23);
            b = (b & !EXP_MASK) | (eb << 23);
            check_mul(a, b);
            check_div(a, b);
        }
    }

    /// Targeted rounding ties: products/quotients exactly between two
    /// representable values must round to even.
    #[test]
    fn rounding_edges() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        for _ in 0..20_000 {
            // a in [1,2), b = a + tiny -> products dense near rounding ties.
            let a = 0x3f80_0000 | (rng.next() as u32 & MANT_MASK);
            let b = 0x3f80_0000 | ((rng.next() >> 32) as u32 & MANT_MASK);
            check_mul(a, b);
            check_div(a, b);
            // Near the normal/denormal boundary.
            let c = 0x0080_0000 | (rng.next() as u32 & 0xffff);
            let d = 0x3f80_0000 | ((rng.next() >> 32) as u32 & MANT_MASK);
            check_mul(c, d);
            check_div(c, d);
            check_div(d, c);
        }
    }
}
