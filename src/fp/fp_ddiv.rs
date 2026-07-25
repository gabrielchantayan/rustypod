//! Port of the ARM ADS 1.0.1 soft-float double division routine.
//!
//! Originals (retailOS, soft-float: doubles travel as raw `u64` bit
//! patterns, never as `f64`):
//! - `__ddiv`     @ 0x083eb238 (516 bytes, 39 callers) — special-case
//!   handling (NaN/Inf/zero/denormal), exponent assembly, sticky
//!   round-to-nearest-even.
//! - `_ddiv_core` @ 0x083eb45c (600 bytes) — the divider proper: a 256-byte
//!   reciprocal seed table (`ldrb`) followed by Newton-Raphson `mla`/`mul`
//!   refinement producing a 56-bit quotient plus remainder.
//!
//! Deliberate implementation choice: `_ddiv_core`'s Newton-Raphson estimate
//! is an internal detail — its only observable contract is the final
//! correctly-rounded IEEE 754 quotient. This port replaces it with classic
//! shift-subtract restoring division on the 53-bit significands
//! (`divide_significands`), which is far easier to audit for exact rounding.
//! The seed table bytes are therefore not extracted. The `__ddiv` wrapper
//! semantics (rounding, special cases, NaN encodings) are reproduced from
//! the original machine code.
//!
//! Reproduced original behaviors (verified against the disassembly):
//! - Round-to-nearest-even with sticky bit for all finite results.
//! - Any NaN operand yields the canonical NaN `0x7FF8000000000000`
//!   (the original routes through `_fp_trap`; with traps masked as in
//!   retailOS it returns the default NaN — payloads are NOT propagated).
//! - `Inf/Inf` and `0/0` yield `0x7FF8000000000001` — the original's
//!   quirky payload-1 NaN (0x83eb450 / 0x83eb44c), kept for bug
//!   compatibility. (Host hardware returns the canonical NaN instead.)
//! - `x/±0` (finite nonzero x) -> ±Inf, `±0/x` -> ±0, signs XORed.
//!
//! Documented deviations (intentional, host-oracle compatible):
//! - Denormal INPUTS: the original flushes them to zero (treating them as
//!   +0 regardless of sign, a sign quirk at 0x83eb360/0x83eb394). This port
//!   normalizes them and computes the true IEEE quotient.
//! - Denormal RESULTS: the original flushes underflowing results to ±0
//!   (no gradual underflow; 0x83eb318). This port produces correctly
//!   rounded denormals per IEEE 754.
//! - No FP exception trapping: the original can tail-call `_fp_trap` for
//!   invalid/overflow/underflow; retailOS runs with traps masked, which is
//!   equivalent to returning the default results computed here.
//!
//! Integer-only implementation: no `f64` arithmetic, no 64-bit `/` or `%`
//! (would lower to unported soft-float helpers on ARM).

/// Canonical quiet NaN returned for any NaN operand (traps-masked default).
const CANONICAL_NAN: u64 = 0x7FF8_0000_0000_0000;

/// Payload-1 NaN the original returns for `Inf/Inf` and `0/0`.
const INVALID_NAN: u64 = 0x7FF8_0000_0000_0001;

const EXP_MASK: u64 = 0x7FF;
const SIG_MASK: u64 = 0x000F_FFFF_FFFF_FFFF; // 52 fraction bits
const HIDDEN_BIT: u64 = 1 << 52;
const SIGN_BIT: u64 = 1 << 63;
const INFINITY: u64 = 0x7FF0_0000_0000_0000;
const EXP_MAX: i32 = 0x7FF;

/// __ddiv — original: `__ddiv` @ 0x083eb238 (516 bytes) with `_ddiv_core`
/// @ 0x083eb45c (600 bytes) inlined conceptually (see module docs for the
/// restoring-division replacement).
///
/// IEEE 754 double division, round-to-nearest-even. Arguments and result
/// are soft-float `u64` bit patterns.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __ddiv(a: u64, b: u64) -> u64 {
    let sign = (a ^ b) & SIGN_BIT;
    let exp_a = ((a >> 52) & EXP_MASK) as i32;
    let exp_b = ((b >> 52) & EXP_MASK) as i32;
    let frac_a = a & SIG_MASK;
    let frac_b = b & SIG_MASK;

    // Inf/NaN operands.
    if exp_a == EXP_MAX || exp_b == EXP_MAX {
        if (exp_a == EXP_MAX && frac_a != 0) || (exp_b == EXP_MAX && frac_b != 0) {
            return CANONICAL_NAN;
        }
        if exp_a == EXP_MAX && exp_b == EXP_MAX {
            return INVALID_NAN; // Inf/Inf
        }
        if exp_a == EXP_MAX {
            return sign | INFINITY; // Inf / finite
        }
        return sign; // finite / Inf -> ±0
    }

    // Zero operands (denormals fall through to the general path — see the
    // module docs for the deviation from the original's flush-to-zero).
    if exp_b == 0 && frac_b == 0 {
        if exp_a == 0 && frac_a == 0 {
            return INVALID_NAN; // 0/0
        }
        return sign | INFINITY; // x/±0
    }
    if exp_a == 0 && frac_a == 0 {
        return sign; // ±0 / x
    }

    // Finite nonzero operands: normalize significands to 53 bits (top bit
    // set) with unbiased exponents, value = sig * 2^(exp-52).
    let (sig_a, unbiased_a) = normalize_significand(frac_a, exp_a);
    let (sig_b, unbiased_b) = normalize_significand(frac_b, exp_b);

    // Force the quotient into [1, 2) so the divide loop's top bit is set.
    let (sig_a, borrow) = if sig_a < sig_b {
        (sig_a << 1, 1)
    } else {
        (sig_a, 0)
    };
    let result_exp = unbiased_a - borrow - unbiased_b + 1023;

    // 56 quotient bits (top bit always set) plus a nonzero-remainder flag.
    let (quotient, has_remainder) = divide_significands(sig_a, sig_b);

    if result_exp >= EXP_MAX {
        return sign | INFINITY; // overflow
    }

    if result_exp <= 0 {
        // Denormal result (gradual underflow): round the quotient at the
        // denormal ulp of 2^-1074, i.e. shift out 5 - result_exp bits.
        let shift_out = 5 - result_exp;
        if shift_out >= 64 {
            return sign; // rounds to ±0
        }
        let mantissa = round_shift(quotient, shift_out as u32, has_remainder);
        // `mantissa` may round up to 2^52, which is exactly the smallest
        // normal encoding — the plain bit OR handles both cases.
        return sign | mantissa;
    }

    // Normal result: keep the top 53 bits, round with guard/round/sticky.
    let mut significand = round_shift(quotient, 4, has_remainder);
    let mut exponent = result_exp;
    if significand >> 53 != 0 {
        // Rounding carried out of the top bit: 1.111...1 -> 10.0.
        significand >>= 1;
        exponent += 1;
        if exponent >= EXP_MAX {
            return sign | INFINITY;
        }
    }
    sign | ((exponent as u64) << 52) | (significand & SIG_MASK)
}

/// Splits a finite nonzero double into a 53-bit significand (bit 52 set)
/// and its unbiased exponent, normalizing denormals.
fn normalize_significand(frac: u64, exp_field: i32) -> (u64, i32) {
    if exp_field == 0 {
        // Denormal: no hidden bit; shift left until bit 52 is set.
        let shift = frac.leading_zeros() as i32 - 11;
        (frac << shift, -1022 - shift)
    } else {
        (frac | HIDDEN_BIT, exp_field - 1023)
    }
}

/// Restoring shift-subtract division: given 53-bit `numer` in
/// `[denom, 2*denom)`, returns `(floor(numer * 2^56 / denom), remainder !=
/// 0)`. The quotient is 57 bits with the top bit always set, giving 53
/// significand bits plus guard/round/sticky room. Each iteration emits one
/// quotient bit (compare/subtract, then double the remainder), so after k
/// iterations the quotient is `floor(numer * 2^(k-1) / denom)` — hence 57
/// iterations for 56 fractional bits.
fn divide_significands(numer: u64, denom: u64) -> (u64, bool) {
    let mut remainder = numer;
    let mut quotient: u64 = 0;
    let mut bit = 0;
    while bit < 57 {
        quotient <<= 1;
        if remainder >= denom {
            remainder -= denom;
            quotient |= 1;
        }
        // remainder < denom <= 2^53 here, so the shift never overflows.
        remainder <<= 1;
        bit += 1;
    }
    (quotient, remainder != 0)
}

/// Rounds `value >> shift_out` to nearest-even. `sticky` is the OR of all
/// discarded bits below `value`'s low `shift_out` bits. `shift_out` must be
/// in `1..=63`.
fn round_shift(value: u64, shift_out: u32, sticky: bool) -> u64 {
    let rounded = value >> shift_out;
    let guard = (value >> (shift_out - 1)) & 1;
    let below_guard = value & ((1u64 << (shift_out - 1)) - 1);
    let round_up = guard == 1 && (below_guard != 0 || sticky || (rounded & 1) == 1);
    if round_up {
        rounded + 1
    } else {
        rounded
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn ddiv(a: u64, b: u64) -> u64 {
        unsafe { __ddiv(a, b) }
    }

    /// Host IEEE oracle (aarch64 hardware f64, round-to-nearest-even).
    fn host_div(a: u64, b: u64) -> u64 {
        (f64::from_bits(a) / f64::from_bits(b)).to_bits()
    }

    const MIN_NORMAL: u64 = 0x0010_0000_0000_0000;
    const MIN_DENORMAL: u64 = 0x0000_0000_0000_0001;
    const MAX_DENORMAL: u64 = 0x000F_FFFF_FFFF_FFFF;
    const POS_ZERO: u64 = 0;
    const NEG_ZERO: u64 = SIGN_BIT;

    #[test]
    fn basic_exact_divisions() {
        let cases: &[(u64, u64)] = &[
            (6.0f64.to_bits(), 3.0f64.to_bits()),
            (1.0f64.to_bits(), 2.0f64.to_bits()),
            (2.0f64.to_bits(), 1.0f64.to_bits()),
            (1.5f64.to_bits(), 0.5f64.to_bits()),
            (7.0f64.to_bits(), 0.25f64.to_bits()),
            (0.0f64.to_bits(), 1.0f64.to_bits()),
        ];
        for &(a, b) in cases {
            assert_eq!(ddiv(a, b), host_div(a, b), "{a:#x} / {b:#x}");
        }
        assert_eq!(ddiv(6.0f64.to_bits(), 3.0f64.to_bits()), 2.0f64.to_bits());
        assert_eq!(ddiv(1.0f64.to_bits(), 2.0f64.to_bits()), 0.5f64.to_bits());
    }

    #[test]
    fn signs() {
        let one = 1.0f64.to_bits();
        let two = 2.0f64.to_bits();
        assert_eq!(ddiv(one, two), 0.5f64.to_bits());
        assert_eq!(ddiv(one | SIGN_BIT, two), (-0.5f64).to_bits());
        assert_eq!(ddiv(one, two | SIGN_BIT), (-0.5f64).to_bits());
        assert_eq!(ddiv(one | SIGN_BIT, two | SIGN_BIT), 0.5f64.to_bits());
    }

    #[test]
    fn sticky_rounding_matches_host() {
        // Non-terminating quotients: sticky bit decides the rounding.
        let pairs: &[(f64, f64)] = &[
            (1.0, 3.0),
            (2.0, 3.0),
            (1.0, 10.0),
            (10.0, 3.0),
            (1.0, 7.0),
            (2.0, 7.0),
            (1.0, 49.0),
            (123456.0, 7.0),
            (1.0, f64::from_bits(MAX_DENORMAL)),
        ];
        for &(x, y) in pairs {
            let (a, b) = (x.to_bits(), y.to_bits());
            assert_eq!(ddiv(a, b), host_div(a, b), "{x} / {y}");
        }
    }

    #[test]
    fn divide_by_zero() {
        let one = 1.0f64.to_bits();
        assert_eq!(ddiv(one, POS_ZERO), INFINITY);
        assert_eq!(ddiv(one | SIGN_BIT, POS_ZERO), INFINITY | SIGN_BIT);
        assert_eq!(ddiv(one, NEG_ZERO), INFINITY | SIGN_BIT);
        assert_eq!(ddiv(one | SIGN_BIT, NEG_ZERO), INFINITY);
        assert_eq!(host_div(one, POS_ZERO), INFINITY); // oracle sanity
    }

    #[test]
    fn zero_divided() {
        let one = 1.0f64.to_bits();
        assert_eq!(ddiv(POS_ZERO, one), POS_ZERO);
        assert_eq!(ddiv(NEG_ZERO, one), NEG_ZERO);
        assert_eq!(ddiv(POS_ZERO, one | SIGN_BIT), NEG_ZERO);
        assert_eq!(ddiv(NEG_ZERO, one | SIGN_BIT), POS_ZERO);
    }

    #[test]
    fn zero_over_zero_is_payload1_nan() {
        // Original firmware quirk (0x83eb44c): 0/0 -> 0x7FF8000000000001,
        // not the host's canonical NaN.
        assert_eq!(ddiv(POS_ZERO, POS_ZERO), INVALID_NAN);
        assert_eq!(ddiv(NEG_ZERO, NEG_ZERO), INVALID_NAN);
        assert_eq!(ddiv(POS_ZERO, NEG_ZERO), INVALID_NAN);
        assert!(f64::from_bits(INVALID_NAN).is_nan());
    }

    #[test]
    fn infinities() {
        let one = 1.0f64.to_bits();
        assert_eq!(ddiv(INFINITY, one), INFINITY);
        assert_eq!(ddiv(INFINITY | SIGN_BIT, one), INFINITY | SIGN_BIT);
        assert_eq!(ddiv(INFINITY, one | SIGN_BIT), INFINITY | SIGN_BIT);
        assert_eq!(ddiv(one, INFINITY), POS_ZERO);
        assert_eq!(ddiv(one | SIGN_BIT, INFINITY), NEG_ZERO);
        assert_eq!(ddiv(one, INFINITY | SIGN_BIT), NEG_ZERO);
        // Inf/Inf -> the original's payload-1 NaN (0x83eb450).
        assert_eq!(ddiv(INFINITY, INFINITY), INVALID_NAN);
        assert_eq!(ddiv(INFINITY | SIGN_BIT, INFINITY), INVALID_NAN);
        assert_eq!(ddiv(INFINITY, INFINITY | SIGN_BIT), INVALID_NAN);
    }

    #[test]
    fn nan_operands_yield_canonical_nan() {
        let one = 1.0f64.to_bits();
        let quiet = CANONICAL_NAN;
        let signaling = 0x7FF0_0000_0000_0001u64;
        let negative = 0xFFF8_0000_0000_0000u64;
        let payload = 0x7FF8_0000_0000_0042u64;
        for nan in [quiet, signaling, negative, payload] {
            assert_eq!(ddiv(nan, one), CANONICAL_NAN, "nan / 1 ({nan:#x})");
            assert_eq!(ddiv(one, nan), CANONICAL_NAN, "1 / nan ({nan:#x})");
            assert_eq!(ddiv(nan, nan), CANONICAL_NAN);
            assert_eq!(ddiv(nan, INFINITY), CANONICAL_NAN);
            assert_eq!(ddiv(INFINITY, nan), CANONICAL_NAN);
        }
    }

    #[test]
    fn denormal_inputs() {
        let one = 1.0f64.to_bits();
        let two = 2.0f64.to_bits();
        assert_eq!(ddiv(MIN_DENORMAL, one), MIN_DENORMAL);
        assert_eq!(ddiv(MIN_DENORMAL, two), host_div(MIN_DENORMAL, two));
        assert_eq!(ddiv(MIN_DENORMAL, MIN_DENORMAL), one);
        assert_eq!(ddiv(MAX_DENORMAL, MIN_DENORMAL), host_div(MAX_DENORMAL, MIN_DENORMAL));
        assert_eq!(ddiv(one, MIN_DENORMAL), host_div(one, MIN_DENORMAL)); // -> Inf
        assert_eq!(ddiv(MIN_DENORMAL | SIGN_BIT, one), MIN_DENORMAL | SIGN_BIT);
        assert_eq!(ddiv(MAX_DENORMAL, two), host_div(MAX_DENORMAL, two));
        // Denormal / zero -> Inf (IEEE; the original flushed to NaN).
        assert_eq!(ddiv(MIN_DENORMAL, POS_ZERO), INFINITY);
    }

    #[test]
    fn denormal_results() {
        let one = 1.0f64.to_bits();
        let two = 2.0f64.to_bits();
        // Smallest normal halved/quartered/thirded -> denormals.
        assert_eq!(ddiv(MIN_NORMAL, two), MIN_NORMAL >> 1);
        assert_eq!(ddiv(MIN_NORMAL, 4.0f64.to_bits()), MIN_NORMAL >> 2);
        assert_eq!(ddiv(MIN_NORMAL, 3.0f64.to_bits()), host_div(MIN_NORMAL, 3.0f64.to_bits()));
        assert_eq!(ddiv(MIN_NORMAL | SIGN_BIT, two), (MIN_NORMAL >> 1) | SIGN_BIT);
        // Exact tie at the denormal boundary: 2^-1022 / 2^53 = 2^-1075,
        // rounds to even -> +0. (Division ties are only possible here.)
        let two53 = 9007199254740992.0f64.to_bits();
        assert_eq!(ddiv(MIN_NORMAL, two53), POS_ZERO);
        assert_eq!(host_div(MIN_NORMAL, two53), POS_ZERO);
        // Just above the tie: 3*2^-1022 / 2^54 = 1.5 * 2^-1075 -> min denormal.
        let three_min = f64::from_bits(MIN_NORMAL) * 3.0;
        let two54 = 18014398509481984.0f64.to_bits();
        let a = three_min.to_bits();
        assert_eq!(ddiv(a, two54), MIN_DENORMAL);
        assert_eq!(host_div(a, two54), MIN_DENORMAL);
        // Denormal result with sticky rounding.
        assert_eq!(ddiv(MIN_NORMAL, 7.0f64.to_bits()), host_div(MIN_NORMAL, 7.0f64.to_bits()));
        // Largest denormal construction: (2 - 2^-52) * min_normal / 2.
        assert_eq!(ddiv(f64::from_bits(MIN_NORMAL).to_bits(), one), MIN_NORMAL);
    }

    #[test]
    fn overflow_and_underflow() {
        let max = f64::MAX.to_bits();
        let two = 2.0f64.to_bits();
        assert_eq!(ddiv(max, 0.5f64.to_bits()), INFINITY);
        assert_eq!(ddiv(max, 0.5f64.to_bits() | SIGN_BIT), INFINITY | SIGN_BIT);
        // Rounding just below overflow boundary must match the host.
        let near = host_div(max, 1.0f64.to_bits());
        assert_eq!(ddiv(max, 1.0f64.to_bits()), near);
        assert_eq!(ddiv(max, two), host_div(max, two));
    }

    #[test]
    fn random_pairs_match_host() {
        // xorshift64* PRNG, deterministic seed.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut checked = 0u32;
        let mut skipped = 0u32;
        while checked < 100_000 {
            let a = next();
            let b = next();
            let exp_a = (a >> 52) & EXP_MASK;
            let exp_b = (b >> 52) & EXP_MASK;
            let mag_a = a & !SIGN_BIT;
            let mag_b = b & !SIGN_BIT;
            // Cases with documented firmware-specific NaN payloads are
            // covered by directed tests instead.
            if (exp_a == EXP_MASK as u64 && mag_a != INFINITY)
                || (exp_b == EXP_MASK as u64 && mag_b != INFINITY)
            {
                skipped += 1; // NaN operand
                continue;
            }
            if exp_a == EXP_MASK as u64 && exp_b == EXP_MASK as u64 {
                skipped += 1; // Inf/Inf
                continue;
            }
            if mag_a == 0 && mag_b == 0 {
                skipped += 1; // 0/0
                continue;
            }
            assert_eq!(ddiv(a, b), host_div(a, b), "{a:#018x} / {b:#018x}");
            checked += 1;
        }
        // Random u64s hit denormal/Inf encodings often enough to matter.
        assert!(skipped < 100_000);
    }
}
