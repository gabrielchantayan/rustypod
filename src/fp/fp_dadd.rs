//! Port of the ARM ADS 1.0.1 soft-float double add/subtract core — the
//! most-called arithmetic in retailOS.
//!
//! retailOS is SOFT-FLOAT: doubles travel as u64 bit patterns (r0:r1
//! register pairs). This module does pure integer bit manipulation — no
//! f64 arithmetic, which would lower to unported __aeabi_d* helpers.
//!
//! Algorithm of the original: the entry points classify both exponents
//! (field 0x000 or 0x7ff goes to a shared specials block), then dispatch
//! on the sign XOR (`teq r1, r3` + conditional `eor` of the subtrahend's
//! sign bit) to one of two shared cores:
//!   - add-core @ 0x83eaf54 (same effective sign): order by magnitude,
//!     align the smaller 53-bit significand (hidden bit restored) right
//!     by the exponent difference with a sticky fold, add, normalize one
//!     place on carry, round to nearest-even.
//!   - sub-core @ 0x83ec0c4 (differing effective sign): same alignment,
//!     subtract (the smaller operand is negated with a sticky-corrected
//!     twos-complement frame), renormalize by up to 52 places on
//!     cancellation, round to nearest-even.
//! __drsb flips the FIRST operand's sign and reuses both cores (and, for
//! specials, swaps the register pair and jumps into __dsub's specials),
//! i.e. __drsb(a, b) == b - a.
//!
//! Behavioral deviations from strict IEEE 754, mirrored from the
//! original (and pinned by directed tests below):
//! - Any NaN input returns the canonical quiet NaN 0x7ff80000_00000000;
//!   input payload and sign are NOT propagated (the original tail-calls
//!   a shared exception stub with fp-status 0x04000011/0x04000012, which
//!   returns immediately with no trap handler installed). Host aarch64
//!   propagates the payload instead — the tests use the canonical NaN.
//! - Inf + -Inf, Inf - Inf (same sign), and the __drsb equivalents
//!   return the invalid-operation NaN 0x7ff80000_00000001 (low word 1),
//!   not the host's default NaN 0x7ff80000_00000000.
//! - Denormal INPUTS are flushed: a nonzero denormal participates as
//!   +0.0 (its sign is dropped — so (-denormal) + (-denormal) = +0, and
//!   a normal operand is returned bit-exact). Exact -0.0 inputs keep
//!   their sign, giving -0 + -0 = -0 and -0 - +0 = -0 as in IEEE.
//! - Denormal RESULTS flush to +0.0 always — the sign is dropped (the
//!   original executes `mov r1, #0` on exponent underflow) and no
//!   gradual underflow is produced. Cancellation results that IEEE
//!   keeps as denormals come back +0 here.
//!
//! Behavioral verification: host-side `cargo test` compares against
//! native aarch64 f64 add/sub (IEEE round-to-nearest-even oracle) for
//! all cases where the original is IEEE-conformant, with the deviations
//! above folded into the oracle; `tools/match.py` (ipod-decomp) reports
//! the mnemonic-level diff against the original machine code.

const SIGN: u64 = 0x8000_0000_0000_0000;
const FRAC: u64 = 0x000f_ffff_ffff_ffff;
const HIDDEN: u64 = 0x0010_0000_0000_0000;
const POS_INF: u64 = 0x7ff0_0000_0000_0000;

/// Canonical quiet NaN returned for any NaN input (hi 0x7ff80000, lo 0).
const QNAN: u64 = 0x7ff8_0000_0000_0000;

/// Invalid-operation NaN for Inf(+/-)Inf (hi 0x7ff80000, lo 1).
const INVALID_NAN: u64 = 0x7ff8_0000_0000_0001;

#[inline]
fn exp_of(x: u64) -> u32 {
    ((x >> 52) & 0x7ff) as u32
}

#[inline]
fn is_nan(x: u64) -> bool {
    exp_of(x) == 0x7ff && x & FRAC != 0
}

/// Flush a zero/denormal input the way the specials blocks do: a
/// nonzero denormal collapses to +0.0 (sign dropped); exact +-0.0 is
/// kept as-is.
#[inline]
fn flush_input(x: u64) -> u64 {
    if exp_of(x) == 0 && x & FRAC != 0 {
        0
    } else {
        x
    }
}

/// Shift a 53-bit significand (scaled by 2^10) right by `s` bits,
/// folding everything that falls off into bit 0 as a sticky bit.
#[inline]
fn shr_sticky(x: u64, s: u32) -> u64 {
    if s == 0 {
        x
    } else if s >= 64 {
        (x != 0) as u64
    } else {
        (x >> s) | (((x << (64 - s)) != 0) as u64)
    }
}

/// Round a normalized significand (hidden bit at 62, fraction bits
/// 10..61, guard bit 9, sticky bits 0..8) to nearest-even and pack with
/// sign and biased exponent. Overflow yields +-Inf. Callers guarantee
/// `exp >= 1` (underflow is flushed before this is reached).
fn round_pack(sign: u64, mut exp: i32, sig: u64) -> u64 {
    let mut mant = sig >> 10; // 53 bits, hidden bit at 52
    let guard = (sig >> 9) & 1;
    let sticky = sig & 0x1ff;
    if guard == 1 && (sticky != 0 || mant & 1 == 1) {
        mant += 1;
        if mant >> 53 != 0 {
            // Round-up rippled the hidden bit out: 1.11..1 -> 10.0.
            mant >>= 1;
            exp += 1;
        }
    }
    if exp >= 0x7ff {
        return sign | POS_INF;
    }
    sign | ((exp as u64) << 52) | (mant & FRAC)
}

/// Add-core @ 0x83eaf54: both operands normal, nonzero, same sign.
/// Returns sign * (|a| + |b|).
fn add_core(a: u64, b: u64) -> u64 {
    let sign = a & SIGN;
    let (hi, lo) = if a & !SIGN >= b & !SIGN { (a, b) } else { (b, a) };
    let exp_hi = exp_of(hi) as i32;
    let diff = exp_hi - exp_of(lo) as i32;
    let sig_hi = (hi & FRAC) | HIDDEN;
    let sig_lo = (lo & FRAC) | HIDDEN;

    // Significands scaled by 2^10: hidden bit at 62, 10 guard bits
    // below, sticky folded into bit 0 by the alignment shift.
    let (sum, carry) = (sig_hi << 10).overflowing_add(shr_sticky(sig_lo << 10, diff as u32));
    let mut exp = exp_hi + carry as i32;
    let mut sum = if carry {
        (sum >> 1) | (sum & 1) | (1 << 63)
    } else {
        sum
    };
    // Normalize to a hidden bit at 62 (carry pushed it to 63).
    if sum >> 63 != 0 {
        sum = (sum >> 1) | (sum & 1);
        exp += 1;
    }
    round_pack(sign, exp, sum)
}

/// Sub-core helper: same-sign normal operands, |hi| >= |lo|.
/// Returns sign * (|hi| - |lo|).
fn sub_magnitudes(sign: u64, hi: u64, lo: u64) -> u64 {
    let exp_hi = exp_of(hi) as i32;
    let diff = exp_hi - exp_of(lo) as i32;
    let sig_hi = (hi & FRAC) | HIDDEN;
    let sig_lo = (lo & FRAC) | HIDDEN;

    // Same 2^10 scaling as the add-core. The aligned subtrahend carries
    // a sticky bit in bit 0, so the difference is the floor of the true
    // result; deep cancellation is only possible when the alignment
    // shift was exact (diff <= 10 guard bits), so rounding stays exact.
    let delta = (sig_hi << 10) - shr_sticky(sig_lo << 10, diff as u32);
    if delta == 0 {
        // Exact cancellation: x - x = +0.0 in round-to-nearest.
        return 0;
    }
    // delta < 2^63: normalize the leading 1 to bit 62.
    let shift = delta.leading_zeros() as i32 - 1;
    let exp = exp_hi - shift;
    if exp < 1 {
        // Denormal result: the original flushes to +0.0, dropping the
        // sign. (Reachable only with an exact significand, so no
        // round-up across the boundary is lost here.)
        return 0;
    }
    round_pack(sign, exp, delta << shift)
}

/// Sub-core @ 0x83ec0c4: both operands normal, nonzero, same sign.
/// Returns a - b.
fn sub_core(a: u64, b: u64) -> u64 {
    if a & !SIGN >= b & !SIGN {
        sub_magnitudes(a & SIGN, a, b)
    } else {
        sub_magnitudes((a & SIGN) ^ SIGN, b, a)
    }
}

/// __dadd specials @ 0x83eb06c: at least one exponent field is 0x000
/// (zero/denormal) or 0x7ff (Inf/NaN).
fn add_specials(a: u64, b: u64) -> u64 {
    if is_nan(a) || is_nan(b) {
        return QNAN;
    }
    let fa = flush_input(a);
    let fb = flush_input(b);
    let ea = exp_of(fa);
    let eb = exp_of(fb);
    if ea == 0x7ff || eb == 0x7ff {
        if ea == 0x7ff && eb == 0x7ff {
            // Inf (+) Inf: opposite signs are an invalid operation.
            if (fa ^ fb) & SIGN != 0 {
                return INVALID_NAN;
            }
            return fa;
        }
        // Exactly one Inf: it dominates (the other side is finite).
        return if ea == 0x7ff { fa } else { fb };
    }
    // Zero/denormal involved (already flushed to +-0).
    if ea != 0 {
        return fa; // normal + (flushed) zero: return the normal operand
    }
    if eb != 0 {
        return fb;
    }
    // Both zero: -0 only when both inputs are exactly -0.0.
    if fa == SIGN && fb == SIGN {
        return SIGN;
    }
    0
}

/// __dsub specials @ 0x83ec274 (shared with __drsb via a register
/// swap): like add_specials but the second operand's sign flips.
fn sub_specials(a: u64, b: u64) -> u64 {
    if is_nan(a) || is_nan(b) {
        return QNAN;
    }
    let fa = flush_input(a);
    let fb = flush_input(b);
    let ea = exp_of(fa);
    let eb = exp_of(fb);
    if ea == 0x7ff || eb == 0x7ff {
        if ea == 0x7ff && eb == 0x7ff {
            // Inf - Inf with equal signs is an invalid operation.
            if (fa ^ fb) & SIGN == 0 {
                return INVALID_NAN;
            }
            return fa;
        }
        return if ea == 0x7ff { fa } else { fb ^ SIGN };
    }
    if ea != 0 {
        return fa;
    }
    if eb != 0 {
        return fb ^ SIGN;
    }
    // Both zero: start from a's flushed zero; exact -0.0 for b forces +0.
    let mut result = if fa == SIGN { SIGN } else { 0 };
    if fb == SIGN {
        result = 0;
    }
    result
}

/// __dadd — original: `FUN_083eaf2c` @ 0x083eaf2c (500 bytes, 70
/// callers — the hottest double op in retailOS).
///
/// Doubles are u64 bit patterns (soft-float). Same signs use the
/// add-core, differing signs flip b's sign bit and use the sub-core;
/// exponent fields 0x000/0x7ff go to the specials block. See the module
/// header for the mirrored non-IEEE edge behavior.
#[no_mangle]
pub unsafe extern "C" fn __dadd(a: u64, b: u64) -> u64 {
    if exp_of(a) & 0x7ff == 0 || exp_of(a) == 0x7ff || exp_of(b) & 0x7ff == 0 || exp_of(b) == 0x7ff
    {
        return add_specials(a, b);
    }
    if (a ^ b) & SIGN != 0 {
        sub_core(a, b ^ SIGN)
    } else {
        add_core(a, b)
    }
}

/// __dsub — original: `FUN_083ec09c` @ 0x083ec09c (660 bytes, 39
/// callers; contains the shared sub-core 0x83ec0c4 and specials block
/// 0x83ec274).
///
/// Doubles are u64 bit patterns (soft-float). Differing signs flip b's
/// sign bit and use the add-core; same signs use the sub-core.
#[no_mangle]
pub unsafe extern "C" fn __dsub(a: u64, b: u64) -> u64 {
    if exp_of(a) & 0x7ff == 0 || exp_of(a) == 0x7ff || exp_of(b) & 0x7ff == 0 || exp_of(b) == 0x7ff
    {
        return sub_specials(a, b);
    }
    if (a ^ b) & SIGN != 0 {
        add_core(a, b ^ SIGN)
    } else {
        sub_core(a, b)
    }
}

/// __drsb — original: `FUN_083ebed8` @ 0x083ebed8 (76 bytes, 16
/// callers). Reverse subtract: __drsb(a, b) = b - a. Flips the FIRST
/// operand's sign (`eor r1, #0x80000000`) and dispatches to the shared
/// add-core 0x83eaf54 / sub-core 0x83ec0c4; specials swap the register
/// pair and jump into __dsub's specials block.
#[no_mangle]
pub unsafe extern "C" fn __drsb(a: u64, b: u64) -> u64 {
    if exp_of(a) & 0x7ff == 0 || exp_of(a) == 0x7ff || exp_of(b) & 0x7ff == 0 || exp_of(b) == 0x7ff
    {
        // Register swap, then __dsub's specials: sub_specials(b, a).
        return sub_specials(b, a);
    }
    if (a ^ b) & SIGN != 0 {
        // Signs differed: -a and b now share a sign -> add-core.
        add_core(a ^ SIGN, b)
    } else {
        // Same sign: negate both -> sub-core computes (-a) - (-b).
        sub_core(a ^ SIGN, b ^ SIGN)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn dadd(a: u64, b: u64) -> u64 {
        unsafe { __dadd(a, b) }
    }
    fn dsub(a: u64, b: u64) -> u64 {
        unsafe { __dsub(a, b) }
    }
    fn drsb(a: u64, b: u64) -> u64 {
        unsafe { __drsb(a, b) }
    }

    const INF: u64 = POS_INF;
    const NEG_INF: u64 = POS_INF | SIGN;
    const ONE: u64 = 0x3ff0_0000_0000_0000;
    const NEG_ONE: u64 = ONE | SIGN;
    const MIN_NORMAL: u64 = 0x0010_0000_0000_0000;
    const MAX_DENORM: u64 = 0x000f_ffff_ffff_ffff;
    const DBL_MAX: u64 = 0x7fef_ffff_ffff_ffff;

    /// Flush helper mirroring flush_input for the host oracle.
    fn flush(x: u64) -> u64 {
        flush_input(x)
    }

    /// Denormal nonzero results flush to +0.0 (sign dropped).
    fn flush_result(r: u64) -> u64 {
        if (r >> 52) & 0x7ff == 0 && r & FRAC != 0 {
            0
        } else {
            r
        }
    }

    /// Host IEEE oracle for __dadd, with the original's deviations
    /// folded in: canonical NaN for NaN inputs, 0x7ff8...01 for
    /// Inf + -Inf, denormal inputs flushed, denormal results flushed.
    fn oracle_add(a: u64, b: u64) -> u64 {
        if is_nan(a) || is_nan(b) {
            return QNAN;
        }
        let fa = flush(a);
        let fb = flush(b);
        if fa & !SIGN == INF && fb & !SIGN == INF && (fa ^ fb) & SIGN != 0 {
            return INVALID_NAN;
        }
        flush_result((f64::from_bits(fa) + f64::from_bits(fb)).to_bits())
    }

    /// Host IEEE oracle for __dsub (Inf - Inf same sign -> INVALID_NAN).
    fn oracle_sub(a: u64, b: u64) -> u64 {
        if is_nan(a) || is_nan(b) {
            return QNAN;
        }
        let fa = flush(a);
        let fb = flush(b);
        if fa & !SIGN == INF && fb & !SIGN == INF && (fa ^ fb) & SIGN == 0 {
            return INVALID_NAN;
        }
        flush_result((f64::from_bits(fa) - f64::from_bits(fb)).to_bits())
    }

    fn check(a: u64, b: u64) {
        assert_eq!(dadd(a, b), oracle_add(a, b), "dadd a={a:#x} b={b:#x}");
        assert_eq!(dsub(a, b), oracle_sub(a, b), "dsub a={a:#x} b={b:#x}");
        assert_eq!(drsb(a, b), oracle_sub(b, a), "drsb a={a:#x} b={b:#x}");
    }

    #[test]
    fn normals_match_host() {
        let cases: &[(u64, u64)] = &[
            (0x3ff8_0000_0000_0000, 0x4002_0000_0000_0000), // 1.5, 2.25
            (0x4008_0000_0000_0000, 0xc01c_0000_0000_0000), // 3.0, -7.0
            (ONE, ONE),
            (DBL_MAX, 0x3fe0_0000_0000_0000), // DBL_MAX, 0.5
            (MIN_NORMAL, ONE),
            (0x3e69_1234_5678_9abc, 0x41ff_edcb_a987_6543), // random-ish
            (0x43e0_0000_0000_0001, 0x3c90_0000_0000_0001), // huge, tiny
            (0xbff0_0000_0000_0001, 0x3ff0_0000_0000_0001), // just off -1.0
            (DBL_MAX, DBL_MAX),                             // overflow to +Inf
            (DBL_MAX | SIGN, DBL_MAX),                      // -DBL_MAX + DBL_MAX = 0
        ];
        for &(a, b) in cases {
            check(a, b);
            check(b, a);
            check(a | SIGN, b);
            check(a, b | SIGN);
            check(a | SIGN, b | SIGN);
        }
    }

    /// Exponent gaps 0..=60 (past 53 the smaller operand is sticky-only).
    #[test]
    fn exponent_gaps_match_host() {
        let a = 0x3ff8_0000_0000_0000u64; // 1.5
        for gap in 0..=60u64 {
            let b = (0x3ff - gap) << 52 | 0x000c_0000_0000_0000; // 1.75 * 2^-gap
            check(a, b);
            check(b, a);
            check(a, b | SIGN);
            check(b | SIGN, a);
            check(a | SIGN, b);
            check(a | SIGN, b | SIGN);
        }
    }

    #[test]
    fn cancellation() {
        // x - x = +0.0 exactly, for any normal x (also negative x).
        for &x in &[ONE, NEG_ONE, DBL_MAX, MIN_NORMAL, 0x3ff8_0000_0000_0000] {
            assert_eq!(dsub(x, x), 0, "x={x:#x}");
            assert_eq!(dadd(x, x ^ SIGN), 0, "x={x:#x}");
            assert_eq!(drsb(x, x), 0, "x={x:#x}");
        }
        // Near cancellation: (1 + 2^-52) - 1 = 2^-52.
        let eps = 0x3cb0_0000_0000_0000u64;
        assert_eq!(dsub(ONE | 1, ONE), eps);
        assert_eq!(dsub(ONE | 1, ONE), oracle_sub(ONE | 1, ONE));
        // Deep cancellation across an exponent boundary: result needs a
        // 51-place renormalization.
        let a = 0x3ff0_0000_0000_0001u64;
        let b = 0x3fef_ffff_ffff_fffeu64;
        check(a, b);
        check(b, a);
        // Cancellation into the denormal range flushes to +0.0:
        // (1 + 2^-52)*2^-1022 - 2^-1022 = min denormal -> +0 (host: 1).
        assert_eq!(dsub(MIN_NORMAL | 1, MIN_NORMAL), 0);
        assert_eq!(dsub(MIN_NORMAL, MIN_NORMAL | 1), 0); // sign dropped
        // 2^-1021 - (1 + 2^-52)*2^-1022 = largest denormal -> +0.
        let two_min = 0x0020_0000_0000_0000u64;
        assert_eq!(dsub(two_min, MIN_NORMAL | 1), 0);
        assert_eq!(dsub(MIN_NORMAL | 1, two_min), 0);
    }

    /// Denormal INPUTS flush to +0.0; exact -0.0 keeps its sign.
    #[test]
    fn denormal_inputs() {
        let denorm = 0x0008_0000_0000_0001u64;
        let neg_denorm = denorm | SIGN;

        // A normal operand is returned bit-exact regardless of the
        // denormal's value or sign.
        assert_eq!(dadd(denorm, ONE), ONE);
        assert_eq!(dadd(ONE, neg_denorm), ONE);
        assert_eq!(dsub(ONE, denorm), ONE);
        assert_eq!(dsub(denorm, ONE), NEG_ONE);
        assert_eq!(drsb(ONE, denorm), NEG_ONE); // denorm - 1
        assert_eq!(drsb(denorm, ONE), ONE); // 1 - denorm

        // Denormal op denormal -> +0.0, even for two negative denormals
        // (quirk: sign dropped; IEEE FTZ would give -0).
        assert_eq!(dadd(denorm, denorm), 0);
        assert_eq!(dadd(neg_denorm, neg_denorm), 0);
        assert_eq!(dsub(denorm, neg_denorm), 0);
        assert_eq!(dadd(MAX_DENORM, MAX_DENORM), 0);

        // Exact zeros keep IEEE sign rules.
        assert_eq!(dadd(SIGN, SIGN), SIGN); // -0 + -0 = -0
        assert_eq!(dadd(SIGN, 0), 0);
        assert_eq!(dadd(0, SIGN), 0);
        assert_eq!(dsub(SIGN, 0), SIGN); // -0 - +0 = -0
        assert_eq!(dsub(0, SIGN), 0); // +0 - -0 = +0
        assert_eq!(dsub(SIGN, SIGN), 0); // -0 - -0 = +0
        // A negative denormal flushes to +0, NOT -0.
        assert_eq!(dadd(neg_denorm, 0), 0);
        assert_eq!(dsub(neg_denorm, 0), 0);
        assert_eq!(dadd(neg_denorm, SIGN), 0); // not -0: low word nonzero

        // Everything above must also match the oracle sweep.
        for &x in &[denorm, neg_denorm, 1, 1 | SIGN, 0, SIGN, MAX_DENORM] {
            for &y in &[denorm, neg_denorm, ONE, NEG_ONE, 0, SIGN] {
                check(x, y);
            }
        }
    }

    #[test]
    fn infinities() {
        assert_eq!(dadd(INF, INF), INF);
        assert_eq!(dadd(NEG_INF, NEG_INF), NEG_INF);
        assert_eq!(dadd(INF, NEG_INF), INVALID_NAN);
        assert_eq!(dadd(NEG_INF, INF), INVALID_NAN);
        assert_eq!(dsub(INF, INF), INVALID_NAN);
        assert_eq!(dsub(NEG_INF, NEG_INF), INVALID_NAN);
        assert_eq!(dsub(INF, NEG_INF), INF);
        assert_eq!(dsub(NEG_INF, INF), NEG_INF);
        assert_eq!(drsb(INF, INF), INVALID_NAN);
        assert_eq!(drsb(INF, NEG_INF), NEG_INF); // -Inf - Inf
        assert_eq!(drsb(NEG_INF, INF), INF); // Inf - -Inf

        assert_eq!(dadd(INF, ONE), INF);
        assert_eq!(dadd(NEG_INF, ONE), NEG_INF);
        assert_eq!(dsub(ONE, INF), NEG_INF);
        assert_eq!(dsub(INF, ONE), INF);
        assert_eq!(drsb(ONE, INF), INF); // Inf - 1
        assert_eq!(drsb(INF, ONE), NEG_INF); // 1 - Inf

        // Inf with a zero/denormal other side still returns the Inf.
        assert_eq!(dadd(INF, 0), INF);
        assert_eq!(dadd(INF, 1), INF); // denormal
        assert_eq!(dsub(1, NEG_INF), INF);
        assert_eq!(dsub(INF, SIGN), INF);

        for &x in &[INF, NEG_INF] {
            for &y in &[INF, NEG_INF, ONE, NEG_ONE, 0, SIGN, 1] {
                check(x, y);
                check(y, x);
            }
        }
    }

    /// Any NaN input yields the canonical quiet NaN 0x7ff80000_00000000
    /// — payload and sign are NOT propagated (host aarch64 would
    /// propagate; the deviation is pinned here).
    #[test]
    fn nan_inputs_canonical() {
        let payload_nan = 0x7ff8_1234_5678_9abcu64;
        let signaling_nan = 0x7ff4_0000_0000_0000u64;
        let neg_nan = 0xfff8_0000_0000_0001u64;
        for &n in &[payload_nan, signaling_nan, neg_nan] {
            assert_eq!(dadd(n, ONE), QNAN);
            assert_eq!(dadd(ONE, n), QNAN);
            assert_eq!(dsub(n, ONE), QNAN);
            assert_eq!(dsub(ONE, n), QNAN);
            assert_eq!(drsb(n, ONE), QNAN);
            assert_eq!(drsb(ONE, n), QNAN);
            assert_eq!(dadd(n, INF), QNAN); // NaN beats Inf
            assert_eq!(dsub(n, n), QNAN);
            assert_eq!(dadd(n, 0), QNAN);
            assert_eq!(dadd(n, 1), QNAN); // NaN beats denormal flush
            // Document the host difference: aarch64 propagates payload.
            assert_ne!(f64::from_bits(n) + f64::from_bits(ONE), f64::from_bits(QNAN));
        }
    }

    /// Exact ties (guard bit set, sticky clear) round to even.
    #[test]
    fn ties_round_to_even() {
        let half_ulp = 0x3ca0_0000_0000_0000u64; // 2^-53 = half ulp of 1.0

        // 1.0 + 2^-53: tie, even mantissa -> round down.
        assert_eq!(dadd(ONE, half_ulp), ONE);
        assert_eq!(dadd(ONE, half_ulp), oracle_add(ONE, half_ulp));
        // (1 + 2^-52) + 2^-53: tie, odd mantissa -> round up.
        assert_eq!(dadd(ONE | 1, half_ulp), ONE | 2);
        assert_eq!(dadd(ONE | 1, half_ulp), oracle_add(ONE | 1, half_ulp));
        // 1.0 - 2^-53 is EXACT (the ulp just below 1.0 is 2^-53, so the
        // subtraction renormalizes one place and lands on 1-2^-53).
        let below_one = 0x3fef_ffff_ffff_ffffu64;
        assert_eq!(dsub(ONE, half_ulp), below_one);
        assert_eq!(dsub(ONE, half_ulp), oracle_sub(ONE, half_ulp));
        // (1 - 2^-53) - 2^-53 = 1 - 2^-52: exact again.
        assert_eq!(dsub(below_one, half_ulp), below_one - 1);
        assert_eq!(dsub(below_one, half_ulp), oracle_sub(below_one, half_ulp));
        // 1.0 - 3*2^-53: tie between 1-2^-52 (even) and 1-2^-53 (odd)
        // -> rounds to 1-2^-52.
        let three_half = 0x3ca8_0000_0000_0000u64; // 3 * 2^-53
        assert_eq!(dsub(ONE, three_half), below_one - 1);
        assert_eq!(dsub(ONE, three_half), oracle_sub(ONE, three_half));
        // (1 + 2^-52) - 2^-53 = 1 + 2^-53: tie -> even is 1.0.
        assert_eq!(dsub(ONE | 1, half_ulp), ONE);
        assert_eq!(dsub(ONE | 1, half_ulp), oracle_sub(ONE | 1, half_ulp));
        // Negative side mirrors: -1.0 + -2^-53 -> -1.0.
        assert_eq!(dadd(NEG_ONE, half_ulp | SIGN), NEG_ONE);
        // Just past the tie (sticky set) rounds away from even.
        let past = 0x3ca0_0000_0000_0001u64; // 2^-53 + 2^-1074-ish
        assert_eq!(dadd(ONE, past), oracle_add(ONE, past));
        assert_eq!(dadd(ONE, past), ONE | 1);
    }

    #[test]
    fn overflow_to_infinity() {
        assert_eq!(dadd(DBL_MAX, DBL_MAX), INF);
        assert_eq!(dadd(DBL_MAX | SIGN, DBL_MAX | SIGN), NEG_INF);
        assert_eq!(dsub(DBL_MAX, DBL_MAX | SIGN), INF);
        assert_eq!(drsb(DBL_MAX | SIGN, DBL_MAX), INF); // max - -max
        // Rounding ripple: largest finite + just over half an ulp of it.
        let bump = 0x7ca0_0000_0000_0000u64; // 2^971: > half ulp of DBL_MAX
        assert_eq!(dadd(DBL_MAX, bump), oracle_add(DBL_MAX, bump));
        assert_eq!(dadd(DBL_MAX, bump), INF);
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

    /// 100k fully random pairs: exact bit equality with the oracle for
    /// all three entry points. Full-range bit patterns give ~1/1024
    /// each of denormal and Inf/NaN inputs for free.
    #[test]
    fn random_pairs_match_oracle() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..100_000 {
            let a = rng.next();
            let b = rng.next();
            check(a, b);
        }
    }

    /// 30k pairs with correlated exponents (gap 0..=60, both normal) to
    /// stress alignment, sticky tracking and cancellation.
    #[test]
    fn random_correlated_exponents() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        for _ in 0..30_000 {
            let ea = 1 + rng.next() % 0x7fd; // 1..=0x7fd
            let gap = (rng.next() % 61) as i64;
            let eb = (ea as i64 + if rng.next() & 1 == 0 { gap } else { -gap })
                .clamp(1, 0x7fe) as u64;
            let a = ea << 52 | rng.next() & FRAC | (rng.next() & 1) << 63;
            let b = eb << 52 | rng.next() & FRAC | (rng.next() & 1) << 63;
            check(a, b);
        }
    }

    /// 20k near-cancellation pairs: same or adjacent exponents with
    /// mantissas differing only in low bits, plus tiny-exponent pairs
    /// brushing the denormal-result flush boundary.
    #[test]
    fn random_cancellation() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        for _ in 0..20_000 {
            let ea = 1 + rng.next() % 0x7fd;
            let ma = rng.next() & FRAC;
            let delta = rng.next() & 0xffff; // small low-bit difference
            let (mb, eb) = if rng.next() & 1 == 0 {
                (ma.wrapping_sub(delta), ea)
            } else {
                (ma.wrapping_sub(delta), 1.max(ea - 1))
            };
            let eb = eb.max(1);
            let a = ea << 52 | ma | (rng.next() & 1) << 63;
            let b = eb << 52 | mb & FRAC | (rng.next() & 1) << 63;
            check(a, b);
        }
        // Small exponents: results land in/around the denormal range.
        let mut rng = Rng(0x0f0f_0f0f_0f0f_0f0f);
        for _ in 0..20_000 {
            let ea = 1 + rng.next() % 14;
            let eb = 1 + rng.next() % 14;
            let a = ea << 52 | rng.next() & FRAC | (rng.next() & 1) << 63;
            let b = eb << 52 | rng.next() & FRAC | (rng.next() & 1) << 63;
            check(a, b);
        }
    }

    /// Dense grid over mantissa shapes at boundary exponents.
    #[test]
    fn grid_near_boundaries() {
        let mut rng = Rng(0xc001_d00d_badd_f00d);
        let mut mantissas: std::vec::Vec<u64> = std::vec![
            0,
            1,
            2,
            0x000f_ffff_ffff_ffff,
            0x000f_ffff_ffff_fffe,
            0x0008_0000_0000_0000,
            0x0008_0000_0000_0001,
            0x0000_0000_0000_0003,
        ];
        for _ in 0..8 {
            mantissas.push(rng.next() & FRAC);
        }
        let exps: [u64; 8] = [1, 2, 0xd, 0xe, 0x3ff, 0x400, 0x7fd, 0x7fe];
        for &ea in &exps {
            for &eb in &exps {
                for &ma in &mantissas {
                    for &mb in &mantissas {
                        let a = ea << 52 | ma;
                        let b = eb << 52 | mb;
                        check(a, b);
                        check(a | SIGN, b);
                        check(a, b | SIGN);
                    }
                }
            }
        }
    }
}
