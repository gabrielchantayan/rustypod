//! Ports of the ARM ADS 1.0.1 soft-float add/subtract family for single
//! precision, plus the `_frnd` rounding tail that sits in the same region.
//!
//! Originals (retailOS osos, load base 0x08000000):
//!   __fadd @ 0x083ec4b4 (308 B) — fast path handles only both-normal
//!        operands: 24-bit significands `lsl #8` + hidden 0x80000000, the
//!        smaller operand is aligned right by the exponent difference, then
//!        a guard/round/sticky round. Specials (exp 0 or 0xFF) at 0x83ec568.
//!   __frsb @ 0x083ecc28 (56 B) — flips the first operand's sign, then
//!        dispatches to the add or sub core (r_sb(a,b) = b - a); specials
//!        tail at 0x83ecd48 with the operands swapped (3-eor swap).
//!   __fsub @ 0x83ecc60 (352 B) — signs differ: negate b, magnitude-add
//!        core at 0x83ec4d4; signs equal: magnitude-subtract core at
//!        0x83ecc80 with borrow renorm (clz) and flush-to-zero underflow;
//!        specials at 0x83ecd48.
//!   _frnd  @ 0x83ecdc4 (140 B) — shared round-to-nearest-even tail,
//!        dead-linked in osos (no caller anywhere in the image).
//!
//! SOFT-FLOAT CALLING CONVENTION: floats are u32 IEEE 754 bit patterns in
//! r0/r1. This module uses pure integer bit manipulation only — never f32
//! arithmetic, which would lower to the very helpers being ported.
//!
//! Behavioral notes verified against the disassembly (all reproduced here):
//! * DENORMAL INPUTS ARE FLUSHED TO ZERO. The specials gate triggers on an
//!   exponent field of 0, and the zero/denormal tail returns the *other*
//!   operand unchanged, so e.g. min_normal + max_denormal == min_normal.
//! * DENORMAL RESULTS ARE FLUSHED TO +0. The sub core's cancellation paths
//!   (0x83eccfc..0x83ecd47) return +0 whenever the true result would be
//!   denormal. Sums can never denormalize, so __fadd has no such path.
//! * NaN handling: any NaN operand yields the canonical quiet NaN
//!   0x7FC00000 — payload and sign are DROPPED (the original loads the
//!   literal and tails the trap decoder at 0x83ed080 with ip=0x4000001/2,
//!   which returns it untouched). The invalid operations inf+(-inf) and
//!   inf-inf yield 0x7FC00001 via a separate literal, also not the host's
//!   default NaN. Host tests use these ADS values as the oracle.
//! * TIE QUIRK (documented deviation from IEEE 754): the magnitude-add
//!   core's no-carry path returns truncated+1 on an exact tie
//!   (round bit set, sticky and alignment-lost bits all zero) WITHOUT the
//!   round-to-even fixup — the `tst ip,#0x7f` / `cmpne` / `bxcc` sequence
//!   at 0x83ec50c..0x83ec518 returns while C is still 0 from the `adc`.
//!   The carry path (0x83ec544..) and both magnitude-subtract pack paths
//!   (`bxne` at 0x83ecce4/0x83eccc8) DO round ties to even. Net effect:
//!   __fadd/__fsub/__frsb magnitude-adds round exact ties away from zero,
//!   e.g. 1.0 + 2^-24 == 1.0 + 1 ulp (IEEE RNE would keep 1.0).
//! * _frnd is NOT a float->float round-to-int. Its exponent math
//!   (`rsb r3, r3, #193`, mask 23) treats the input as a float whose value
//!   is scaled by 2^-43 (bias 170): it rounds a * 2^-43 to an integer with
//!   round-half-even and returns it SIGN-MAGNITUDE (sign<<31 | magnitude,
//!   magnitude < 2^24). It also reads an inbound r2 (continuation/sticky
//!   word) that no live caller in osos sets; this port folds r2 = 0, which
//!   reproduces exact round-half-even for the reachable single-word cases.
//!   Inputs with exp > 193 (|a * 2^-43| >= 2^24, inf, NaN) fall into a
//!   garbage path returning an inverted-sign zero; documented, not fixed.

const SIGN: u32 = 0x8000_0000;
const HIDDEN: u32 = 0x8000_0000; // hidden-bit marker for <<8 significands
const EXP_MASK: u32 = 0x7F80_0000;
const QNAN_CANONICAL: u32 = 0x7FC0_0000; // any NaN operand
const QNAN_INVALID: u32 = 0x7FC0_0001; // inf + (-inf) / inf - inf

/// True when the exponent field is 0 (zero/denormal) or 0xFF (inf/NaN) —
/// the original's `eor`/`tst #0x7f000000` gate for the slow tail.
#[inline]
fn exp_is_special(x: u32) -> bool {
    let exp = (x >> 23) & 0xFF;
    exp == 0 || exp == 0xFF
}

/// ARM `lsr` by a register amount: shifts of 32 or more yield 0.
#[inline]
fn lsr_arm(value: u32, amount: u32) -> u32 {
    if amount >= 32 {
        0
    } else {
        value >> amount
    }
}

/// Bits lost when the smaller significand was aligned right by `exp_diff`,
/// reconstructed exactly like the original's `rsb r3, r3, #32; lsls r1, r1,
/// r3` (ARM register shifts of 32+ yield 0, matching the wrapping `rsb`).
#[inline]
fn alignment_lost_bits(significand: u32, exp_diff: u32) -> u32 {
    let amount = 32u32.wrapping_sub(exp_diff) & 0xFF;
    if amount >= 32 {
        0
    } else {
        significand << amount
    }
}

/// Overflow epilogue shared by both add paths (0x83ec530): the packed
/// result rounded up to exponent 0xFF — return signed infinity.
#[inline]
fn overflow_to_infinity(packed: u32) -> u32 {
    let shifted = packed.wrapping_sub(0x6000_0000);
    (0xFF | (shifted >> 23)) << 23
}

/// Magnitude-add core (0x83ec4d4): both operands normal with a common
/// sign; returns `|a| + |b|` packed under that sign. Contains the
/// no-carry tie quirk documented in the module header.
fn add_magnitude(a: u32, b: u32) -> u32 {
    // Same sign: the unsigned pattern compare orders magnitudes.
    let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
    let hi_field = hi >> 23; // sign<<8 | exponent
    let exp_diff = hi_field - (lo >> 23);
    let lo_sig = HIDDEN | (lo << 8);
    let hi_sig = HIDDEN | (hi << 8);
    let aligned = lsr_arm(lo_sig, exp_diff);
    let sum = hi_sig.wrapping_add(aligned);

    if sum < hi_sig {
        // Carry out: renormalize one place right (rrx with C=1).
        let shifted = (sum >> 1) | HIDDEN;
        let round = (shifted >> 7) & 1;
        let mut packed = (shifted >> 8)
            .wrapping_add(hi_field << 23)
            .wrapping_add(round);
        let sticky = sum & 0xFF;
        if round == 1 && sticky == 0 {
            // Tie: this path rounds to even when the alignment was exact.
            if alignment_lost_bits(lo_sig, exp_diff) == 0 {
                packed &= !1;
            }
        }
        if (packed << 1) >= 0xFF00_0000 {
            return overflow_to_infinity(packed);
        }
        return packed;
    }

    // No carry: hidden bit already in place, exponent pre-decremented.
    let round = (sum >> 7) & 1;
    let packed = (sum >> 8)
        .wrapping_add((hi_field - 1) << 23)
        .wrapping_add(round);
    if round == 0 {
        return packed;
    }
    if sum & 0x7F != 0 {
        if (packed << 1) >= 0xFF00_0000 {
            return overflow_to_infinity(packed);
        }
        return packed;
    }
    // Exact tie: the original returns truncated+1 here (round half away),
    // NOT round-to-even — see the module header. It also skips the
    // overflow check, which is harmless: a tie can only round up into
    // exponent 0xFF from an all-ones (odd) mantissa, where IEEE agrees.
    packed
}

/// Shared tie fixup of the magnitude-subtract core (0x83ecce8): the
/// truncated difference overestimates the true one, so a nonzero
/// alignment remainder rounds DOWN; an exact tie rounds to even.
#[inline]
fn subtract_tie_fixup(packed: u32, lo_sig: u32, exp_diff: u32) -> u32 {
    if alignment_lost_bits(lo_sig, exp_diff) == 0 {
        packed & !1
    } else {
        packed - 1
    }
}

/// Magnitude-subtract core (0x83ecc80): both operands normal with a
/// common sign; returns `a - b`. Pure IEEE round-to-nearest-even with
/// flush-to-zero of denormal results.
fn subtract_magnitude(a: u32, b: u32) -> u32 {
    let (hi, lo) = if a >= b {
        (a, b)
    } else {
        // Result takes the flipped common sign: a - b == -(b - a).
        (b ^ SIGN, a ^ SIGN)
    };
    let hi_field = hi >> 23;
    let exp_diff = hi_field - (lo >> 23);
    let lo_sig = HIDDEN | (lo << 8);
    let hi_sig = HIDDEN | (hi << 8);
    let aligned = lsr_arm(lo_sig, exp_diff);
    let diff = hi_sig.wrapping_sub(aligned);

    if (diff as i32) < 0 {
        // Difference still normalized (hidden bit in place): pack.
        let round = (diff >> 7) & 1;
        let packed = (diff >> 8)
            .wrapping_add((hi_field - 1) << 23)
            .wrapping_add(round);
        if round == 0 {
            return packed;
        }
        if diff & 0x7F != 0 {
            return packed;
        }
        return subtract_tie_fixup(packed, lo_sig, exp_diff);
    }

    // Cancellation: at least one leading zero.
    if hi_field & 0xFE == 0 {
        // Exponent too small to renormalize: true result is denormal.
        return 0; // flush to +0
    }
    let shifted = diff << 1;
    if (shifted as i32) < 0 {
        // Normalized after a single shift (arithmetic pack at 0x83eccb8).
        let round = (shifted >> 7) & 1;
        let packed = (((shifted as i32) >> 8) as u32)
            .wrapping_add(hi_field << 23)
            .wrapping_add(round);
        if round == 0 {
            return packed;
        }
        if diff & 0x3F != 0 {
            return packed;
        }
        return subtract_tie_fixup(packed, lo_sig, exp_diff);
    }

    // Massive cancellation (0x83eccfc): normalize with clz, or flush.
    if shifted == 0 {
        return 0; // exact cancellation: +0
    }
    let reduced = shifted >> 2;
    let zeros = reduced.leading_zeros();
    let new_field = hi_field.wrapping_sub(zeros);
    let significand = reduced.rotate_right((40 - zeros) & 31);
    // The original's `teq r3, r2, lsr #8`: the sign lane survives iff the
    // exponent did not underflow below zero.
    if (new_field >> 8) == (hi_field >> 8) {
        significand.wrapping_add(new_field << 23)
    } else {
        0 // denormal result: flush to +0
    }
}

/// __fadd slow tail (0x83ec568): at least one operand has exponent 0 or
/// 0xFF. Denormal inputs are flushed to zero here.
fn add_specials(a: u32, b: u32) -> u32 {
    let a_abs = a << 1;
    let b_abs = b << 1;
    if a_abs & 0xFF00_0000 == 0xFF00_0000 || b_abs & 0xFF00_0000 == 0xFF00_0000 {
        // Infinity or NaN involved (0x83ec5a0).
        if b_abs > 0xFF00_0000 || a_abs > 0xFF00_0000 {
            return QNAN_CANONICAL; // any NaN operand
        }
        if a_abs == b_abs {
            // Both infinite: same sign keeps it, opposite signs is invalid.
            if (a ^ b) as i32 >= 0 {
                return a;
            }
            return QNAN_INVALID;
        }
        if a_abs == 0xFF00_0000 {
            return a;
        }
        return b;
    }
    // Zero/denormal flush: return the normal operand, else merge zeros.
    if a & EXP_MASK != 0 {
        return a;
    }
    if b & EXP_MASK != 0 {
        return b;
    }
    if a == SIGN && b == SIGN {
        return a; // -0 + -0 == -0
    }
    0
}

/// __fsub slow tail (0x83ecd48), also used by __frsb with operands
/// already swapped.
fn subtract_specials(a: u32, b: u32) -> u32 {
    let a_abs = a << 1;
    let b_abs = b << 1;
    if a_abs & 0xFF00_0000 == 0xFF00_0000 || b_abs & 0xFF00_0000 == 0xFF00_0000 {
        if b_abs > 0xFF00_0000 || a_abs > 0xFF00_0000 {
            return QNAN_CANONICAL;
        }
        if a_abs == b_abs {
            // Both infinite: opposite signs keep a, same sign is invalid.
            if ((a ^ b) as i32) < 0 {
                return a;
            }
            return QNAN_INVALID;
        }
        if a_abs == 0xFF00_0000 {
            return a;
        }
        return b ^ SIGN;
    }
    if a & EXP_MASK != 0 {
        return a;
    }
    if b & EXP_MASK != 0 {
        return b ^ SIGN;
    }
    // Both flushed to zero: -0 - +0 == -0, everything else +0.
    let mut result = if a == SIGN { a } else { 0 };
    if b == SIGN {
        result = 0; // -0 - -0 == +0
    }
    result
}

/// __fadd — original @ 0x083ec4b4. IEEE single-precision add with
/// flush-to-zero of denormal inputs, canonical-NaN output, and the
/// tie-rounds-away quirk documented in the module header.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __fadd(a: u32, b: u32) -> u32 {
    if exp_is_special(a) || exp_is_special(b) {
        return add_specials(a, b);
    }
    if ((a ^ b) as i32) < 0 {
        return subtract_magnitude(a, b ^ SIGN);
    }
    add_magnitude(a, b)
}

/// __fsub — original @ 0x083ecc60. IEEE single-precision subtract with
/// the same conventions as `__fadd`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __fsub(a: u32, b: u32) -> u32 {
    if exp_is_special(a) || exp_is_special(b) {
        return subtract_specials(a, b);
    }
    if ((a ^ b) as i32) < 0 {
        return add_magnitude(a, b ^ SIGN);
    }
    subtract_magnitude(a, b)
}

/// __frsb — original @ 0x083ecc28. Reverse subtract: `__frsb(a, b)` is
/// `b - a`, computed by negating a and dispatching to the shared cores.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __frsb(a: u32, b: u32) -> u32 {
    if exp_is_special(a) || exp_is_special(b) {
        // The original swaps the pair with three eors, then tails the
        // __fsub specials: specials(b, a) computes b - a.
        return subtract_specials(b, a);
    }
    let neg_a = a ^ SIGN;
    if (neg_a ^ b) as i32 >= 0 {
        return add_magnitude(neg_a, b);
    }
    subtract_magnitude(neg_a, b ^ SIGN)
}

/// Round-to-nearest-even tail, original @ 0x83ecdc4 (`_frnd`).
///
/// NOT a float round-to-int: the input is treated as a float scaled by
/// 2^-43 (exponent bias 170) and the result is a sign-magnitude integer.
/// `sticky_word` is the original's inbound r2 continuation word; no live
/// caller in osos sets it, so the export below passes 0.
fn frnd_tail(a: u32, sticky_word: u32) -> u32 {
    let biased = (a & SIGN) | (a >> 23);
    let biased = biased & !0x100; // drop the duplicated sign lane
    let remain = 193u32.wrapping_sub(biased); // r3 throughout
    let magnitude = remain & !SIGN; // 193 - exp (mod 2^31)

    if magnitude <= 23 {
        // 170 <= exp <= 193: 1 <= |a * 2^-43| < 2^24, rounding is live.
        let frac_shift = 32u32.wrapping_sub(remain) & 0xFF; // exp - 161
        let fraction = if frac_shift >= 32 {
            0
        } else {
            a << frac_shift
        };
        let back = 32u32.wrapping_sub(32u32.wrapping_sub(remain)); // == remain
        let significand = (a & 0x00FF_FFFF) | 0x0080_0000;
        let integer = significand >> (back & 0xFF);
        let mut packed = integer | (back & SIGN);
        if fraction == 0 {
            return packed;
        }
        let doubled = fraction << 1;
        if fraction as i32 >= 0 {
            return packed; // round bit clear
        }
        if doubled != 0 {
            return packed + 1; // above half: round up
        }
        // Exactly half in this word: consult the continuation word.
        // mvns r3, r2, asr #31 → Z set iff r2 negative, C = r2 bit 30.
        let mvn = !((sticky_word as i32) >> 31);
        let zero = mvn == 0;
        let carry = (sticky_word >> 30) & 1 != 0;
        if !carry || zero {
            packed = packed.wrapping_add(1); // addls
        }
        if !carry && !zero {
            packed &= !1; // biccc
        }
        return packed;
    }

    // cmp r1, #0x80000019: V is set for every magnitude > 23 except 24
    // (exp == 169, |a * 2^-43| in [0.5, 1)).
    let (_, overflow) = (magnitude as i32).overflowing_sub(0x8000_0019u32 as i32);
    if overflow {
        // exp < 169 → ±0; exp > 193 → garbage inverted-sign zero (the
        // original never guards it — its callers kept the range).
        return remain & SIGN;
    }
    // exp == 169: round |v| in [0.5, 1) to 0 or 1.
    let mantissa_zero = (a << 9) == 0;
    let mut packed = remain & SIGN;
    packed = packed.wrapping_add(1);
    if mantissa_zero && sticky_word & SIGN == 0 {
        packed &= !1; // exactly 0.5 with neutral continuation: to even
    }
    packed
}

/// _frnd — original @ 0x83ecdc4. Dead-linked shared rounding tail; see
/// `frnd_tail` and the module header for the actual semantics.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _frnd(a: u32) -> u32 {
    frnd_tail(a, 0)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    // ---- oracle helpers (host IEEE + documented ADS deviations) --------

    /// Flush a denormal/zero exponent to signed zero, as the originals do.
    fn flush(x: u32) -> u32 {
        if (x >> 23) & 0xFF == 0 {
            x & SIGN
        } else {
            x
        }
    }

    fn is_nan(x: u32) -> bool {
        (x << 1) > 0xFF00_0000
    }

    fn is_inf(x: u32) -> bool {
        (x << 1) == 0xFF00_0000
    }

    /// Independent integer reference for the magnitude-add core.
    /// Returns (packed result, tie_quirk_fired).
    fn ref_mag_add(sign: u32, ea: u32, ma: u32, eb: u32, mb: u32) -> (u32, bool) {
        let (eh, mh, el, ml) = if (ea, ma) >= (eb, mb) {
            (ea, ma, eb, mb)
        } else {
            (eb, mb, ea, ma)
        };
        let d = eh - el;
        let big = (0x80_0000u64 | mh as u64) << 24;
        let small = 0x80_0000u64 | ml as u64;
        let aligned = if d >= 32 { 0 } else { (small << 24) >> d };
        let lost = d > 24 && (d >= 48 || (small & ((1u64 << (d - 24)) - 1)) != 0);
        let sum = big + aligned; // < 2^49
        let (mut e, sig24, round, sticky) = if sum >= (1u64 << 48) {
            (
                eh + 1,
                (sum >> 25) as u32,
                ((sum >> 24) & 1) as u32,
                (sum & 0xFF_FFFF) != 0 || lost,
            )
        } else {
            (
                eh,
                (sum >> 24) as u32,
                ((sum >> 23) & 1) as u32,
                (sum & 0x7F_FFFF) != 0 || lost,
            )
        };
        let mut sig = sig24;
        let mut quirk = false;
        if round == 1 {
            if sticky {
                sig += 1;
            } else if sum >= (1u64 << 48) {
                sig = (sig + 1) & !1; // carry path: round-to-even
            } else {
                sig += 1; // no-carry path: ADS tie quirk (half away)
                quirk = true;
            }
        }
        if sig >= (1 << 24) {
            sig >>= 1;
            e += 1;
        }
        if e >= 0xFF {
            return (sign | 0x7F80_0000, quirk);
        }
        (sign | (e << 23) | (sig & 0x7F_FFFF), quirk)
    }

    /// Independent integer reference for the magnitude-subtract core
    /// (pure RNE, flush-to-zero of denormal results).
    fn ref_mag_sub(sign: u32, ea: u32, ma: u32, eb: u32, mb: u32) -> u32 {
        let d = ea - eb;
        let big = (0x80_0000u64 | ma as u64) << 24;
        let small = 0x80_0000u64 | mb as u64;
        let aligned = if d >= 32 { 0 } else { (small << 24) >> d };
        let lost = d > 24 && (d >= 48 || (small & ((1u64 << (d - 24)) - 1)) != 0);
        let diff = big - aligned; // overestimates the true difference
        if diff == 0 && !lost {
            return 0;
        }
        let shift = diff.leading_zeros() - 16; // top bit to position 47
        let v = diff << shift;
        let e = ea as i32 - shift as i32;
        if e < 1 {
            return 0; // denormal result: flush to +0
        }
        let mut sig = (v >> 24) as u32;
        let round = (v >> 23) & 1 != 0;
        let vsticky = (v & 0x7F_FFFF) != 0;
        if round {
            if vsticky {
                sig += 1; // true fraction > 1/2
            } else if lost {
                // tie in v, but the true value is below half: round down
            } else {
                sig = (sig + 1) & !1; // exact tie: round to even
            }
        }
        let mut e = e as u32;
        if sig >= (1 << 24) {
            sig >>= 1;
            e += 1;
        }
        sign | (e << 23) | (sig & 0x7F_FFFF)
    }

    /// Full reference for __fadd: (bits, quirk_fired).
    fn ref_fadd(a: u32, b: u32) -> (u32, bool) {
        let fa = flush(a);
        let fb = flush(b);
        let ea = (fa >> 23) & 0xFF;
        let eb = (fb >> 23) & 0xFF;
        if ea == 0xFF || eb == 0xFF {
            if is_nan(fa) || is_nan(fb) {
                return (QNAN_CANONICAL, false);
            }
            if is_inf(fa) && is_inf(fb) {
                if fa == fb {
                    return (fa, false);
                }
                return (QNAN_INVALID, false);
            }
            return (if is_inf(fa) { fa } else { fb }, false);
        }
        if ea == 0 || eb == 0 {
            if ea != 0 {
                return (fa, false);
            }
            if eb != 0 {
                return (fb, false);
            }
            // The original compares the RAW operands against -0 here.
            if a == SIGN && b == SIGN {
                return (SIGN, false);
            }
            return (0, false);
        }
        let (sa, ma) = (fa & SIGN, fa & 0x7F_FFFF);
        let (sb, mb) = (fb & SIGN, fb & 0x7F_FFFF);
        if sa == sb {
            ref_mag_add(sa, ea, ma, eb, mb)
        } else if (ea, ma) >= (eb, mb) {
            (ref_mag_sub(sa, ea, ma, eb, mb), false)
        } else {
            (ref_mag_sub(sb, eb, mb, ea, ma), false)
        }
    }

    /// Full reference for __fsub: (bits, quirk_fired).
    fn ref_fsub(a: u32, b: u32) -> (u32, bool) {
        let fa = flush(a);
        let fb = flush(b);
        let ea = (fa >> 23) & 0xFF;
        let eb = (fb >> 23) & 0xFF;
        if ea == 0xFF || eb == 0xFF {
            if is_nan(fa) || is_nan(fb) {
                return (QNAN_CANONICAL, false);
            }
            if is_inf(fa) && is_inf(fb) {
                if fa != fb {
                    return (fa, false);
                }
                return (QNAN_INVALID, false);
            }
            return (if is_inf(fa) { fa } else { fb ^ SIGN }, false);
        }
        if ea == 0 || eb == 0 {
            if ea != 0 {
                return (fa, false);
            }
            if eb != 0 {
                return (fb ^ SIGN, false);
            }
            // Raw-operand compares: -0 - +0 == -0, -0 - -0 == +0.
            if a == SIGN && b != SIGN {
                return (SIGN, false);
            }
            return (0, false);
        }
        let (sa, ma) = (fa & SIGN, fa & 0x7F_FFFF);
        let (sb, mb) = (fb & SIGN, fb & 0x7F_FFFF);
        if sa != sb {
            ref_mag_add(sa, ea, ma, eb, mb)
        } else if (ea, ma) >= (eb, mb) {
            (ref_mag_sub(sa, ea, ma, eb, mb), false)
        } else {
            (ref_mag_sub(sa ^ SIGN, eb, mb, ea, ma), false)
        }
    }

    /// Host f32 oracle with ADS flushing/canonicalization applied.
    fn host_fadd(a: u32, b: u32) -> u32 {
        let fa = flush(a);
        let fb = flush(b);
        if is_nan(fa) || is_nan(fb) {
            return QNAN_CANONICAL;
        }
        if is_inf(fa) && is_inf(fb) && fa != fb {
            return QNAN_INVALID;
        }
        // Both flushed to zero: the original merges with RAW -0 compares.
        if (fa << 1) == 0 && (fb << 1) == 0 {
            return if a == SIGN && b == SIGN { SIGN } else { 0 };
        }
        let r = (f32::from_bits(fa) + f32::from_bits(fb)).to_bits();
        if (r << 1) != 0 && (r >> 23) & 0xFF == 0 {
            0 // denormal result flushes to +0
        } else {
            r
        }
    }

    fn host_fsub(a: u32, b: u32) -> u32 {
        let fa = flush(a);
        let fb = flush(b);
        if is_nan(fa) || is_nan(fb) {
            return QNAN_CANONICAL;
        }
        if is_inf(fa) && is_inf(fb) && fa == fb {
            return QNAN_INVALID;
        }
        if (fa << 1) == 0 && (fb << 1) == 0 {
            return if a == SIGN && b != SIGN { SIGN } else { 0 };
        }
        let r = (f32::from_bits(fa) - f32::from_bits(fb)).to_bits();
        if (r << 1) != 0 && (r >> 23) & 0xFF == 0 {
            0
        } else {
            r
        }
    }

    // ---- structured cases ----------------------------------------------

    #[test]
    fn zero_and_denormal_flush() {
        let (pzero, nzero) = (0x0000_0000u32, 0x8000_0000u32);
        let (dn_min, dn_max) = (0x0000_0001u32, 0x007F_FFFFu32);
        let min_normal = 0x0080_0000u32;
        unsafe {
            // Signed-zero rules match IEEE RNE.
            assert_eq!(__fadd(nzero, nzero), nzero);
            assert_eq!(__fadd(nzero, pzero), pzero);
            assert_eq!(__fadd(pzero, nzero), pzero);
            assert_eq!(__fsub(nzero, pzero), nzero);
            assert_eq!(__fsub(nzero, nzero), pzero);
            assert_eq!(__fsub(pzero, nzero), pzero);
            // Denormal inputs flush: normal operand returned unchanged.
            assert_eq!(__fadd(min_normal, dn_max), min_normal);
            assert_eq!(__fadd(dn_max, min_normal), min_normal);
            assert_eq!(__fsub(min_normal, dn_max), min_normal);
            assert_eq!(__fsub(dn_min, min_normal), min_normal | SIGN);
            assert_eq!(__fadd(dn_min, dn_max), pzero); // both flushed
            assert_eq!(__fadd(dn_min | SIGN, dn_max | SIGN), pzero); // raw != -0
            assert_eq!(__fsub(dn_min, dn_min), pzero);
        }
    }

    #[test]
    fn infinities_and_nans() {
        let (pinf, ninf) = (0x7F80_0000u32, 0xFF80_0000u32);
        let one = 0x3F80_0000u32;
        unsafe {
            assert_eq!(__fadd(pinf, one), pinf);
            assert_eq!(__fadd(one, ninf), ninf);
            assert_eq!(__fadd(pinf, pinf), pinf);
            assert_eq!(__fadd(ninf, ninf), ninf);
            assert_eq!(__fadd(pinf, ninf), QNAN_INVALID); // 0x7FC00001
            assert_eq!(__fadd(ninf, pinf), QNAN_INVALID);
            assert_eq!(__fsub(pinf, ninf), pinf);
            assert_eq!(__fsub(ninf, ninf), QNAN_INVALID);
            assert_eq!(__fsub(pinf, pinf), QNAN_INVALID);
            assert_eq!(__fsub(one, pinf), ninf);
            // NaN canonicalization: payload and sign are dropped.
            for nan in [0x7FC0_0000u32, 0x7F80_0001, 0xFFC0_0000, 0x7FFF_FFFF] {
                assert_eq!(__fadd(nan, one), QNAN_CANONICAL, "nan {nan:#x}");
                assert_eq!(__fadd(one, nan), QNAN_CANONICAL, "nan {nan:#x}");
                assert_eq!(__fsub(nan, one), QNAN_CANONICAL);
                assert_eq!(__fsub(one, nan), QNAN_CANONICAL);
                assert_eq!(__fadd(nan, pinf), QNAN_CANONICAL);
                assert_eq!(__fadd(nan, nan), QNAN_CANONICAL);
                assert_eq!(__frsb(nan, one), QNAN_CANONICAL);
                assert_eq!(__frsb(one, nan), QNAN_CANONICAL);
            }
            assert_eq!(__frsb(pinf, pinf), QNAN_INVALID); // inf - inf
            assert_eq!(__frsb(pinf, ninf), ninf); // -inf - inf
            assert_eq!(__frsb(one, pinf), pinf); // inf - 1
        }
    }

    #[test]
    fn tie_quirk_cases() {
        unsafe {
            // Exact tie in the no-carry add path: ADS rounds half away.
            // 1.0 + 2^-24: IEEE RNE keeps 1.0 (even), ADS gives 1 ulp up.
            assert_eq!(__fadd(0x3F80_0000, 0x3380_0000), 0x3F80_0001);
            assert_eq!(host_fadd(0x3F80_0000, 0x3380_0000), 0x3F80_0000);
            // Same with a negative common sign: away == more negative.
            assert_eq!(__fadd(0xBF80_0000, 0xB380_0000), 0xBF80_0001);
            // d = 2 tie: 1.0 + 0.25*(1 + 2*2^-23): RNE 0x3FA00000, ADS +1.
            assert_eq!(__fadd(0x3F80_0000, 0x3E80_0002), 0x3FA0_0001);
            assert_eq!(host_fadd(0x3F80_0000, 0x3E80_0002), 0x3FA0_0000);
            // Odd truncation: quirk and RNE agree.
            assert_eq!(__fadd(0x3F80_0001, 0x3380_0000), 0x3F80_0002);
            // Tie spoiled by alignment sticky: both round up.
            assert_eq!(__fadd(0x3F80_0000, 0x3380_0001), 0x3F80_0001);
            // __fsub reaches the same core with opposite signs.
            assert_eq!(__fsub(0x3F80_0000, 0xB380_0000), 0x3F80_0001);
            // Carry-path tie rounds to EVEN: 0x3FFFFFFF + 2^-22 is a tie
            // between 2.0 and 2.0+ulp; both ADS and IEEE pick 2.0.
            assert_eq!(__fadd(0x3FFF_FFFF, 0x3480_0000), 0x4000_0000);
            // Magnitude-subtract ties are round-to-even (no quirk).
            // 1+2^-22 minus 2^-24: tie between 1+ulp and 1+2ulp → even.
            assert_eq!(__fsub(0x3F80_0002, 0x3380_0000), 0x3F80_0002);
            // 1+3*2^-22 minus 2^-24: tie between 1+5ulp and 1+6ulp → 6.
            assert_eq!(__fsub(0x3F80_0006, 0x3380_0000), 0x3F80_0006);
            assert_eq!(host_fsub(0x3F80_0006, 0x3380_0000), 0x3F80_0006);
        }
    }

    #[test]
    fn cancellation_and_underflow() {
        unsafe {
            // x - x == +0.
            assert_eq!(__fsub(0x3F80_0000, 0x3F80_0000), 0);
            assert_eq!(__fsub(0xBF80_0000, 0xBF80_0000), 0);
            // Multi-bit cancellation with renormalization.
            assert_eq!(__fsub(0x3F80_0000, 0x3F7F_FFFF), 0x3380_0000); // 2^-24
            assert_eq!(__fsub(0x3F80_0000, 0x3F00_0000), 0x3F00_0000); // 0.5
            // Denormal results flush to +0 (min_normal - 1 ulp there).
            assert_eq!(__fsub(0x0080_0001, 0x0080_0000), 0);
            assert_eq!(__fsub(0x0080_0000, 0x0080_0001), 0); // flushes to +0
            // Rounding into the exponent: just-below-1 + 2^-24 == 2.0.
            assert_eq!(__fadd(0x3F7F_FFFF, 0x3380_0000), 0x3F80_0000);
            // Overflow to infinity, both signs.
            let max = 0x7F7F_FFFFu32;
            assert_eq!(__fadd(max, max), 0x7F80_0000);
            assert_eq!(__fadd(max | SIGN, max | SIGN), 0xFF80_0000);
            assert_eq!(__fsub(max, max | SIGN), 0x7F80_0000);
        }
    }

    #[test]
    fn frsb_matches_swapped_fsub() {
        let samples: Vec<u32> = std::vec![
            0, 1, SIGN, SIGN | 1, 0x3F80_0000, 0xBF80_0000, 0x3380_0000,
            0x3E80_0002, 0x7F80_0000, 0xFF80_0000, 0x7FC0_0000, 0x7F80_0001,
            0x007F_FFFF, 0x0080_0000, 0x7F7F_FFFF, 0x3FFF_FFFF, 0x3480_0000,
        ];
        unsafe {
            for &a in &samples {
                for &b in &samples {
                    assert_eq!(__frsb(a, b), __fsub(b, a), "frsb({a:#x}, {b:#x})");
                }
            }
        }
    }

    // ---- randomized sweeps: reference + host cross-check ----------------

    struct XorShift(u32);
    impl XorShift {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            self.0
        }
    }

    fn sample_pool() -> Vec<u32> {
        let mut rng = XorShift(0x1234_5678);
        let mut pool: Vec<u32> = std::vec![
            0, 1, SIGN, SIGN | 1, 0x007F_FFFF, 0x0080_0000, 0x8080_0000,
            0x3F80_0000, 0xBF80_0000, 0x3F80_0001, 0x3380_0000, 0x3E80_0002,
            0x7F80_0000, 0xFF80_0000, 0x7FC0_0000, 0xFF80_0001, 0x7FFF_FFFF,
            0x7F7F_FFFF, 0xFF7F_FFFF, 0x3FFF_FFFF, 0x3480_0000, 0x0000_0002,
        ];
        for _ in 0..3000 {
            let r = rng.next();
            pool.push(match r & 3 {
                // Fully random.
                0 => r,
                // Small exponent difference with the previous entry: hits
                // alignment, rounding, tie and cancellation paths.
                1 => {
                    let prev = *pool.last().unwrap();
                    let exp = (prev >> 23) & 0xFF;
                    let nudge = (r >> 24) % 4;
                    let exp = exp.saturating_sub(nudge).max(1);
                    (prev & SIGN) | (exp << 23) | (r & 0x7F_FFFF)
                }
                // Exponents near the extremes.
                2 => (r & 0x807F_FFFF) | ((r >> 16) & 0x7F80_0000),
                // Tiny exponents (denormal boundary).
                _ => r & 0x80FF_FFFF,
            });
        }
        pool
    }

    #[test]
    fn fadd_sweep_matches_reference_and_host() {
        let pool = sample_pool();
        unsafe {
            for (i, &a) in pool.iter().enumerate() {
                for &b in pool.iter().skip(i.saturating_sub(4)).take(9) {
                    let (expect, quirk) = ref_fadd(a, b);
                    assert_eq!(__fadd(a, b), expect, "fadd({a:#x}, {b:#x})");
                    let host = host_fadd(a, b);
                    if quirk {
                        // No-carry tie: quirk matches RNE when the
                        // truncated mantissa was odd, else 1 ulp away.
                        let delta = (expect & !SIGN).wrapping_sub(host & !SIGN);
                        assert!(delta <= 1, "quirk shape fadd({a:#x}, {b:#x})");
                    } else {
                        assert_eq!(expect, host, "host fadd({a:#x}, {b:#x})");
                    }
                }
            }
        }
    }

    #[test]
    fn fsub_sweep_matches_reference_and_host() {
        let pool = sample_pool();
        unsafe {
            for (i, &a) in pool.iter().enumerate() {
                for &b in pool.iter().skip(i.saturating_sub(4)).take(9) {
                    let (expect, quirk) = ref_fsub(a, b);
                    assert_eq!(__fsub(a, b), expect, "fsub({a:#x}, {b:#x})");
                    let host = host_fsub(a, b);
                    if quirk {
                        let delta = (expect & !SIGN).wrapping_sub(host & !SIGN);
                        assert!(delta <= 1, "quirk shape fsub({a:#x}, {b:#x})");
                    } else {
                        assert_eq!(expect, host, "host fsub({a:#x}, {b:#x})");
                    }
                    assert_eq!(__frsb(a, b), __fsub(b, a), "frsb({a:#x}, {b:#x})");
                }
            }
        }
    }

    // ---- _frnd ------------------------------------------------------------

    #[test]
    fn frnd_vectors() {
        unsafe {
            // The original is NOT f32::round: it rounds a * 2^-43 to a
            // sign-magnitude integer (dead tail, see module header). These
            // are the original's true outputs for the suggested inputs.
            assert_eq!(_frnd(0x3F00_0000), 0); // 0.5f → +0
            assert_eq!(_frnd(0x3FC0_0000), 0); // 1.5f → +0
            assert_eq!(_frnd(0x4020_0000), 0); // 2.5f → +0
            assert_eq!(_frnd(0xC020_0000), SIGN); // -2.5f → -0
            // Large (exp > 193): garbage inverted-sign zero, as shipped.
            assert_eq!(_frnd(0x7149_F2C9), SIGN); // +1e30f
            assert_eq!(_frnd(0xF149_F2C9), 0); // -1e30f
            // No-fraction middle-range values round-trip.
            assert_eq!(_frnd(0x56C0_0000), 12); // 12.0 (bias 170)
            assert_eq!(_frnd(0x5700_0000), 16); // 16.0
            // Live rounding: 12.75 → 13, ties to even (11.5/12.5 → 12).
            assert_eq!(_frnd(0x56CC_0000), 13);
            assert_eq!(_frnd(0x56B8_0000), 12);
            assert_eq!(_frnd(0x56C8_0000), 12);
            assert_eq!(_frnd(0xD6CC_0000), SIGN | 13); // sign-magnitude
            // Denormal/zero inputs flush to signed zero.
            assert_eq!(_frnd(0x0000_0001), 0);
            assert_eq!(_frnd(0x8000_0001), SIGN);
            // NaN/inf fall into the exp > 193 garbage path.
            assert_eq!(_frnd(0x7FC0_0000), SIGN);
            assert_eq!(_frnd(0xFFC0_0000), 0);
        }
    }

    #[test]
    fn frnd_sweep_matches_scaled_round_to_int() {
        let mut rng = XorShift(0xABCD_EF01);
        unsafe {
            for _ in 0..20_000 {
                let exp = 150 + rng.next() % 44; // 150..=193
                let a = (rng.next() & SIGN) | (exp << 23) | (rng.next() & 0x7F_FFFF);
                let v = f32::from_bits(a) as f64 * 2f64.powi(-43);
                let expected = (a & SIGN) | (v.abs().round_ties_even() as u32);
                assert_eq!(_frnd(a), expected, "frnd({a:#010x})");
            }
        }
    }
}
