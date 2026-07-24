//! Ports of the ARM ADS 1.0.1 soft-float compare family. The originals do
//! not return a value at all: they end in `mov pc, lr` right after a `cmp`,
//! so the *CPSR condition flags* are the result. Compiler-generated callers
//! test only the unsigned conditions (C and Z): after `bl __dcmplt` a `blo`
//! is taken iff a < b, and the NaN path deliberately returns C=1, Z=0 so
//! that every ordered predicate (lt/le/gt/ge) reads false when unordered.
//!
//! Originals (retailOS osos, load base 0x08000000):
//!   __dcmpeq        @ 0x083eb748 (260 B) — descriptor 0x04120019 on NaN
//!   __dcmplt/le     @ 0x083eb9c0 (132 B) — descriptor 0x04160019 on NaN
//!   __dcmpgt/ge     @ 0x083ebe38 (156 B) — descriptor 0x04160019, plus a
//!                     3-eor swap of the operand register pair on the NaN
//!                     path so the shared handler keeps the b-vs-a direction
//!   __fcmpeq        @ 0x083ec820 (216 B) — descriptor 0x04120009 on NaN
//!   __fcmplt/le     @ 0x083ec9a8 (116 B) — descriptor 0x04160009 on NaN
//!   __fcmpgt/ge     @ 0x083ecba4 (128 B) — descriptor 0x04160009 + eor swap
//!
//! SOFT-FLOAT CALLING CONVENTION: doubles are u64 and floats are u32 IEEE
//! bit patterns (r1:r0 / r0). Rust cannot return CPU flags, so each export
//! returns the four flag bits packed as N=8, Z=4, C=2, V=1 (ARM CPSR top
//! nibble semantics, as after `cmp`):
//!
//!   outcome     N Z C V   value
//!   a < b       1 0 0 0   0x8
//!   a == b      0 1 1 0   0x6
//!   a > b       0 0 1 0   0x2
//!   unordered   1 0 1 0   0xA   (either operand NaN)
//!
//! The gt/ge variants return the flags for the *swapped* comparison
//! (b vs a): a > b reads as the 0x8 "less" pattern, a < b as 0x2. This is
//! exactly what the original bodies do — they compare r3 against r1 in the
//! positive/mixed paths — and what their callers rely on.
//!
//! Behavioral notes verified against the disassembly:
//! * DENORMALS ARE FLUSHED TO ZERO. When both exponents are zero the
//!   original jumps straight to an `equal` return without looking at the
//!   mantissas, so any two same-exponent-0 values (zeros/denormals of
//!   either sign) compare equal. Denormal vs normal still orders
//!   correctly via the plain integer compare. This port reproduces the
//!   flush (it is NOT IEEE 754 behavior) and the host tests flush the
//!   oracle the same way.
//! * NaN handling: the original jumps to a shared handler (doubles
//!   0x083eb154, floats 0x083eb1d4) with an fp-error descriptor in ip.
//!   Infinities fall through to a plain compare; a genuine NaN takes the
//!   error route which — traps disabled, the only configuration retailOS
//!   uses — converges for every descriptor variant on the flag pattern
//!   N=1, Z=0, C=1, V=0 (via `mvn r1, ip, lsl #15; lsls r1, r1, #1` at
//!   0x083ed1d4). Signaling/quiet NaNs and payloads are not
//!   distinguished. We return 0xA directly instead of modelling
//!   __fp_error/__fp_trap.
//! * V flag: the original's mixed-sign finite path (`cmp r3, r1` with
//!   opposite signs) can leave V=1 and N reflecting the raw high-word
//!   subtraction. No caller can observe this — the compiler only emits
//!   unsigned condition tests after these calls — so this port always
//!   returns the canonical V=0 patterns above.
//! * The eq and lt/le double bodies are instruction-identical except for
//!   the descriptor word, and both NaN routes yield identical flags, so
//!   __dcmpeq/__dcmplt/__dcmple are one implementation here (likewise for
//!   the float trio).
//!
//! The module uses pure integer bit manipulation only — never f32/f64
//! arithmetic, which would lower to the very helpers being ported.

use core::cmp::Ordering;

/// Packed condition-flag results (N=8, Z=4, C=2, V=1).
pub const FLAGS_LESS: u32 = 0x8; // N
pub const FLAGS_EQUAL: u32 = 0x6; // Z|C
pub const FLAGS_GREATER: u32 = 0x2; // C
pub const FLAGS_UNORDERED: u32 = 0xA; // N|C

/// Double with exponent field 0x7FF and zero mantissa, shifted left by 1
/// (sign bit shifted out). `(bits << 1) > D_INF_X2` iff `bits` is a NaN.
const D_INF_X2: u64 = 0xFFE0_0000_0000_0000;
/// Float Infinity, shifted left by 1.
const F_INF_X2: u32 = 0xFF00_0000;

/// Flush a double bit pattern with exponent field 0 (zero or denormal) to
/// a signed zero, matching the original's compare-time flush-to-zero.
#[inline]
fn d_flush_zero(bits: u64) -> u64 {
    // (bits << 1) < 2^53  <=>  exponent field is 0.
    if (bits << 1) < (1u64 << 53) {
        bits & (1u64 << 63) // keep only the sign
    } else {
        bits
    }
}

/// Float counterpart of `d_flush_zero`.
#[inline]
fn f_flush_zero(bits: u32) -> u32 {
    // (bits << 1) < 2^24  <=>  exponent field is 0.
    if (bits << 1) < (1u32 << 24) {
        bits & (1u32 << 31)
    } else {
        bits
    }
}

/// Idiomatic Rust helper: compare two doubles given as IEEE bit patterns,
/// with the original's denormal flush-to-zero semantics. Returns `None`
/// when either operand is a NaN (the original's unordered/descriptor
/// route). Never uses host floating point.
pub fn dcmp(a: u64, b: u64) -> Option<Ordering> {
    let a = d_flush_zero(a);
    let b = d_flush_zero(b);
    if (a << 1) > D_INF_X2 || (b << 1) > D_INF_X2 {
        return None; // NaN: exp all-ones with a nonzero mantissa
    }
    Some(cmp_sign_magnitude_64(a, b))
}

/// Idiomatic Rust helper: compare two floats given as IEEE bit patterns,
/// same semantics as `dcmp`.
pub fn fcmp(a: u32, b: u32) -> Option<Ordering> {
    let a = f_flush_zero(a);
    let b = f_flush_zero(b);
    if (a << 1) > F_INF_X2 || (b << 1) > F_INF_X2 {
        return None;
    }
    Some(cmp_sign_magnitude_32(a, b))
}

/// Ordered compare of two non-NaN sign-magnitude patterns (denormals
/// already flushed). Comparing the signless patterns `(x << 1)` orders
/// magnitudes correctly, zeros of either sign included.
#[inline]
fn cmp_sign_magnitude_64(a: u64, b: u64) -> Ordering {
    let sign_a = (a >> 63) != 0;
    let sign_b = (b >> 63) != 0;
    if sign_a != sign_b {
        // Opposite signs: +0 vs -0 is the only equal pair here (both
        // signless patterns zero); otherwise the negative one is smaller.
        if (a << 1) == 0 && (b << 1) == 0 {
            Ordering::Equal
        } else if sign_a {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    } else {
        let mag = (a << 1).cmp(&(b << 1));
        if sign_a {
            mag.reverse() // both negative: bigger magnitude is smaller
        } else {
            mag
        }
    }
}

/// Float counterpart of `cmp_sign_magnitude_64`.
#[inline]
fn cmp_sign_magnitude_32(a: u32, b: u32) -> Ordering {
    let sign_a = (a >> 31) != 0;
    let sign_b = (b >> 31) != 0;
    if sign_a != sign_b {
        if (a << 1) == 0 && (b << 1) == 0 {
            Ordering::Equal
        } else if sign_a {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    } else {
        let mag = (a << 1).cmp(&(b << 1));
        if sign_a {
            mag.reverse()
        } else {
            mag
        }
    }
}

/// Map an ordering result onto the original's packed flag pattern.
#[inline]
fn flags_of(ord: Option<Ordering>) -> u32 {
    match ord {
        Some(Ordering::Less) => FLAGS_LESS,
        Some(Ordering::Equal) => FLAGS_EQUAL,
        Some(Ordering::Greater) => FLAGS_GREATER,
        None => FLAGS_UNORDERED,
    }
}

/// __dcmpeq — original @ 0x083eb748. `a`/`b` are u64 double bit patterns.
/// Returns packed flags (see module header); only Z matters to eq callers.
#[no_mangle]
pub extern "C" fn __dcmpeq(a: u64, b: u64) -> u32 {
    flags_of(dcmp(a, b))
}

/// __dcmplt — original @ 0x083eb9c0 (shared with __dcmple). Flags of a vs b.
#[no_mangle]
pub extern "C" fn __dcmplt(a: u64, b: u64) -> u32 {
    flags_of(dcmp(a, b))
}

/// __dcmple — alias of __dcmplt in the original (same address).
#[no_mangle]
pub extern "C" fn __dcmple(a: u64, b: u64) -> u32 {
    flags_of(dcmp(a, b))
}

/// __dcmpgt — original @ 0x083ebe38 (shared with __dcmpge). Returns the
/// flags of the *swapped* comparison b vs a, like the original bodies
/// (`cmp r3, r1`) and the 3-eor operand swap on the NaN path.
#[no_mangle]
pub extern "C" fn __dcmpgt(a: u64, b: u64) -> u32 {
    flags_of(dcmp(b, a))
}

/// __dcmpge — alias of __dcmpgt in the original (same address).
#[no_mangle]
pub extern "C" fn __dcmpge(a: u64, b: u64) -> u32 {
    flags_of(dcmp(b, a))
}

/// __fcmpeq — original @ 0x083ec820. `a`/`b` are u32 float bit patterns.
#[no_mangle]
pub extern "C" fn __fcmpeq(a: u32, b: u32) -> u32 {
    flags_of(fcmp(a, b))
}

/// __fcmplt — original @ 0x083ec9a8 (shared with __fcmple).
#[no_mangle]
pub extern "C" fn __fcmplt(a: u32, b: u32) -> u32 {
    flags_of(fcmp(a, b))
}

/// __fcmple — alias of __fcmplt in the original (same address).
#[no_mangle]
pub extern "C" fn __fcmple(a: u32, b: u32) -> u32 {
    flags_of(fcmp(a, b))
}

/// __fcmpgt — original @ 0x083ecba4 (shared with __fcmpge). Swapped
/// direction: flags of b vs a.
#[no_mangle]
pub extern "C" fn __fcmpgt(a: u32, b: u32) -> u32 {
    flags_of(fcmp(b, a))
}

/// __fcmpge — alias of __fcmpgt in the original (same address).
#[no_mangle]
pub extern "C" fn __fcmpge(a: u32, b: u32) -> u32 {
    flags_of(fcmp(b, a))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;
    use std::vec::Vec;

    // ---- host oracles -------------------------------------------------
    // The originals flush exponent-0 values to signed zero, so the host
    // IEEE oracle must be flushed the same way before partial_cmp.

    fn host_dcmp(a: u64, b: u64) -> Option<Ordering> {
        let fa = f64::from_bits(d_flush_zero(a));
        let fb = f64::from_bits(d_flush_zero(b));
        fa.partial_cmp(&fb)
    }

    fn host_fcmp(a: u32, b: u32) -> Option<Ordering> {
        let fa = f32::from_bits(f_flush_zero(a));
        let fb = f32::from_bits(f_flush_zero(b));
        fa.partial_cmp(&fb)
    }

    fn host_flags(ord: Option<Ordering>) -> u32 {
        flags_of(ord)
    }

    // ---- flag mapping (documented semantics of the original) ----------

    #[test]
    fn flag_patterns_match_original() {
        // less: N=1 Z=0 C=0 V=0; equal: Z=1 C=1; greater: C=1; unordered: N=1 C=1
        assert_eq!(flags_of(Some(Ordering::Less)), 0x8);
        assert_eq!(flags_of(Some(Ordering::Equal)), 0x6);
        assert_eq!(flags_of(Some(Ordering::Greater)), 0x2);
        assert_eq!(flags_of(None), 0xA);
        // Concretely through the exports.
        assert_eq!(__dcmplt(1.0f64.to_bits(), 2.0f64.to_bits()), FLAGS_LESS);
        assert_eq!(__dcmplt(2.0f64.to_bits(), 1.0f64.to_bits()), FLAGS_GREATER);
        assert_eq!(__dcmplt(1.0f64.to_bits(), 1.0f64.to_bits()), FLAGS_EQUAL);
        assert_eq!(__dcmplt(f64::NAN.to_bits(), 1.0f64.to_bits()), FLAGS_UNORDERED);
        // gt/ge report the swapped direction.
        assert_eq!(__dcmpgt(2.0f64.to_bits(), 1.0f64.to_bits()), FLAGS_LESS);
        assert_eq!(__dcmpgt(1.0f64.to_bits(), 2.0f64.to_bits()), FLAGS_GREATER);
        assert_eq!(__dcmpgt(1.0f64.to_bits(), 1.0f64.to_bits()), FLAGS_EQUAL);
        assert_eq!(__dcmpgt(1.0f64.to_bits(), f64::NAN.to_bits()), FLAGS_UNORDERED);
    }

    // ---- zeros and denormal flush -------------------------------------

    #[test]
    fn signed_zeros_compare_equal() {
        let pos_zero = 0.0f64.to_bits();
        let neg_zero = (-0.0f64).to_bits();
        assert_eq!(dcmp(pos_zero, neg_zero), Some(Ordering::Equal));
        assert_eq!(dcmp(neg_zero, neg_zero), Some(Ordering::Equal));
        assert_eq!(__dcmpeq(pos_zero, neg_zero), FLAGS_EQUAL);
        assert_eq!(__dcmpgt(pos_zero, neg_zero), FLAGS_EQUAL);
        assert_eq!(fcmp(0.0f32.to_bits(), (-0.0f32).to_bits()), Some(Ordering::Equal));
    }

    #[test]
    fn denormals_flush_to_zero() {
        let d_min = 1u64; // smallest positive denormal
        let d_max = (1u64 << 52) - 1; // largest denormal
        let neg_denorm = d_min | (1u64 << 63);
        let min_normal = 1u64 << 52;

        // Two denormals of different magnitude compare EQUAL (flush),
        // unlike raw IEEE where 4.9e-324 < 2.2e-308-ish.
        assert_eq!(dcmp(d_min, d_max), Some(Ordering::Equal));
        assert_eq!(dcmp(d_max, d_min), Some(Ordering::Equal));
        // Denormal vs zero: equal, either sign.
        assert_eq!(dcmp(d_min, 0), Some(Ordering::Equal));
        assert_eq!(dcmp(neg_denorm, 0), Some(Ordering::Equal));
        assert_eq!(dcmp(d_min, 1u64 << 63), Some(Ordering::Equal)); // +dn vs -0
        // Denormal vs smallest normal still orders correctly.
        assert_eq!(dcmp(d_max, min_normal), Some(Ordering::Less));
        assert_eq!(dcmp(neg_denorm, min_normal | (1u64 << 63)), Some(Ordering::Greater));
        // Flush applies before NaN checks: a flushed value is not NaN.
        assert_eq!(dcmp(d_min, f64::NAN.to_bits()), None);

        // Float variants.
        let f_min = 1u32;
        let f_max = (1u32 << 23) - 1;
        assert_eq!(fcmp(f_min, f_max), Some(Ordering::Equal));
        assert_eq!(fcmp(f_max, 1u32 << 23), Some(Ordering::Less));
        assert_eq!(fcmp(f_min, 0), Some(Ordering::Equal));
        assert_eq!(fcmp(f_min | (1u32 << 31), 0), Some(Ordering::Equal));
    }

    // ---- infinities ----------------------------------------------------

    #[test]
    fn infinities() {
        let pinf = f64::INFINITY.to_bits();
        let ninf = f64::NEG_INFINITY.to_bits();
        let one = 1.0f64.to_bits();
        assert_eq!(dcmp(pinf, pinf), Some(Ordering::Equal));
        assert_eq!(dcmp(ninf, ninf), Some(Ordering::Equal));
        assert_eq!(dcmp(pinf, ninf), Some(Ordering::Greater));
        assert_eq!(dcmp(ninf, pinf), Some(Ordering::Less));
        assert_eq!(dcmp(pinf, one), Some(Ordering::Greater));
        assert_eq!(dcmp(ninf, one), Some(Ordering::Less));
        assert_eq!(dcmp(one, pinf), Some(Ordering::Less));
        // Swapped-direction export agrees with the forward one.
        assert_eq!(__dcmpgt(pinf, one), __dcmplt(one, pinf));
        assert_eq!(__dcmpge(ninf, pinf), __dcmple(pinf, ninf));

        let pinf32 = f32::INFINITY.to_bits();
        let ninf32 = f32::NEG_INFINITY.to_bits();
        assert_eq!(fcmp(pinf32, pinf32), Some(Ordering::Equal));
        assert_eq!(fcmp(ninf32, pinf32), Some(Ordering::Less));
        assert_eq!(fcmp(pinf32, 1.0f32.to_bits()), Some(Ordering::Greater));
        assert_eq!(__fcmpgt(pinf32, ninf32), __fcmplt(ninf32, pinf32));
    }

    // ---- NaN: unordered + descriptor route -----------------------------

    #[test]
    fn nan_is_unordered_against_everything() {
        let nans = [
            f64::NAN.to_bits(),                  // quiet NaN
            0x7FF0_0000_0000_0001,               // signaling NaN
            0x7FF8_0000_0000_0000 | (1u64 << 63), // negative quiet NaN
            0x7FFF_FFFF_FFFF_FFFF,               // all-ones payload
        ];
        let others = [
            0u64,
            1u64 << 63,
            1.0f64.to_bits(),
            (-1.0f64).to_bits(),
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            1, // denormal
        ];
        for &n in &nans {
            for &x in &others {
                assert_eq!(dcmp(n, x), None, "NaN vs {x:#x}");
                assert_eq!(dcmp(x, n), None, "{x:#x} vs NaN");
                assert_eq!(__dcmpeq(n, x), FLAGS_UNORDERED);
                assert_eq!(__dcmplt(n, x), FLAGS_UNORDERED);
                assert_eq!(__dcmple(x, n), FLAGS_UNORDERED);
                assert_eq!(__dcmpgt(n, x), FLAGS_UNORDERED);
                assert_eq!(__dcmpge(x, n), FLAGS_UNORDERED);
            }
            assert_eq!(dcmp(n, n), None);
        }

        let fnans = [
            f32::NAN.to_bits(),
            0x7F80_0001,                 // signaling
            0xFF80_0001,                 // negative signaling
            0x7FFF_FFFF,
        ];
        let fothers = [0u32, 1u32 << 31, 1.0f32.to_bits(), f32::INFINITY.to_bits(), 1];
        for &n in &fnans {
            for &x in &fothers {
                assert_eq!(fcmp(n, x), None);
                assert_eq!(fcmp(x, n), None);
                assert_eq!(__fcmpeq(n, x), FLAGS_UNORDERED);
                assert_eq!(__fcmplt(x, n), FLAGS_UNORDERED);
                assert_eq!(__fcmple(n, x), FLAGS_UNORDERED);
                assert_eq!(__fcmpgt(n, x), FLAGS_UNORDERED);
                assert_eq!(__fcmpge(x, n), FLAGS_UNORDERED);
            }
            assert_eq!(fcmp(n, n), None);
        }
    }

    // ---- mixed signs / adjacent mantissas ------------------------------

    #[test]
    fn mixed_signs_and_adjacent_mantissas() {
        let one = 1.0f64.to_bits();
        let neg_one = (-1.0f64).to_bits();
        let big = 1.0e300f64.to_bits();
        let neg_big = (-1.0e300f64).to_bits();
        assert_eq!(dcmp(neg_one, one), Some(Ordering::Less));
        assert_eq!(dcmp(one, neg_one), Some(Ordering::Greater));
        assert_eq!(dcmp(neg_big, neg_one), Some(Ordering::Less));
        assert_eq!(dcmp(neg_one, neg_big), Some(Ordering::Greater));
        // -0 vs negative normal: -0 > -1.
        assert_eq!(dcmp(1u64 << 63, neg_one), Some(Ordering::Greater));
        // +0 vs positive normal: +0 < 1.
        assert_eq!(dcmp(0, one), Some(Ordering::Less));

        // Adjacent mantissas: next representable values around 1.0.
        let next_up = one + 1;
        let next_down = one - 1;
        assert_eq!(dcmp(one, next_up), Some(Ordering::Less));
        assert_eq!(dcmp(next_up, one), Some(Ordering::Greater));
        assert_eq!(dcmp(one, next_down), Some(Ordering::Greater));
        assert_eq!(dcmp(next_down, one), Some(Ordering::Less));
        assert_eq!(dcmp(next_down, next_up), Some(Ordering::Less));
        // Adjacent across the sign boundary of magnitudes.
        assert_eq!(dcmp(next_up | (1u64 << 63), neg_one), Some(Ordering::Less));

        // Floats.
        let fone = 1.0f32.to_bits();
        assert_eq!(fcmp(fone, fone + 1), Some(Ordering::Less));
        assert_eq!(fcmp(fone, fone - 1), Some(Ordering::Greater));
        assert_eq!(fcmp(fone | (1u32 << 31), fone), Some(Ordering::Less));
    }

    // ---- equivalence of the exported entry points ----------------------

    #[test]
    fn exported_variants_are_consistent() {
        let samples: Vec<u64> = std::vec![
            0, 1, 1u64 << 63, 1.0f64.to_bits(), (-1.0f64).to_bits(),
            f64::INFINITY.to_bits(), f64::NEG_INFINITY.to_bits(),
            f64::NAN.to_bits(), 0x7FF0_0000_0000_0001,
            (1u64 << 52) - 1, 1u64 << 52,
            0x7FEF_FFFF_FFFF_FFFF, // max finite
            0x800F_FFFF_FFFF_FFFF, // negative denormal-ish
        ];
        for &a in &samples {
            for &b in &samples {
                let fwd = __dcmpeq(a, b);
                assert_eq!(__dcmplt(a, b), fwd, "lt/eq differ {a:#x} {b:#x}");
                assert_eq!(__dcmple(a, b), fwd, "le/eq differ {a:#x} {b:#x}");
                assert_eq!(__dcmpgt(a, b), __dcmpeq(b, a), "gt not swapped {a:#x} {b:#x}");
                assert_eq!(__dcmpge(a, b), __dcmpeq(b, a), "ge not swapped {a:#x} {b:#x}");
            }
        }
        let fsamples: Vec<u32> = std::vec![
            0, 1, 1u32 << 31, 1.0f32.to_bits(), (-1.0f32).to_bits(),
            f32::INFINITY.to_bits(), f32::NEG_INFINITY.to_bits(),
            f32::NAN.to_bits(), 0x7F80_0001, (1u32 << 23) - 1, 1u32 << 23,
            0x7F7F_FFFF, 0x807F_FFFF,
        ];
        for &a in &fsamples {
            for &b in &fsamples {
                assert_eq!(__fcmplt(a, b), __fcmpeq(a, b));
                assert_eq!(__fcmple(a, b), __fcmpeq(a, b));
                assert_eq!(__fcmpgt(a, b), __fcmpeq(b, a));
                assert_eq!(__fcmpge(a, b), __fcmpeq(b, a));
            }
        }
    }

    // ---- randomized sweeps against the flushed host oracle -------------

    #[test]
    fn double_sweep_matches_host() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Structured pool: edges plus random bit patterns biased toward
        // interesting exponent regions.
        let mut pool: Vec<u64> = std::vec![
            0, 1, 1u64 << 63, (1u64 << 52) - 1, 1u64 << 52,
            f64::INFINITY.to_bits(), f64::NEG_INFINITY.to_bits(),
            f64::NAN.to_bits(), 0x7FF0_0000_0000_0001,
            0x7FEF_FFFF_FFFF_FFFF, 0xFFEF_FFFF_FFFF_FFFF,
            0x0010_0000_0000_0000, 0x8010_0000_0000_0000,
        ];
        for _ in 0..2000 {
            let r = next();
            // Half fully random, half with exponents forced near 0 / max.
            pool.push(if r & 1 == 0 {
                r
            } else {
                (r & 0x800F_FFFF_FFFF_FFFF) | ((r >> 32) & 0x7FF0_0000_0000_0000)
            });
        }
        for (i, &a) in pool.iter().enumerate() {
            for &b in pool.iter().skip(i.saturating_sub(3)).take(7) {
                let expect = host_dcmp(a, b);
                assert_eq!(
                    dcmp(a, b),
                    expect,
                    "dcmp({a:#x}, {b:#x})",
                );
                assert_eq!(__dcmplt(a, b), host_flags(expect));
                assert_eq!(__dcmpgt(a, b), host_flags(host_dcmp(b, a)));
            }
        }
    }

    #[test]
    fn float_sweep_matches_host() {
        let mut state = 0xDEAD_BEEFu32;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        let mut pool: Vec<u32> = std::vec![
            0, 1, 1u32 << 31, (1u32 << 23) - 1, 1u32 << 23,
            f32::INFINITY.to_bits(), f32::NEG_INFINITY.to_bits(),
            f32::NAN.to_bits(), 0x7F80_0001, 0x7F7F_FFFF, 0xFF7F_FFFF,
            0x0080_0000, 0x8080_0000,
        ];
        for _ in 0..4000 {
            let r = next();
            pool.push(if r & 1 == 0 {
                r
            } else {
                (r & 0x807F_FFFF) | ((r >> 16) & 0x7F80_0000)
            });
        }
        for (i, &a) in pool.iter().enumerate() {
            for &b in pool.iter().skip(i.saturating_sub(3)).take(7) {
                let expect = host_fcmp(a, b);
                assert_eq!(fcmp(a, b), expect, "fcmp({a:#x}, {b:#x})");
                assert_eq!(__fcmplt(a, b), host_flags(expect));
                assert_eq!(__fcmpgt(a, b), host_flags(host_fcmp(b, a)));
            }
        }
        // Message formatting sanity (uses std only in tests).
        let _ = format!("{:?}", FLAGS_UNORDERED);
    }
}
