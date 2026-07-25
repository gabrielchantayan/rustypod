//! Ports of the ADS double -> float narrowing chain used by scanf `%f`:
//!
//! - `frexp`              — original: `FUN_08036e80` @ 0x08036e80 (144 bytes).
//! - `d2f_errno`          — original: `FUN_08036d7c` @ 0x08036d7c (204 bytes).
//! - `scanf_narrow_float` — original: `FUN_08036e4c` @ 0x08036e4c (32 bytes).
//!
//! retailOS is SOFT-FLOAT: doubles travel as `u64` and floats as `u32` raw
//! IEEE-754 bit patterns (register pairs / single registers on device). No
//! f32/f64 arithmetic appears below; everything routes through the committed
//! soft-float ports (`__dscalb`, `__d2f`, `__dcmpeq`/`__dcmpgt`,
//! `__ieee_status`, `errno_set`). Host tests use native `f64::from_bits` /
//! `f32` casts as the oracle where the ADS quirks allow.
//!
//! Call graph (sole call chain in osos): `scanf_float_engine` @ 0x08036348
//! stores a float-sized `%f` result through `FUN_08036e4c`, which loads the
//! double from memory (lo word first) and calls the checked narrower
//! `FUN_08036d7c`, which in turn uses `frexp` @ 0x08036e80 purely to learn
//! the binary exponent (the returned mantissa is discarded).
//!
//! Algorithms:
//! - `frexp(x, &e)`: classic C `frexp` — writes the binary exponent of `x`
//!   to `*e` and returns the mantissa `m` with 0.5 <= |m| < 1 (exponent
//!   field forced to 0x3fe), such that x = m * 2^e. Zero, Inf and NaN
//!   return unchanged with `*e = 0`. Subnormal inputs are pre-scaled by
//!   2^54 via `__dscalb` with `*e` biased by -54 — but retailOS `__dscalb`
//!   FLUSHES subnormals to +0.0, so a subnormal input deterministically
//!   yields (m = +0.5, e = -1076). Bug-for-bug faithful (the path is dead
//!   in practice: retailOS soft-float never produces subnormal doubles).
//! - `d2f_errno(x)`: narrows with ERANGE reporting. `e + 126` (the would-be
//!   float biased exponent of the frexp mantissa) selects the path:
//!   - `1..=254`: in float range — plain `__d2f(x)`, errno untouched. NOTE
//!     `__d2f`'s own rounding may still overflow to ±Inf (e.g. doubles in
//!     (float MAX, 2^128)) or flush to +0 (doubles in [2^-127, 2^-126))
//!     WITHOUT errno — faithful to the original.
//!   - `<= 0` and `x != 0.0` (checked via `__dcmpeq`): underflow — the
//!     original brackets `__d2f` in an `__ieee_status(0x808, ...)`
//!     save/restore (a no-op stub in retailOS, mirrored anyway) and sets
//!     errno = ERANGE iff the narrowed magnitude is zero (always, given
//!     `__d2f`'s flush-to-+0). Returns the flushed +0.
//!   - `>= 255`: overflow — errno = ERANGE and ±Inf by the sign of `x`
//!     (`__dcmpgt(x, 0.0)`, i.e. flags of 0-vs-x: greater -> x negative ->
//!     -Inf; less/equal -> +Inf). Inf/NaN inputs never reach this path
//!     (frexp reports e = 0 for them, so they take the in-range `__d2f`).
//! - `scanf_narrow_float(out, in)`: loads the double as two little-endian
//!   words (lo first) and stores `d2f_errno`'s float word — the exact
//!   `ScanfFloatNarrowFn` contract of scanf_float_engine.rs, whose
//!   `SCANF_FLOAT_NARROW` default now points here.
//!
//! Deviations:
//! - Doubles cross these boundaries as `u64` instead of register pairs
//!   (crate-wide soft-float convention).
//! - The ADS double-compare helpers set real CPSR flags; the crate's ports
//!   return the packed N/Z/C/V nibble, so the original's `beq` / `ldrls` /
//!   `ldrhi` become explicit tests of the Z and C/Z bits (see
//!   fp_compare.rs for the encoding).

use crate::errno::errno_set;
use crate::fp_compare::{__dcmpeq, __dcmpgt};
use crate::fp_fconv::__d2f;
use crate::fp_scalb::{__dscalb, __ieee_status};

/// ADS errno value for a range error (ERANGE; osos numbering, see
/// runtime/errno.rs).
const ERANGE: i32 = 2;

/// Packed-flags Z bit as returned by the fp_compare ports (the original
/// helpers set the real CPSR Z flag; see fp_compare.rs).
const FLAG_Z: u32 = 0x4;
/// Packed-flags C bit (ARM `hi` = C set && Z clear).
const FLAG_C: u32 = 0x2;

/// `__ieee_status` mask the original saves/restores around the underflow
/// narrowing (underflow/inexact accrual bits; the retailOS stub ignores it).
const UNDERFLOW_STATUS_MASK: u32 = 0x808;

/// Scale applied to subnormal inputs before exponent extraction (2^54),
/// with the matching -54 bias on the reported exponent.
const SUBNORMAL_PRESCALE: i32 = 0x36;

/// frexp — original: `FUN_08036e80` @ 0x08036e80 (144 bytes).
///
/// Decomposes `x` (double bit pattern) into mantissa-in-[0.5,1) return
/// value and binary exponent `*exp_out`. See the module docs for the
/// zero/Inf/NaN and (dead) subnormal behavior.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn frexp(x: u64, exp_out: *mut i32) -> u64 {
    *exp_out = 0;
    let lo = x as u32;
    let mut hi = (x >> 32) as u32;
    let mut mag = hi & 0x7fff_ffff;

    // Inf/NaN (the original's adds/subs #0x90000000 dance is a range
    // check for mag >= 0x7ff00000) and ±0 return unchanged with *exp = 0.
    if mag >= 0x7ff0_0000 || (mag | lo) == 0 {
        return x;
    }

    let mut x = x;
    if mag < 0x0010_0000 {
        // Subnormal: pre-scale by 2^54 and bias the exponent by -54.
        // retailOS __dscalb flushes subnormals to +0 (see module docs).
        x = __dscalb(x, SUBNORMAL_PRESCALE);
        *exp_out = -SUBNORMAL_PRESCALE;
        hi = (x >> 32) as u32;
        mag = hi & 0x7fff_ffff;
    }

    // Binary exponent = biased field - 0x3fe (+ the subnormal bias).
    *exp_out += (mag >> 20) as i32 - 0x3fe;
    // Force the exponent field to 0x3fe: mantissa lands in [0.5, 1).
    let hi_mantissa = (hi & !0x7ff0_0000) | 0x3fe0_0000;
    (x & 0xffff_ffff) | ((hi_mantissa as u64) << 32)
}

/// d2f_errno — original: `FUN_08036d7c` @ 0x08036d7c (204 bytes).
///
/// Double -> float narrowing with ERANGE reporting on over/underflow;
/// see the module docs for the exact path selection and quirks.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn d2f_errno(x: u64) -> u32 {
    let mut exp: i32 = 0;
    frexp(x, &mut exp); // Mantissa discarded — only the exponent is used.
    let float_biased_exp = exp + 0x7e;

    // Underflow branch: exponent at or below the float range, nonzero x.
    if float_biased_exp <= 0 && __dcmpeq(x, 0) & FLAG_Z == 0 {
        let saved = __ieee_status(UNDERFLOW_STATUS_MASK, 0);
        let narrowed = __d2f(x);
        __ieee_status(UNDERFLOW_STATUS_MASK, saved & UNDERFLOW_STATUS_MASK);
        if narrowed & 0x7fff_ffff == 0 {
            errno_set(ERANGE);
        }
        return narrowed;
    }

    if float_biased_exp < 0xff {
        return __d2f(x); // In range (incl. x == 0 and Inf/NaN, exp == 0).
    }

    // Overflow: ERANGE, ±Inf by the sign of x. __dcmpgt(x, 0) returns the
    // flags of 0-vs-x; the original's `ldrhi` (C && !Z) picks -Inf.
    errno_set(ERANGE);
    let flags = __dcmpgt(x, 0);
    if flags & FLAG_C != 0 && flags & FLAG_Z == 0 {
        0xff80_0000 // x < 0 -> -Inf
    } else {
        0x7f80_0000 // x >= 0 -> +Inf
    }
}

/// scanf_narrow_float — original: `FUN_08036e4c` @ 0x08036e4c (32 bytes).
///
/// The scanf `%f` store veneer: loads the converted double from `in_double`
/// (two little-endian words, LO WORD FIRST) and stores the checked-narrowed
/// float word to `out_float`. Matches `ScanfFloatNarrowFn` and serves as
/// the `SCANF_FLOAT_NARROW` default (scanf_float_engine.rs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scanf_narrow_float(out_float: *mut u32, in_double: *const u32) {
    let lo = *in_double;
    let hi = *in_double.add(1);
    *out_float = d2f_errno((lo as u64) | ((hi as u64) << 32));
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::errno::{errno_get, errno_set};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that read/write the shared errno word.
    static ERRNO_LOCK: Mutex<()> = Mutex::new(());

    fn frexp_of(x: f64) -> (u64, i32) {
        let mut e = 0i32;
        let m = unsafe { frexp(x.to_bits(), &mut e) };
        (m, e)
    }

    #[test]
    fn frexp_normals_match_reference() {
        let cases: Vec<f64> = std::vec![
            0.5, 0.75, 1.0, 2.0, 3.0, 8.0, 1e10, 1e-10, 0.1, 123.456,
            f64::MAX, f64::MIN_POSITIVE, -0.5, -3.0, -1e300, 1e-300,
        ];
        for x in cases {
            let (m, e) = frexp_of(x);
            // Reference: exponent-field arithmetic on the normal input.
            let bits = x.to_bits();
            let want_e = ((bits >> 52) & 0x7ff) as i32 - 0x3fe;
            let want_m = (bits & !(0x7ffu64 << 52)) | (0x3feu64 << 52);
            assert_eq!(e, want_e, "exp of {x}");
            assert_eq!(m, want_m, "mantissa of {x}");
            // Invariant: x == m * 2^e with |m| in [0.5, 1).
            let mf = f64::from_bits(m);
            assert!((0.5..1.0).contains(&mf.abs()), "mantissa range of {x}");
            // (2^e itself overflows for e == 1024, i.e. x == f64::MAX —
            // the bits assertions above already pin that case.)
            if (2f64).powi(e).is_finite() {
                assert_eq!(mf * (2f64).powi(e), x, "recompose {x}");
            }
        }
    }

    #[test]
    fn frexp_zero_inf_nan_pass_through_with_exp_zero() {
        for x in [0.0f64, -0.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            let mut e = 123i32;
            let m = unsafe { frexp(x.to_bits(), &mut e) };
            assert_eq!(m, x.to_bits(), "value {x}");
            assert_eq!(e, 0, "exp of {x}");
        }
        // NaN payload preserved (no canonicalization on this path).
        let payload_nan = 0x7ff5_dead_beef_0001u64;
        let mut e = 9i32;
        assert_eq!(unsafe { frexp(payload_nan, &mut e) }, payload_nan);
        assert_eq!(e, 0);
    }

    #[test]
    fn frexp_subnormals_hit_the_dscalb_flush_quirk() {
        // retailOS __dscalb flushes subnormals to +0, so the pre-scale
        // step yields the deterministic garbage (m = +0.5, e = -1076)
        // documented in the module header — for either sign.
        for bits in [1u64, 0x000f_ffff_ffff_ffffu64, 0x8000_0000_0000_0001u64] {
            let mut e = 0i32;
            let m = unsafe { frexp(bits, &mut e) };
            assert_eq!(m, 0.5f64.to_bits(), "subnormal {bits:#x}");
            assert_eq!(e, -0x36 - 0x3fe, "subnormal {bits:#x}");
        }
    }

    /// Runs d2f_errno with errno cleared, returns (float bits, errno).
    fn narrow(x: f64) -> (u32, i32) {
        unsafe {
            let saved = errno_get();
            errno_set(0);
            let f = d2f_errno(x.to_bits());
            let e = errno_get();
            errno_set(saved);
            (f, e)
        }
    }

    #[test]
    fn d2f_errno_in_range_matches_native_cast() {
        let _lock = ERRNO_LOCK.lock().unwrap();
        let cases: Vec<f64> = std::vec![
            0.0, -0.0, 1.0, -1.0, 0.1, 123.456, 1e30, -1e30, 3.3e38,
            f32::MAX as f64, f32::MIN_POSITIVE as f64,
            core::f64::consts::PI,
        ];
        for x in cases {
            let (f, e) = narrow(x);
            let want = x as f32;
            if want == 0.0 && x != 0.0 {
                // Underflow region behavior is pinned separately below.
                continue;
            }
            assert_eq!(f, want.to_bits(), "narrow {x}");
            assert_eq!(e, 0, "errno for {x}");
        }
    }

    #[test]
    fn d2f_errno_overflow_sets_erange_and_saturates() {
        let _lock = ERRNO_LOCK.lock().unwrap();
        // 2^128 and above: frexp exponent pushes e+126 to >= 255.
        assert_eq!(narrow(3.3e38), (3.3e38f32.to_bits(), 0)); // still finite
        assert_eq!(narrow(1e39), (0x7f80_0000, ERANGE));
        assert_eq!(narrow(-1e39), (0xff80_0000, ERANGE));
        assert_eq!(narrow(f64::MAX), (0x7f80_0000, ERANGE));
        assert_eq!(narrow(f64::MIN), (0xff80_0000, ERANGE));
    }

    #[test]
    fn d2f_errno_quirk_rounding_overflow_in_range_path_skips_errno() {
        let _lock = ERRNO_LOCK.lock().unwrap();
        // A double just below 2^128 but above float MAX: frexp says
        // e+126 == 254 (in range), yet __d2f rounds up to +Inf — the
        // original reports NO errno here. Pinned bug-for-bug.
        let x = f64::from_bits(0x47ef_ffff_f000_0000); // ~3.402824e38
        assert!(x > f32::MAX as f64);
        let (f, e) = narrow(x);
        assert_eq!(f, 0x7f80_0000);
        assert_eq!(e, 0);
    }

    #[test]
    fn d2f_errno_underflow_flushes_to_plus_zero_with_erange() {
        let _lock = ERRNO_LOCK.lock().unwrap();
        // Below 2^-126 (e+126 <= 0): flush to +0 (sign dropped by
        // __d2f's no-denormal rule) and ERANGE.
        for x in [1e-40f64, -1e-40, 2.0f64.powi(-127), -(2.0f64.powi(-140))] {
            let (f, e) = narrow(x);
            assert_eq!(f, 0, "flush of {x}");
            assert_eq!(e, ERANGE, "errno for {x}");
        }
    }

    #[test]
    fn d2f_errno_zero_inf_nan_never_touch_errno() {
        let _lock = ERRNO_LOCK.lock().unwrap();
        assert_eq!(narrow(0.0), (0, 0));
        assert_eq!(narrow(-0.0), (0x8000_0000, 0));
        assert_eq!(narrow(f64::INFINITY), (0x7f80_0000, 0));
        assert_eq!(narrow(f64::NEG_INFINITY), (0xff80_0000, 0));
        // NaN narrows to the canonical positive qNaN (a __d2f rule).
        assert_eq!(narrow(f64::NAN), (0x7fc0_0000, 0));
    }

    #[test]
    fn scanf_narrow_float_reads_lo_word_first() {
        let _lock = ERRNO_LOCK.lock().unwrap();
        let x = 123.456f64;
        let bits = x.to_bits();
        let words = [bits as u32, (bits >> 32) as u32];
        let mut out = 0u32;
        unsafe { scanf_narrow_float(&mut out, words.as_ptr()) };
        assert_eq!(out, (123.456f32).to_bits());
    }
}
