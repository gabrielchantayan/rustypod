//! Ports of the ARM ADS 1.0.1 libm routines from osos:
//!
//! - `sqrt`      — original: `FUN_08031e44` @ 0x08031e44 (112 bytes).
//! - `expf`      — original: `FUN_08031ec8` @ 0x08031ec8 (112 bytes).
//! - `expf_core` — original: `FUN_08033f40` @ 0x08033f40 (420 bytes).
//!
//! retailOS is SOFT-FLOAT: doubles travel as `u64` and floats as `u32` raw
//! IEEE-754 bit patterns. No f32/f64 arithmetic appears below (it would
//! lower to the unported `__aeabi_*` helpers) — all floating-point math goes
//! through the committed soft-float primitive ports. Host tests use native
//! `f32::from_bits`/`f64::from_bits` as the oracle.
//!
//! Identification notes (correcting the batch assignment, which labeled the
//! second and third functions "sqrtf @ 0x08031ec8" and "_fsqrt core
//! @ 0x08033f40"; names.yaml's porting queue repeats the guess):
//! - There is NO float sqrt in this image. The only square-root core is the
//!   double `_dsqrt` @ 0x083ebf28 (ported in crate::fp_misc), and the only
//!   libm sqrt is the double `sqrt` below.
//! - 0x08031ec8 is `expf`: expf(-Inf) returns +0 (a sqrt would raise EDOM
//!   and return NaN), both error paths store code 2 = ERANGE (underflow and
//!   overflow — a sqrt can do neither), and tiny |x| < 0x33800000 returns
//!   1.0f (e^x == 1 to float precision; sqrt(0) would not be 1).
//! - 0x08033f40 is the expf core: it splits x = floor(x) + frac via
//!   `__d2i(__dadd(__f2d(x), 128.0))` (const @ 0x080340e8), evaluates
//!   e^frac through the digit-recurrence kernel @ 0x08035d50, then scales
//!   by e^floor(x) using three float tables — e^1..e^9 @ 0x08986130,
//!   e^10..e^80 * 2^-16 @ 0x08986154, e^-10..e^-110 * 2^36 @ 0x08986174 —
//!   with the 2^±16/2^36 fixup folded into a final `__fmul` by 2^delta.
//! - Sole on-device caller of `expf` @ 0x0825d844 computes a 16.16
//!   fixed-point exponential decay: `f2i(expf((float)(-n * 2^-16)) * 2^16)`,
//!   clamped to +-32768 — nonsensical for a sqrt, exactly an exp.
//!
//! `sqrt` — original @ 0x08031e44. Domain check, then tail `_dsqrt`:
//! NaN inputs (exponent all-ones with nonzero payload, detected as bit 31
//! of `0x7ff00000 - ((hi & 0x7fffffff) | (lo != 0))`) go straight to
//! `_dsqrt`, which canonicalizes them. Everything else is compared against
//! +0.0 through `__dcmplt` @ 0x083eb9c0; the `bcs` (not-less) path tails
//! `_dsqrt`. Ordered-less inputs (all negative normals and -Inf — the
//! compare flushes denormals, so -0 and negative denormals are NOT less
//! and fall through to `_dsqrt`, which flushes them to +0 / keeps -0)
//! store EDOM (1) through the "raise wrapper" @ 0x08032178 and return the
//! NaN 0x7ff80000_00000001 (low word 1, like `_dsqrt`'s own negative path;
//! literal pool @ 0x08031ec0).
//!
//! `expf` — original @ 0x08031ec8. Exponent-0xff preamble: -Inf returns
//! +0; NaN/+Inf tail `__fscalb(x, 1)` (Inf passes through, NaN yields the
//! canonical float qNaN via the trap dispatcher). Finite inputs go through
//! `expf_core(x, 0)`; a +-0 result (underflow) or +Inf result (overflow)
//! stores ERANGE (2) and returns +0.0f / +Inf respectively. The original's
//! underflow path loads the fixed double @ 0x0898603c
//! (0x00000000_bda8fae9, a positive denormal) and tail-calls `__d2f`,
//! which flushes it to +0.0f — modeled here as a literal +0.
//!
//! `expf_core` — original @ 0x08033f40. Second argument is an exponent
//! delta folded into the final scale (the only caller passes 0).
//!
//! Kernel dependency:
//! - The e^frac kernel @ 0x08035d50 (hyperbolic CORDIC, ported as
//!   `crate::libm::cordic::exp_frac_kernel`; writes its result through the
//!   third of three out pointers, the other two being sinh/cosh outputs the
//!   caller never reads) sits behind the replaceable [`EXP_FRAC_KERNEL`]
//!   hook — the same pattern as `LOG_ATANH_KERNEL` in crate::libm::misc.
//!   The wired default adapts the real port's out-pointer signature to the
//!   single value the caller reads.
//!
//! Behavioral notes / simplifications:
//! - The "libm raise wrapper" @ 0x08032178 is `*__rt_errno_addr() = code`,
//!   already committed as `errno_set` in crate::runtime::errno (osos
//!   numbering: 1 = EDOM, 2 = ERANGE); these functions call it, exactly
//!   like the originals (the batch assignment had asked for a stub, but
//!   the real thing is committed — see crate::libm::misc for the same
//!   conclusion).
//! - The core's Inf/NaN `__fscalb` tail @ 0x08033f88 is dead code (every
//!   exponent-0xff input is caught by the magnitude early exits); kept for
//!   fidelity. The exponent-excursion aborts branch to the non-returning
//!   retailOS stub @ 0x08030f44 (exit via 0x082b20a0); they are likewise
//!   unreachable for inputs passing the early exits (|x| clamped to
//!   [-104, 90) keeps e = floor(x) inside [-104, 89], inside all table
//!   ranges) and are modeled by [`expf_abort`].
//! - errno is shared mutable state: host tests that check it serialize on
//!   a mutex, same as crate::libm::misc.
//! - Inherited deviation: the original's `__fmul` flushes denormal results
//!   to +-0, but the committed fp_fmuldiv port deliberately implements
//!   full IEEE gradual underflow. expf underflow in [-104, -88) therefore
//!   returns a denormal WITHOUT ERANGE here, where the silicon returns
//!   +0 WITH ERANGE (e^-87 == 1.6e-38 is the smallest normal result; the
//!   -104.0f early exit still gives +0 + ERANGE, and anything below half
//!   the smallest denormal flushes to +0 even with gradual underflow).

use core::cmp::Ordering;

use crate::fp_compare::dcmp;
use crate::fp_dadd::__dadd;
use crate::fp_dconv::__d2i;
use crate::fp_fadd::__frsb;
use crate::fp_fconv::{__f2d, __i2f};
use crate::fp_fmuldiv::__fmul;
use crate::fp_misc::_dsqrt;
use crate::fp_scalb::__fscalb;
use crate::runtime::errno::errno_set;
use crate::runtime::rt_div::__rt_sdivmod;

/// osos errno numbering (see crate::libm::misc).
const EDOM: i32 = 1;
const ERANGE: i32 = 2;

/// 1.0f and +Inf float bit patterns.
const ONE_F: u32 = 0x3f80_0000;
const POS_INF_F: u32 = 0x7f80_0000;
const NEG_INF_F: u32 = 0xff80_0000;

/// NaN returned for sqrt's domain error (x < 0): 0x7ff80000_00000001,
/// the literal pool entry @ 0x08031ec0 — NOT the canonical quiet NaN.
const SQRT_DOMAIN_NAN: u64 = 0x7ff8_0000_0000_0001;

/// Double constant @ 0x080340e8: 128.0, the floor-split addend.
const CONST_128: u64 = 0x4060_0000_0000_0000;

/// e^1 .. e^9, float table @ 0x08986130.
const POW_E: [u32; 9] = [
    0x402d_f854, 0x40ec_7326, 0x41a0_af2e, 0x425a_6481, 0x4314_69c5, 0x43c9_b6e3, 0x4489_1443,
    0x453a_4f54, 0x45fd_38ac,
];
/// e^10 .. e^80 scaled by 2^-16, float table @ 0x08986154. The 2^16 fixup
/// is folded into the exponent delta (+16) instead of the stored values.
const POW_E10_POS: [u32; 8] = [
    0x3eac_14ee, 0x45e7_5844, 0x4d1b_8238, 0x5451_106a, 0x5b8c_881f, 0x62bc_ede5, 0x69fd_fe91,
    0x712a_bbce,
];
/// e^-10 .. e^-110 scaled by 2^36, float table @ 0x08986174. The 2^-36
/// fixup is folded into the exponent delta (-36).
const POW_E10_NEG: [u32; 11] = [
    0x4a3e_6bce, 0x430d_a433, 0x3bd2_b706, 0x349c_bc92, 0x2d69_2beb, 0x262d_70c9, 0x1f01_02bf,
    0x17bf_ecba, 0x108e_c284, 0x0954_60f9, 0x021d_f968,
];

/// sqrt — original: `FUN_08031e44` @ 0x08031e44 (112 bytes).
///
/// Double square root: NaN -> `_dsqrt` (canonical qNaN out), x < 0 (in the
/// original's denormal-flushing compare against +0.0) -> EDOM and the
/// NaN 0x7ff80000_00000001, everything else -> `_dsqrt(x)`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqrt(x: u64) -> u64 {
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    // NaN pre-filter, mirroring the original's arithmetic: bit 31 of
    // 0x7ff00000 - ((hi & 0x7fffffff) | (lo != 0)) is set exactly for NaN
    // (exponent all-ones with a nonzero payload; Inf gives exactly 0).
    let mag = (hi & 0x7fff_ffff) | u32::from(lo != 0);
    if (0x7ff0_0000u32.wrapping_sub(mag)) >> 31 != 0 {
        return _dsqrt(x);
    }
    // __dcmplt(x, +0.0): the bcs (not-less) path tails _dsqrt. dcmp
    // reproduces the original's compare-time denormal flush, so -0 and
    // negative denormals compare equal to +0.0 and reach _dsqrt (which
    // keeps -0 and flushes -denormal to +0). Unordered (NaN) is filtered
    // above, so only Some(Less) takes the domain-error path.
    if dcmp(x, 0) == Some(Ordering::Less) {
        errno_set(EDOM);
        return SQRT_DOMAIN_NAN;
    }
    _dsqrt(x)
}

/// expf — original: `FUN_08031ec8` @ 0x08031ec8 (112 bytes).
///
/// (Mislabeled "sqrtf" in the batch assignment — see module header.)
/// Base-e exponential with ADS semantics: NaN -> canonical float qNaN,
/// +Inf -> +Inf, -Inf -> +0, underflow -> ERANGE and +0, overflow ->
/// ERANGE and +Inf.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn expf(x: u32) -> u32 {
    // Exponent field all ones (the original's `mvn r1, r0, asr #23` /
    // `tst r1, #0xff` checks exactly this, sign included).
    if (x >> 23) & 0xff == 0xff {
        // `cmn r0, #0x800000` is zero only for 0xff800000 (-Inf): +0 out.
        if x == NEG_INF_F {
            return 0;
        }
        // +Inf passes through __fscalb unchanged; NaN raises its error
        // descriptor and yields the canonical float qNaN.
        return __fscalb(x, 1);
    }
    let result = expf_core(x, 0);
    if result & 0x7fff_ffff == 0 {
        // Underflow: ERANGE, and the original's tail __d2f of the fixed
        // denormal double @ 0x0898603c flushes to +0.0f.
        errno_set(ERANGE);
        return 0;
    }
    if result == POS_INF_F {
        // Overflow.
        errno_set(ERANGE);
        return POS_INF_F;
    }
    result
}

/// Replaceable hook for the e^frac kernel @ 0x08035d50 (see module
/// header). Signature collapses the original's three out-pointers to the
/// single result the caller reads; the wired default is the real CORDIC
/// port behind a thin adapter.
pub static mut EXP_FRAC_KERNEL: unsafe extern "C" fn(u32) -> u32 = default_exp_frac_kernel;

/// Default [`EXP_FRAC_KERNEL`]: the real port,
/// `crate::libm::cordic::exp_frac_kernel`, with the sinh/cosh outputs
/// (scratch the original caller never reads) dropped.
unsafe extern "C" fn default_exp_frac_kernel(frac: u32) -> u32 {
    let mut sinh_scratch: u32 = 0;
    let mut cosh_scratch: u32 = 0;
    let mut result: u32 = 0;
    crate::libm::cordic::exp_frac_kernel(
        frac,
        &mut sinh_scratch,
        &mut cosh_scratch,
        &mut result,
    );
    result
}

/// Dispatches through [`EXP_FRAC_KERNEL`]. The volatile read keeps the
/// hook a real runtime dispatch (same rationale as LOG_ATANH_KERNEL in
/// crate::libm::misc).
unsafe fn exp_frac_kernel(frac: u32) -> u32 {
    let kernel = core::ptr::read_volatile(&raw const EXP_FRAC_KERNEL);
    kernel(frac)
}

/// The original's exponent excursions (e <= -110, e10 outside the table
/// ranges, zeroed local) branch to the non-returning retailOS abort/exit
/// stub @ 0x08030f44. Provably unreachable for any input passing the
/// early exits; modeled as a diverging loop.
#[inline(never)]
fn expf_abort() -> ! {
    loop {}
}

/// expf_core — original: `FUN_08033f40` @ 0x08033f40 (420 bytes).
///
/// (Mislabeled "_fsqrt core" in the batch assignment — see module
/// header.) Computes e^x * 2^exp_delta as a float bit pattern:
/// x = e + frac with e = floor(x), local = e^frac from the kernel, scaled
/// by e^e through the power tables and a final `__fmul` by 2^delta.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn expf_core(x: u32, exp_delta: i32) -> u32 {
    let mag = x & 0x7fff_ffff;
    // |x| < 2^-24-ish (0x33800000): e^x == 1.0f to float precision.
    if mag < 0x3380_0000 {
        return ONE_F;
    }
    if x & 0x8000_0000 == 0 {
        // x >= 90.0f: certain overflow.
        if mag >= 0x42b4_0000 {
            return POS_INF_F;
        }
    } else {
        // x <= -104.0f: certain underflow.
        if mag >= 0x42d0_0000 {
            return 0;
        }
    }
    // Dead code (no exponent-0xff input survives the early exits); the
    // original keeps this __fscalb tail.
    if (x >> 23) & 0xff == 0xff {
        return __fscalb(x, 1);
    }

    // e = floor(x): x + 128.0 is exact in double for the reachable range,
    // positive, and __d2i truncates toward zero — i.e. floor(x) + 128.
    let d = __dadd(__f2d(x), CONST_128);
    let e = __d2i(d).wrapping_sub(128);
    // frac = x - (float)e, via __frsb's flipped-sign add.
    let frac = __frsb(__i2f(e), x);
    let mut local = exp_frac_kernel(frac);

    let mut delta = exp_delta;
    if e != 0 {
        if e <= -110 {
            expf_abort();
        }
        // e^e = e^rem * e^(10 * (q - 11)), q = (e + 110) / 10.
        let mut rem: i32 = 0;
        let q = __rt_sdivmod(e.wrapping_add(110), 10, &mut rem);
        let e10 = q - 11;
        if rem != 0 {
            // rem in 1..=9 and e10 in -11..=8 are guaranteed by the abort
            // checks above; the original indexes its tables unchecked.
            local = __fmul(local, *POW_E.get_unchecked((rem - 1) as usize));
        }
        if e10 > 0 {
            if e10 >= 9 {
                expf_abort();
            }
            local = __fmul(local, *POW_E10_POS.get_unchecked((e10 - 1) as usize));
            delta += 16;
        } else if e10 < 0 {
            if e10 < -11 {
                expf_abort();
            }
            local = __fmul(local, *POW_E10_NEG.get_unchecked((-e10 - 1) as usize));
            delta -= 36;
        }
    }

    let exp_local = ((local as i32) >> 23) & 0xff;
    if exp_local == 0 {
        expf_abort();
    }
    // Overflow: biased exponent would reach 0xff (signed compare).
    if exp_local + delta >= 0xff {
        return POS_INF_F;
    }
    // Deep underflow: result more than 2^24 below the normal range.
    if exp_local - delta < -24 {
        return 0;
    }
    // Scale by 2^delta: the original builds 0x3f800000 + (delta << 23)
    // and tail-calls __fmul (shallower underflows flush to +0 there).
    let scale = (0x3f80_0000i32.wrapping_add(delta.wrapping_shl(23))) as u32;
    __fmul(local, scale)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::errno::{errno_get, errno_set};
    use std::sync::Mutex;

    /// Serializes tests that swap the EXP_FRAC_KERNEL hook or touch the
    /// shared errno cell (same pattern as crate::libm::misc).
    static LOCK: Mutex<()> = Mutex::new(());

    const D_INF: u64 = 0x7ff0_0000_0000_0000;
    const D_MIN_NORMAL: u64 = 0x0010_0000_0000_0000;
    const D_MAX_DENORM: u64 = 0x000f_ffff_ffff_ffff;
    const D_QNAN: u64 = 0x7ff8_0000_0000_0000;
    const F_QNAN: u32 = 0x7fc0_0000;

    fn dsqrt(x: u64) -> u64 {
        unsafe { sqrt(x) }
    }

    fn fexp(x: u32) -> u32 {
        unsafe { expf(x) }
    }

    fn fexp_core(x: u32, delta: i32) -> u32 {
        unsafe { expf_core(x, delta) }
    }

    /// errno is process-global and OTHER modules' tests mutate it
    /// concurrently, so a single set/call/check can lose the race. Retry
    /// with a backoff until the expected value is observed (a genuine bug
    /// — the call never writing errno — fails every attempt and still
    /// panics). Kept short: the errno cell is only nonzero for a few
    /// instructions around each attempt.
    fn assert_errno_after<F: FnMut()>(mut call: F, expect: i32) {
        for _ in 0..50 {
            unsafe { errno_set(0) };
            call();
            if unsafe { errno_get() } == expect {
                unsafe { errno_set(0) };
                return;
            }
            unsafe { errno_set(0) };
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("errno != {expect} after call (50 attempts)");
    }

    /// Host IEEE oracle: aarch64 f64::sqrt is correctly rounded.
    fn host_sqrt(x: u64) -> u64 {
        f64::from_bits(x).sqrt().to_bits()
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

    // ---- sqrt ----

    #[test]
    fn sqrt_perfect_squares() {
        for i in 1..=1000u64 {
            let v = i as f64 * i as f64;
            let bits = v.to_bits();
            assert_eq!(dsqrt(bits), (i as f64).to_bits(), "sqrt({v})");
            assert_eq!(dsqrt(bits), host_sqrt(bits));
        }
    }

    #[test]
    fn sqrt_directed_normals() {
        let cases: &[u64] = &[
            0x3ff0_0000_0000_0000, // 1.0
            0x4000_0000_0000_0000, // 2.0
            0x3fe0_0000_0000_0000, // 0.5
            D_MIN_NORMAL,
            0x7fef_ffff_ffff_ffff, // DBL_MAX
            0x3e69_1234_5678_9abc,
            0x7fe0_0000_0000_0001,
            0x0010_0000_0000_0001,
        ];
        for &x in cases {
            assert_eq!(dsqrt(x), host_sqrt(x), "x={x:#x}");
        }
    }

    #[test]
    fn sqrt_zero_and_inf() {
        assert_eq!(dsqrt(0), 0); // +0
        assert_eq!(dsqrt(0x8000_0000_0000_0000), 0x8000_0000_0000_0000); // -0
        assert_eq!(dsqrt(D_INF), D_INF); // +Inf
        // None of these touch errno.
        assert_errno_after(|| { dsqrt(0); }, 0);
    }

    #[test]
    fn sqrt_negative_is_domain_error() {
        for &x in &[
            0xbff0_0000_0000_0000, // -1.0
            0xc4f8_7654_3210_fedc, // negative normal
            D_INF | 0x8000_0000_0000_0000, // -Inf
            0x8010_0000_0000_0000, // smallest-magnitude negative normal
        ] {
            assert_eq!(dsqrt(x), SQRT_DOMAIN_NAN, "x={x:#x}");
            assert_errno_after(|| { dsqrt(x); }, EDOM);
        }
    }

    #[test]
    fn sqrt_nan_inputs_canonicalize() {
        // NaN goes straight to _dsqrt: canonical qNaN, no errno.
        assert_eq!(dsqrt(0x7ff8_0000_0000_0000), D_QNAN);
        assert_eq!(dsqrt(0x7ff4_0000_dead_beef), D_QNAN);
        assert_eq!(dsqrt(0xfff8_0000_0000_0001), D_QNAN);
        assert_eq!(dsqrt(0x7ff0_0000_0000_0001), D_QNAN); // sNaN
        assert_errno_after(|| { dsqrt(D_QNAN); }, 0);
    }

    #[test]
    fn sqrt_denormals_flush_without_errno() {
        // The compare flushes denormals, so even NEGATIVE denormals are
        // not "less than +0.0": no EDOM, _dsqrt flushes them to +0.
        assert_eq!(dsqrt(1), 0); // smallest positive denormal
        assert_eq!(dsqrt(D_MAX_DENORM), 0);
        assert_eq!(dsqrt(0x8000_0000_0000_0001), 0); // negative denormal
        assert_eq!(dsqrt(0x800f_ffff_ffff_ffff), 0);
        assert_errno_after(|| { dsqrt(0x8000_0000_0000_0001); }, 0);
    }

    #[test]
    fn sqrt_random_matches_host() {
        let mut rng = Rng(0x5eed_5eed_5eed_5eed);
        for _ in 0..100_000 {
            let x = rng.next();
            let fx = f64::from_bits(x);
            if fx.is_nan() {
                assert_eq!(dsqrt(x), D_QNAN, "NaN x={x:#x}");
                continue;
            }
            if fx < 0.0 && x & 0x7fff_ffff_ffff_ffff >= D_MIN_NORMAL {
                // Negative normal or -Inf: domain error.
                assert_eq!(dsqrt(x), SQRT_DOMAIN_NAN, "x={x:#x}");
                continue;
            }
            if x & 0x7fff_ffff_ffff_ffff != 0 && x & 0x7fff_ffff_ffff_ffff < D_MIN_NORMAL {
                // +-denormal: flushed to +0 by _dsqrt.
                assert_eq!(dsqrt(x), 0, "denormal x={x:#x}");
                continue;
            }
            assert_eq!(dsqrt(x), host_sqrt(x), "x={x:#x}");
        }
    }

    // ---- expf wrapper ----

    #[test]
    fn expf_special_values() {
        assert_eq!(fexp(0), ONE_F); // e^0 = 1
        assert_eq!(fexp(0x8000_0000), ONE_F); // e^-0 = 1
        assert_eq!(fexp(POS_INF_F), POS_INF_F); // e^+Inf = +Inf
        assert_eq!(fexp(NEG_INF_F), 0); // e^-Inf = +0
        // NaN -> canonical float qNaN via the trap dispatcher.
        assert_eq!(fexp(0x7fc0_0000), F_QNAN);
        assert_eq!(fexp(0x7f80_0001), F_QNAN); // sNaN
        assert_eq!(fexp(0xffc0_0000), F_QNAN); // negative NaN
    }

    #[test]
    fn expf_tiny_returns_one() {
        // |x| < 0x33800000 -> 1.0f without touching the core's math.
        assert_eq!(fexp(1e-8f32.to_bits()), ONE_F);
        assert_eq!(fexp((-1e-8f32).to_bits()), ONE_F);
        assert_eq!(fexp(0x337f_ffff), ONE_F);
        assert_eq!(fexp(0xb37f_ffff), ONE_F);
    }

    #[test]
    fn expf_integer_powers_hit_tables_exactly() {
        // Integer x: frac = 0 -> kernel fast path -> local = 1.0f exactly,
        // so the result is a pure table product.
        assert_eq!(fexp(1.0f32.to_bits()), POW_E[0]); // e^1
        assert_eq!(fexp(2.0f32.to_bits()), POW_E[1]); // e^2
        assert_eq!(fexp(9.0f32.to_bits()), POW_E[8]); // e^9
        // e^10 = B[0] * 2^16 (exact power-of-two scaling).
        let e10 = f32::from_bits(POW_E10_POS[0]) * 65536.0f32;
        assert_eq!(fexp(10.0f32.to_bits()), e10.to_bits());
    }

    /// Native replica of the table algorithm for integer n in [-87, 88]
    /// (range where e^n stays normal), using correctly rounded f32 muls.
    fn native_exp_int(n: i32) -> u32 {
        if n == 0 {
            return ONE_F;
        }
        let mut local = 1.0f32;
        let mut delta = 0i32;
        let q = (n + 110) / 10;
        let rem = (n + 110) % 10;
        let e10 = q - 11;
        if rem != 0 {
            local *= f32::from_bits(POW_E[(rem - 1) as usize]);
        }
        if e10 > 0 {
            local *= f32::from_bits(POW_E10_POS[(e10 - 1) as usize]);
            delta += 16;
        } else if e10 < 0 {
            local *= f32::from_bits(POW_E10_NEG[(-e10 - 1) as usize]);
            delta -= 36;
        }
        let scale = f32::from_bits((0x3f80_0000i32 + (delta << 23)) as u32);
        (local * scale).to_bits()
    }

    #[test]
    fn expf_directed_integers() {
        for n in [-87, -45, -11, -10, -9, -2, -1, 1, 11, 20, 50, 87, 88] {
            assert_eq!(fexp((n as f32).to_bits()), native_exp_int(n), "n={n}");
        }
        assert_errno_after(|| { fexp(1.0f32.to_bits()); }, 0); // no ERANGE
    }

    #[test]
    fn expf_random_integers_match_native() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        for _ in 0..100_000 {
            let n = (rng.next() % 176) as i32 - 87; // -87..=88
            assert_eq!(fexp((n as f32).to_bits()), native_exp_int(n), "n={n}");
        }
    }

    #[test]
    fn expf_overflow_sets_erange() {
        // 90.0f hits the core's certain-overflow early exit.
        for x in [89.0f32, 90.0f32, 100.0f32, f32::MAX] {
            assert_eq!(fexp(x.to_bits()), POS_INF_F, "x={x}");
            assert_errno_after(|| { fexp(x.to_bits()); }, ERANGE);
        }
    }

    #[test]
    fn expf_underflow_sets_erange() {
        // -104.0f and beyond hit the core's certain-underflow early exit:
        // +0 with ERANGE.
        for x in [-104.0f32, -200.0f32, f32::MIN] {
            assert_eq!(fexp(x.to_bits()), 0, "x={x}");
            assert_errno_after(|| { fexp(x.to_bits()); }, ERANGE);
        }
        // e^-87 is still the smallest normal result here: no error.
        assert_eq!(fexp((-87.0f32).to_bits()), native_exp_int(-87));
        assert_ne!(fexp((-87.0f32).to_bits()), 0);
        assert_errno_after(|| { fexp((-87.0f32).to_bits()); }, 0);
    }

    #[test]
    fn expf_gradual_underflow_via_committed_fmul() {
        // e^-103 = 1.85e-45 is a float DENORMAL. The original's __fmul
        // flushes it to +0 (and the wrapper then raises ERANGE); the
        // committed fp_fmuldiv port deliberately implements full IEEE
        // gradual underflow instead (its documented deviation), so the
        // denormal survives and no ERANGE is raised.
        assert_eq!(fexp((-103.0f32).to_bits()), 0x0000_0001);
        assert_errno_after(|| { fexp((-103.0f32).to_bits()); }, 0);
    }

    // ---- expf_core ----

    #[test]
    fn expf_core_early_exits() {
        assert_eq!(fexp_core(0, 0), ONE_F);
        assert_eq!(fexp_core(0x337f_ffff, 0), ONE_F);
        assert_eq!(fexp_core(POS_INF_F, 0), POS_INF_F); // +Inf
        assert_eq!(fexp_core(NEG_INF_F, 0), 0); // -Inf -> +0
        assert_eq!(fexp_core(0x42b4_0000, 0), POS_INF_F); // +90.0f
        assert_eq!(fexp_core(0xc2d0_0000, 0), 0); // -104.0f
        // Just under 90.0f still overflows: e = 89, local ~= 2 * e^89 *
        // 2^-16 pushes the biased exponent past 0xff in the final check.
        assert_eq!(fexp_core(0x42b3_ffff, 0), POS_INF_F);
    }

    #[test]
    fn expf_core_exp_delta_scales_final_result() {
        let _g = LOCK.lock().unwrap();
        // The tiny-magnitude early exit returns 1.0f WITHOUT applying the
        // delta (the original branches out before the scale is built).
        assert_eq!(fexp_core(0, 16), ONE_F);
        // Otherwise the second argument folds into the final power-of-two
        // scale: expf_core(1, 1) = e^1 * 2.
        let e1x2 = f32::from_bits(POW_E[0]) * 2.0f32;
        assert_eq!(fexp_core(1.0f32.to_bits(), 1), e1x2.to_bits());
        // Negative delta: the wired kernel's e^0.5 (0x3fd3094e, pinned in
        // libm/cordic) scaled by 2^-1 (exact).
        let e_half = f32::from_bits(0x3fd3_094e);
        assert_eq!(fexp_core(0.5f32.to_bits(), -1), (e_half * 0.5f32).to_bits());
    }

    #[test]
    fn expf_core_frac_fast_path_is_exact() {
        let _g = LOCK.lock().unwrap();
        // frac <= 2^-12 uses the original kernel's exact fast path,
        // 1 + frac; with e = 0 no table scaling happens.
        let x = 1e-4f32; // e = 0, frac = 1e-4 <= 2^-12
        let expect = 1.0f32 + x;
        assert_eq!(fexp_core(x.to_bits(), 0), expect.to_bits());
    }

    #[test]
    fn expf_core_wired_default_is_real_cordic_kernel() {
        let _g = LOCK.lock().unwrap();
        // frac > 2^-12: the wired default is the real CORDIC port — the
        // result must be exactly what the exported kernel writes through
        // its third out pointer.
        let x = 0.5f32; // e = 0, frac = 0.5
        let (mut s, mut c, mut r) = (0u32, 0u32, 0u32);
        unsafe { crate::libm::cordic::exp_frac_kernel(x.to_bits(), &mut s, &mut c, &mut r) };
        assert_eq!(fexp_core(x.to_bits(), 0), r);
        assert_eq!(r, 0x3fd3_094e); // e^0.5, pinned in libm/cordic
    }

    #[test]
    fn expf_end_to_end_through_wired_kernel_matches_host() {
        let _g = LOCK.lock().unwrap();
        // Full original pipeline (floor split + CORDIC kernel + power
        // tables) against the host's double-precision exp. The table
        // product stacks a few more roundings on the kernel's 2 ulp.
        for &x in &[0.5f32, 0.75, 1.5, 2.7182818, -0.5, -2.5, 3.75, 10.1, -33.3, 60.25,
                    88.5, -87.4, 0.001, -0.001] {
            let got = fexp(x.to_bits());
            let reference = ((x as f64).exp() as f32).to_bits();
            assert!(
                ulp_distance(got, reference) <= 8,
                "x={x} got={got:#x} ref={reference:#x}"
            );
        }
    }

    /// Ordered-integer ulp distance (same-sign positive floats).
    fn ulp_distance(a: u32, b: u32) -> i64 {
        (a as i64 - b as i64).abs()
    }

    #[test]
    fn expf_core_kernel_hook_drives_scaling() {
        let _g = LOCK.lock().unwrap();
        unsafe extern "C" fn mock_kernel(frac: u32) -> u32 {
            assert_eq!(frac, 0.5f32.to_bits());
            2.0f32.to_bits() // pretend e^0.5 == 2.0
        }
        let saved = unsafe { EXP_FRAC_KERNEL };
        unsafe { EXP_FRAC_KERNEL = mock_kernel };
        // expf_core(5.5) = mock(0.5) * e^5 = 2.0 * e^5.
        let expect = 2.0f32 * f32::from_bits(POW_E[4]);
        assert_eq!(fexp_core(5.5f32.to_bits(), 0), expect.to_bits());
        // Wrapper path reaches the same place.
        assert_eq!(fexp(5.5f32.to_bits()), expect.to_bits());
        unsafe { EXP_FRAC_KERNEL = saved };
        // Default restored.
        assert_eq!(fexp(1.0f32.to_bits()), POW_E[0]);
    }
}
