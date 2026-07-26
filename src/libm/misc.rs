//! Ports of ARM ADS 1.0.1 libm support routines from osos:
//!
//! - `ldexp`         — original: `FUN_08031c10` @ 0x08031c10 (224 bytes).
//! - `log10f`        — original: `FUN_08031f44` @ 0x08031f44 (52 bytes).
//! - `log_decompose` — original: `FUN_080340fc` @ 0x080340fc (276 bytes).
//!
//! retailOS is SOFT-FLOAT: doubles travel as `u64` and floats as `u32` raw
//! IEEE-754 bit patterns. No f32/f64 arithmetic appears below (it would
//! lower to the unported `__aeabi_*` helpers) — all floating-point math goes
//! through the committed soft-float primitive ports. Host tests use native
//! `f32::from_bits`/`f64::from_bits` as the oracle.
//!
//! Identification notes (correcting the original batch guesses):
//! - The "float wrapper" @ 0x08031f44 is `log10f`, not modff-family: it
//!   feeds the decomposer 0.30103f (log10(2), const @ 0x08031f80) and
//!   0.4342945f (log10(e), const @ 0x08031f7c) and tail-returns
//!   `__fadd` of the two output parts. Sole caller @ 0x0817df08.
//! - The "libm error reporter" @ 0x08032178 (20 bytes) is NOT a raise
//!   wrapper: its body is `*__rt_errno_addr() = code`. It is already
//!   committed as `errno_set` in crate::runtime::errno (osos numbering:
//!   1 = EDOM, 2 = ERANGE), so it is not re-ported here — these functions
//!   call it, exactly like the originals.
//! - The decomposer is the shared ln/log10 front-end, frexp-like: for
//!   x = m * 2^e with m in [1,2) it produces out1 = e * `exponent_scale`
//!   and out2 = kernel(u) [* `log_scale`], u = (m-1)/(m-(m-1)/(m+1))
//!   = (m²-1)/(m²+1), where the kernel FUN_08035b3c computes atanh(u)
//!   = ln(m) in fixed point. The `log_scale` multiply is skipped when
//!   `log_scale` == 1.0f (the natural-log caller); log10f passes
//!   log10(2)/log10(e) so that out1 + out2 = log10(x).
//!
//! Kernel dependency:
//! - FUN_08035b3c (524 bytes, fixed-point atanh/log kernel; sole caller is
//!   `log_decompose`) dispatches through the replaceable `LOG_ATANH_KERNEL`
//!   hook — the same pattern as `FP_TRAP_HANDLER` in fp_scalb. The wired
//!   default is the real port, `crate::libm::cordic::log_atanh_kernel`.
//!   Host tests still install a mock atanh kernel where they pin the
//!   surrounding plumbing bit-exactly.
//!
//! Other dependencies modeled here:
//! - Double "is finite" @ 0x082ab120 (32 bytes: exponent field != 0x7ff)
//!   and double copysign @ 0x082c4f50 (44 bytes: magnitude of first, sign
//!   of second) are called by ldexp but not yet committed as their own
//!   ports; they are ported as private helpers below, deliberately NOT
//!   `#[no_mangle]` so a future dedicated port can't collide.
//!
//! Behavioral notes:
//! - ADS soft-float has no subnormal support: subnormal inputs flush to
//!   +0.0. The original's subnormal "normalization" in `log_decompose`
//!   (`__fscalb(x, 32)`) therefore yields scaled = +0.0, m = 1.0,
//!   e = -159 — reproduced faithfully via the committed `__fscalb`.
//! - `ldexp` overflow returns copysign(+Inf, result) with errno = ERANGE;
//!   underflow returns copysign(+0.0, result) (const @ 0x08986040 is 0.0)
//!   with errno = ERANGE. Inf/NaN inputs pass through unchanged with errno
//!   untouched — NaN payloads are preserved because `__dscalb` (which would
//!   canonicalize) is never reached. ±0 inputs likewise return immediately.
//! - The original saves/restores `__ieee_status` bits 0xc around the
//!   `__dscalb` call; retailOS ships the always-zero stub, so this is a
//!   no-op but is mirrored anyway.
//! - The three `pub extern "C"` functions are exported (`#[no_mangle]`)
//!   only for the firmware target (`target_os = "none"`). On 64-bit hosts a C `float`/`double`
//!   argument travels in FP registers (s0/d0) while these ports take the
//!   soft-float bit patterns in general registers (w0/x0), so an exported
//!   `log10f`/`ldexp` would ABI-incompatibly shadow the host libm symbols
//!   that std's `f32::log10` & co. resolve to (the same class of collision
//!   raise.rs documents for `signal`). On the 32-bit soft-float target
//!   both ABIs use r0/r1, so the export is safe there — and that is where
//!   hooks.yaml / match.py need it.

use crate::fp_compare::{__dcmpeq, FLAGS_EQUAL};
use crate::fp_fadd::{__fadd, __frsb, __fsub};
use crate::fp_fconv::__i2f;
use crate::fp_fmuldiv::{__fdiv, __fmul};
use crate::fp_scalb::{__dscalb, __fscalb, __ieee_status};
use crate::runtime::errno::errno_set;

/// osos errno numbers (signal-name table order): 1 = EDOM, 2 = ERANGE.
const EDOM: i32 = 1;
const ERANGE: i32 = 2;

/// 1.0f — the mantissa exponent bias and the "skip multiply" sentinel.
const FLOAT_ONE: u32 = 0x3f80_0000;
/// 0.30103f (log10(2)) — original const @ 0x08031f80.
const FLOAT_LOG10_2: u32 = 0x3e9a_209b;
/// 0.4342945f (log10(e)) — original const @ 0x08031f7c.
const FLOAT_LOG10_E: u32 = 0x3ede_5bd9;
/// -Inf — log10(±0) result, original const @ 0x08034210.
const FLOAT_NEG_INF: u32 = 0xff80_0000;
/// log-domain NaN — log10(negative) result, original const @ 0x08034214.
const FLOAT_LOG_NAN: u32 = 0x7fc0_0001;
/// -Inf input bit pattern (the one exp==0xff case that takes the
/// negative-domain path instead of the __fscalb passthrough).
const FLOAT_NEG_INF_BITS: u32 = 0xff80_0000;
/// +Inf (double) — ldexp overflow magnitude, original const @ 0x08031d18.
const DOUBLE_POS_INF: u64 = 0x7ff0_0000_0000_0000;
/// +0.0 (double) — ldexp underflow magnitude, original const @ 0x08986040.
const DOUBLE_ZERO: u64 = 0;

/// Double "is finite" — original @ 0x082ab120 (32 bytes). Returns 1 when
/// the exponent field is not 0x7ff (finite, including zero/subnormal), 0
/// for ±Inf/NaN. PRIVATE port — see module header.
fn is_finite_double(x: u64) -> i32 {
    // Original: `cmp 0xffe00000, (hi >> 20) << 21; moveq r0,#0; movne r0,#1`
    // — the sign bit shifts out, so only the exponent field matters.
    if (x >> 52) & 0x7ff == 0x7ff {
        0
    } else {
        1
    }
}

/// Double copysign — original @ 0x082c4f50 (44 bytes). Result takes the
/// magnitude of `magnitude` and the sign of `sign_source`. PRIVATE port —
/// see module header.
fn copysign_double(magnitude: u64, sign_source: u64) -> u64 {
    (magnitude & 0x7fff_ffff_ffff_ffff) | (sign_source & 0x8000_0000_0000_0000)
}

/// ldexp — original: `FUN_08031c10` @ 0x08031c10 (224 bytes).
///
/// `x` is the raw double bit pattern, result is `x * 2^n`. Inf/NaN/±0
/// inputs return unchanged (errno untouched). Finite nonzero inputs go
/// through `__dscalb` bracketed by `__ieee_status` save/restore of bits
/// 0xc (a no-op on the stub status word). Overflow to ±Inf or underflow to
/// ±0 sets errno = ERANGE (2) and returns the copysign-adjusted ±Inf / ±0;
/// normal results return directly.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ldexp(x: u64, n: i32) -> u64 {
    if is_finite_double(x) == 0 {
        // ±Inf / NaN: pass through (the `cmp r0,#0; beq` early return).
        return x;
    }
    if __dcmpeq(x, DOUBLE_ZERO) == FLAGS_EQUAL {
        // ±0 scales to itself, no error.
        return x;
    }
    let saved_status = __ieee_status(0, 0) & 0xc;
    let result = __dscalb(x, n);
    __ieee_status(0xc, saved_status);
    if is_finite_double(result) == 0 {
        // Exponent overflowed to ±Inf.
        errno_set(ERANGE);
        return copysign_double(DOUBLE_POS_INF, result);
    }
    if __dcmpeq(result, DOUBLE_ZERO) == FLAGS_EQUAL {
        // Underflowed to ±0 (input was finite and nonzero).
        errno_set(ERANGE);
        return copysign_double(DOUBLE_ZERO, result);
    }
    result
}

/// Replaceable atanh/log kernel hook for FUN_08035b3c (see module
/// header). Called by `log_decompose` with the reduced argument
/// u = (m²-1)/(m²+1) as a float bit pattern; must return atanh(u) = ln(m)
/// as a float bit pattern. The wired default is the real port,
/// [`crate::libm::cordic::log_atanh_kernel`]; host tests swap in mocks.
///
/// `static mut`, written at port/bring-up time only — same discipline as
/// `FP_TRAP_HANDLER` in fp_scalb.
pub static mut LOG_ATANH_KERNEL: unsafe extern "C" fn(u32) -> u32 =
    crate::libm::cordic::log_atanh_kernel;

/// Dispatches through `LOG_ATANH_KERNEL`. The volatile read keeps the hook
/// a real runtime dispatch: without it LLVM const-folds the default and
/// on-device patching would silently have no effect.
unsafe fn log_atanh_kernel(u: u32) -> u32 {
    let kernel = core::ptr::read_volatile(&raw const LOG_ATANH_KERNEL);
    kernel(u)
}

/// log_decompose — original: `FUN_080340fc` @ 0x080340fc (276 bytes).
///
/// Shared ln/log10 front-end (frexp-like). All values are raw float bit
/// patterns. For a positive finite `x` = m * 2^e (m in [1,2)): writes
/// `__fmul(__i2f(e), exponent_scale)` to `out_exponent_part` and
/// `kernel(u)` (times `log_scale` unless that is exactly 1.0f) to
/// `out_log_part`, u = (m-1)/(m-(m-1)/(m+1)); returns 0.
///
/// Exceptional inputs return 1 with only `out_exponent_part` written:
/// ±0 -> -Inf with errno = EDOM; negative (including -Inf) -> 0x7fc00001
/// with errno = EDOM; +Inf -> +Inf and NaN -> canonical qNaN, both via
/// `__fscalb(x, 1)` with errno untouched.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn log_decompose(
    x: u32,
    exponent_scale: u32,
    log_scale: u32,
    out_exponent_part: *mut u32,
    out_log_part: *mut u32,
) -> i32 {
    // `mvn r2, r0, asr #23; tst r2, #0xff` — exponent field == 0xff.
    // -Inf (0xff800000) is excluded and joins the negative-domain path.
    if ((x as i32) >> 23) & 0xff == 0xff && x != FLOAT_NEG_INF_BITS {
        // +Inf passes through unchanged; NaN -> canonical qNaN (via the
        // __fscalb error descriptor). No errno.
        *out_exponent_part = __fscalb(x, 1);
        return 1;
    }
    if x & 0x7fff_ffff == 0 {
        // ±0.
        errno_set(EDOM);
        *out_exponent_part = FLOAT_NEG_INF;
        return 1;
    }
    if x & 0x8000_0000 != 0 {
        // Negative (including -Inf).
        errno_set(EDOM);
        *out_exponent_part = FLOAT_LOG_NAN;
        return 1;
    }

    // Positive finite. Subnormals flush to +0.0 inside __fscalb (see
    // module header) — the `wrapping_sub` reproduces the original's
    // e = 0 - 32 - 127 = -159 for that case.
    let mut scaled = x;
    let mut biased_exponent = (x << 1) >> 24;
    if biased_exponent == 0 {
        scaled = __fscalb(x, 32);
        biased_exponent = ((scaled << 1) >> 24).wrapping_sub(32);
    }
    // `bic r0, r0, #0xc0000000; orr r5, r0, #0x3f800000` — mantissa in
    // [1,2) with the exponent field forced to 127.
    let mantissa = (scaled & 0x3fff_ffff) | FLOAT_ONE;
    let exponent = (biased_exponent as i32) - 127;

    let exponent_part = __fmul(__i2f(exponent), exponent_scale);
    let mantissa_plus = __fadd(mantissa, FLOAT_ONE);
    let mantissa_minus = __fsub(mantissa, FLOAT_ONE);
    let ratio = __fdiv(mantissa_minus, mantissa_plus);
    // `__frsb(ratio, mantissa)` = mantissa - ratio.
    let reduced = __fdiv(mantissa_minus, __frsb(ratio, mantissa));
    let mut log_part = log_atanh_kernel(reduced);
    if log_scale != FLOAT_ONE {
        log_part = __fmul(log_part, log_scale);
    }
    *out_exponent_part = exponent_part;
    *out_log_part = log_part;
    0
}

/// log10f — original: `FUN_08031f44` @ 0x08031f44 (52 bytes).
///
/// `x` is the raw float bit pattern. Decomposes with the log10 constants
/// (0.30103f / 0.4342945f) and returns `__fadd` of the two parts; on a
/// decompose error the stored error value (-Inf / NaN / +Inf / qNaN) is
/// returned directly.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn log10f(x: u32) -> u32 {
    let mut exponent_part: u32 = 0;
    let mut log_part: u32 = 0;
    let error = log_decompose(
        x,
        FLOAT_LOG10_2,
        FLOAT_LOG10_E,
        &mut exponent_part,
        &mut log_part,
    );
    if error != 0 {
        return exponent_part;
    }
    __fadd(exponent_part, log_part)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::errno::errno_get;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// Serializes tests that swap the LOG_ATANH_KERNEL hook or touch the
    /// shared errno cell.
    static LOCK: Mutex<()> = Mutex::new(());

    const LOG10_2: f32 = 0.30103;
    const LOG10_E: f32 = 0.4342945;

    fn d(exp: u64, fraction: u64, negative: bool) -> u64 {
        ((negative as u64) << 63) | (exp << 52) | fraction
    }

    /// Exact 2^n as f64 via bit math (valid for the normal range).
    fn pow2d(n: i32) -> f64 {
        assert!((-1022..=1023).contains(&n));
        f64::from_bits(((n + 1023) as u64) << 52)
    }

    /// Host oracle for x * 2^n with |n| beyond one format range: multiply by
    /// ±2^chunk steps (each an exact normal power of two). Exact as long as
    /// the final result — and each intermediate — stays normal, which holds
    /// for every case these tests feed it.
    fn scale_d(x: f64, n: i32) -> f64 {
        let mut result = x;
        let mut rest = n;
        while rest > 1023 {
            result *= pow2d(1023);
            rest -= 1023;
        }
        while rest < -1022 {
            result *= pow2d(-1022);
            rest += 1022;
        }
        result * pow2d(rest)
    }

    // ---- ldexp ----

    #[test]
    fn ldexp_normal_matches_host() {
        let values = [
            1.5f64.to_bits(),
            (-2.25f64).to_bits(),
            std::f64::consts::PI.to_bits(),
            (-std::f64::consts::PI).to_bits(),
            f64::MIN_POSITIVE.to_bits(),
            d(1, 0x000f_ffff_ffff_ffff, false),
            d(0x7fe, 0x000f_ffff_ffff_ffff, true),
            d(0x355, 0x1234_5678_9abc, false),
        ];
        for &x in &values {
            let exp = ((x >> 52) & 0x7ff) as i32;
            for n in [-(exp - 1), -100, -3, -1, 0, 1, 2, 17, 100, 0x7fe - exp] {
                if n <= -exp || n >= 0x7ff - exp {
                    continue;
                }
                let expect = scale_d(f64::from_bits(x), n).to_bits();
                assert_eq!(unsafe { ldexp(x, n) }, expect, "x={x:#x} n={n}");
            }
        }
    }

    #[test]
    fn ldexp_overflow_sets_erange_returns_signed_inf() {
        let _g = LOCK.lock().unwrap();
        for n in [1024, 2000, i32::MAX] {
            unsafe {
                errno_set(0);
                assert_eq!(ldexp(1.5f64.to_bits(), n), f64::INFINITY.to_bits());
                assert_eq!(errno_get(), ERANGE, "n={n}");
                errno_set(0);
                assert_eq!(ldexp((-1.5f64).to_bits(), n), f64::NEG_INFINITY.to_bits());
                assert_eq!(errno_get(), ERANGE, "n={n}");
            }
        }
        // Largest normal * 2 overflows; one below the boundary does not.
        unsafe {
            errno_set(0);
            assert_eq!(ldexp(f64::MAX.to_bits(), 1), f64::INFINITY.to_bits());
            assert_eq!(errno_get(), ERANGE);
            errno_set(0);
            let n = 0x7ff - 0x3ff - 1;
            assert_eq!(ldexp(1.5f64.to_bits(), n), (1.5f64 * pow2d(n)).to_bits());
            assert_eq!(errno_get(), 0);
        }
    }

    #[test]
    fn ldexp_underflow_sets_erange_returns_signed_zero() {
        let _g = LOCK.lock().unwrap();
        for n in [-1023, -2000, i32::MIN] {
            unsafe {
                errno_set(0);
                assert_eq!(ldexp(1.5f64.to_bits(), n), 0.0f64.to_bits());
                assert_eq!(errno_get(), ERANGE, "n={n}");
                errno_set(0);
                // Sign of the underflowed result is preserved.
                assert_eq!(ldexp((-1.5f64).to_bits(), n), (-0.0f64).to_bits());
                assert_eq!(errno_get(), ERANGE, "n={n}");
            }
        }
        // One above the boundary is the smallest normal-exponent result.
        unsafe {
            errno_set(0);
            let n = -0x3ff + 1;
            assert_eq!(ldexp(1.5f64.to_bits(), n), (1.5f64 * pow2d(n)).to_bits());
            assert_eq!(errno_get(), 0);
        }
    }

    #[test]
    fn ldexp_inf_nan_zero_passthrough_errno_untouched() {
        let _g = LOCK.lock().unwrap();
        unsafe {
            for n in [i32::MIN, -1, 0, 1, i32::MAX] {
                errno_set(0);
                assert_eq!(ldexp(f64::INFINITY.to_bits(), n), f64::INFINITY.to_bits());
                assert_eq!(errno_get(), 0);
                assert_eq!(ldexp(f64::NEG_INFINITY.to_bits(), n), f64::NEG_INFINITY.to_bits());
                assert_eq!(errno_get(), 0);
                assert_eq!(ldexp(0.0f64.to_bits(), n), 0.0f64.to_bits());
                assert_eq!(errno_get(), 0);
                assert_eq!(ldexp((-0.0f64).to_bits(), n), (-0.0f64).to_bits());
                assert_eq!(errno_get(), 0);
            }
            // NaN passes through with its payload preserved (the early
            // return never reaches __dscalb's canonicalization).
            let nan = d(0x7ff, 0x0008_1234_5678, true);
            assert_eq!(ldexp(nan, 3), nan);
            assert_eq!(errno_get(), 0);
        }
    }

    // ---- log_decompose ----

    static LAST_KERNEL_ARG: AtomicU32 = AtomicU32::new(0);

    /// Host atanh(u) as the mock kernel: ln(m) = atanh((m²-1)/(m²+1)).
    unsafe extern "C" fn mock_atanh_kernel(u: u32) -> u32 {
        LAST_KERNEL_ARG.store(u, Ordering::SeqCst);
        atanh_bits(f32::from_bits(u))
    }

    /// Host atanh(u) = 0.5*ln((1+u)/(1-u)) as f32 bits. The transcendental
    /// is evaluated in f64 so the oracle only needs libSystem's `log`
    /// (double) — no symbol this crate exports can interpose it (see the
    /// module header on the ABI-incompatible shadow problem).
    fn atanh_bits(u: f32) -> u32 {
        let v = (1.0f32 + u) / (1.0f32 - u);
        ((0.5f64 * (v as f64).ln()) as f32).to_bits()
    }

    unsafe fn install_mock_kernel() {
        LOG_ATANH_KERNEL = mock_atanh_kernel;
    }

    unsafe fn restore_default_kernel() {
        LOG_ATANH_KERNEL = crate::libm::cordic::log_atanh_kernel;
    }

    /// Host mirror of the decompose main path, step by step in f32 so the
    /// expected bit patterns match the soft-float primitives exactly.
    /// Returns (exponent_part bits, reduced-u bits, log_part bits).
    fn host_decompose(x: f32, exponent_scale: f32, log_scale: f32) -> (u32, u32, u32) {
        let mut scaled = x.to_bits();
        let mut biased = (scaled << 1) >> 24;
        if biased == 0 {
            // Subnormal: __fscalb flushes the input to +0.0.
            scaled = 0;
            biased = 0u32.wrapping_sub(32);
        }
        let mantissa = f32::from_bits((scaled & 0x3fff_ffff) | 0x3f80_0000);
        let exponent = (biased as i32) - 127;
        let exponent_part = ((exponent as f32) * exponent_scale).to_bits();
        let m_plus = mantissa + 1.0;
        let m_minus = mantissa - 1.0;
        let ratio = m_minus / m_plus;
        let reduced = m_minus / (mantissa - ratio);
        let mut log_part = atanh_bits(reduced);
        if log_scale != 1.0 {
            log_part = (f32::from_bits(log_part) * log_scale).to_bits();
        }
        (exponent_part, reduced.to_bits(), log_part)
    }

    fn decompose(x: u32, exponent_scale: u32, log_scale: u32) -> (i32, u32, u32) {
        let mut exponent_part = 0xdead_beef;
        let mut log_part = 0xdead_beef;
        let ret = unsafe {
            log_decompose(
                x,
                exponent_scale,
                log_scale,
                &mut exponent_part,
                &mut log_part,
            )
        };
        (ret, exponent_part, log_part)
    }

    #[test]
    fn decompose_positive_normal_matches_host() {
        let _g = LOCK.lock().unwrap();
        unsafe { install_mock_kernel() };
        let values = [0.5f32, 1.0, 1.5, 2.0, 3.0, 10.0, 123.5, 1e-10, 1e30, f32::MIN_POSITIVE];
        for &x in &values {
            for &(es, ls) in &[(LOG10_2, LOG10_E), (1.0f32, 1.0f32), (2.5f32, 0.75f32)] {
                let (want_ep, want_u, want_lp) = host_decompose(x, es, ls);
                let (ret, ep, lp) = decompose(x.to_bits(), es.to_bits(), ls.to_bits());
                assert_eq!(ret, 0, "x={x}");
                assert_eq!(ep, want_ep, "exponent_part x={x} es={es} ls={ls}");
                assert_eq!(LAST_KERNEL_ARG.load(Ordering::SeqCst), want_u, "kernel arg x={x}");
                assert_eq!(lp, want_lp, "log_part x={x} es={es} ls={ls}");
            }
        }
        unsafe { restore_default_kernel() };
    }

    #[test]
    fn decompose_log_scale_one_skips_multiply() {
        let _g = LOCK.lock().unwrap();
        unsafe { install_mock_kernel() };
        // With log_scale == 1.0f the raw kernel result is stored verbatim —
        // pick a value whose atanh * 1.0 would round differently if the
        // multiply happened (it can't: *1.0 is exact, so instead verify the
        // stored value equals the un-multiplied kernel output exactly).
        let (ret, _ep, lp) = decompose(3.0f32.to_bits(), FLOAT_LOG10_2, FLOAT_ONE);
        assert_eq!(ret, 0);
        let (_, u, _) = host_decompose(3.0, LOG10_2, 1.0);
        assert_eq!(lp, atanh_bits(f32::from_bits(u)));
        unsafe { restore_default_kernel() };
    }

    #[test]
    fn decompose_subnormal_flushes_via_fscalb() {
        let _g = LOCK.lock().unwrap();
        unsafe { install_mock_kernel() };
        // Subnormal input: __fscalb flushes to +0.0, so m = 1.0 and
        // e = -159; u = 0 and the log part is 0. Faithful ADS behavior.
        for x in [1u32, 0x007f_ffff] {
            let (ret, ep, lp) = decompose(x, FLOAT_LOG10_2, FLOAT_LOG10_E);
            assert_eq!(ret, 0);
            assert_eq!(ep, (-159.0f32 * LOG10_2).to_bits(), "x={x:#x}");
            assert_eq!(LAST_KERNEL_ARG.load(Ordering::SeqCst), 0, "x={x:#x}");
            assert_eq!(lp, 0.0f32.to_bits(), "x={x:#x}");
        }
        unsafe { restore_default_kernel() };
    }

    #[test]
    fn decompose_error_paths() {
        let _g = LOCK.lock().unwrap();
        unsafe {
            // ±0 -> EDOM, -Inf.
            for x in [0.0f32.to_bits(), (-0.0f32).to_bits()] {
                errno_set(0);
                let (ret, ep, _lp) = decompose(x, FLOAT_LOG10_2, FLOAT_LOG10_E);
                assert_eq!(ret, 1);
                assert_eq!(ep, FLOAT_NEG_INF);
                assert_eq!(errno_get(), EDOM);
            }
            // Negative and -Inf -> EDOM, domain NaN 0x7fc00001.
            for x in [(-1.0f32).to_bits(), (-123.5f32).to_bits(), FLOAT_NEG_INF_BITS] {
                errno_set(0);
                let (ret, ep, _lp) = decompose(x, FLOAT_LOG10_2, FLOAT_LOG10_E);
                assert_eq!(ret, 1, "x={x:#x}");
                assert_eq!(ep, FLOAT_LOG_NAN, "x={x:#x}");
                assert_eq!(errno_get(), EDOM, "x={x:#x}");
            }
            // +Inf -> +Inf, errno untouched.
            errno_set(0);
            let (ret, ep, _lp) = decompose(f32::INFINITY.to_bits(), FLOAT_LOG10_2, FLOAT_LOG10_E);
            assert_eq!(ret, 1);
            assert_eq!(ep, f32::INFINITY.to_bits());
            assert_eq!(errno_get(), 0);
            // NaN -> canonical qNaN via __fscalb, errno untouched.
            errno_set(0);
            let (ret, ep, _lp) = decompose(f32::NAN.to_bits(), FLOAT_LOG10_2, FLOAT_LOG10_E);
            assert_eq!(ret, 1);
            assert_eq!(ep, 0x7fc0_0000);
            assert_eq!(errno_get(), 0);
        }
    }

    #[test]
    fn decompose_wired_default_is_real_cordic_kernel() {
        let _g = LOCK.lock().unwrap();
        unsafe { restore_default_kernel() };
        // The wired default is the real CORDIC port: the log part must be
        // exactly what the exported kernel returns for the reduced u.
        let (ret, _ep, lp) = decompose(3.0f32.to_bits(), FLOAT_LOG10_2, FLOAT_ONE);
        assert_eq!(ret, 0);
        let (_, want_u, _) = host_decompose(3.0, LOG10_2, 1.0);
        assert_eq!(lp, unsafe { crate::libm::cordic::log_atanh_kernel(want_u) });
        // ... which is atanh(u) = ln(m) to within a couple ulp.
        let want_ln = ((f32::from_bits(want_u) as f64).atanh() as f32).to_bits();
        assert!(ulp_distance(lp, want_ln) <= 2, "lp={lp:#x} want={want_ln:#x}");
        // Powers of two give m == 1.0 -> u == 0, the kernel's exact fast
        // path.
        let (ret, ep, lp) = decompose(4.0f32.to_bits(), FLOAT_LOG10_2, FLOAT_LOG10_E);
        assert_eq!(ret, 0);
        assert_eq!(ep, (2.0f32 * LOG10_2).to_bits());
        assert_eq!(lp, 0.0f32.to_bits());
    }

    #[test]
    fn log10f_end_to_end_through_wired_kernel_matches_host() {
        let _g = LOCK.lock().unwrap();
        unsafe { restore_default_kernel() };
        // Full original pipeline (decompose + real CORDIC kernel + __fadd)
        // against the host's double-precision log10.
        for &x in &[0.5f32, 1.0, 1.5, 2.0, 3.0, 10.0, 100.0, 123.5, 0.001, 1e-10, 1e30,
                    f32::MIN_POSITIVE, 6.02e23] {
            let got = unsafe { log10f(x.to_bits()) };
            let reference = ((x as f64).log10() as f32).to_bits();
            assert!(
                ulp_distance(got, reference) <= 4,
                "x={x} got={got:#x} ref={reference:#x}"
            );
        }
        assert_eq!(unsafe { log10f(1.0f32.to_bits()) }, 0.0f32.to_bits());
    }

    // ---- log10f ----

    /// Host mirror of the full log10f: decompose with the log10 constants,
    /// then add the parts.
    fn host_log10f(x: f32) -> u32 {
        let (ep, _, lp) = host_decompose(x, LOG10_2, LOG10_E);
        (f32::from_bits(ep) + f32::from_bits(lp)).to_bits()
    }

    /// Ordered-integer ulp distance for same-sign floats (i64 math: the
    /// raw bit patterns can straddle the i32 range across signs).
    fn ulp_distance(a: u32, b: u32) -> i64 {
        (a as i64 - b as i64).abs()
    }

    #[test]
    fn log10f_end_to_end_matches_host() {
        let _g = LOCK.lock().unwrap();
        unsafe { install_mock_kernel() };
        let values = [0.5f32, 1.0, 1.5, 2.0, 3.0, 10.0, 100.0, 123.5, 1e-10, 1e30, f32::MIN_POSITIVE];
        for &x in &values {
            assert_eq!(unsafe { log10f(x.to_bits()) }, host_log10f(x), "x={x}");
        }
        unsafe { restore_default_kernel() };
    }

    #[test]
    fn log10f_close_to_std_log10() {
        let _g = LOCK.lock().unwrap();
        unsafe { install_mock_kernel() };
        // The mock kernel is the true atanh, so the composition should land
        // within a few ulp of the host's log10. The reference goes through
        // f64 (libSystem `log10`) — f32::log10 would resolve to `log10f`,
        // which is exactly the symbol this module exports in non-test
        // builds (see module header).
        for &x in &[0.5f32, 1.5, 3.0, 10.0, 123.5, 1e30] {
            let got = unsafe { log10f(x.to_bits()) };
            let reference = ((x as f64).log10() as f32).to_bits();
            assert!(
                ulp_distance(got, reference) <= 4,
                "x={x} got={got:#x} ref={reference:#x}"
            );
        }
        // Exact special values.
        assert_eq!(unsafe { log10f(1.0f32.to_bits()) }, 0.0f32.to_bits());
        unsafe { restore_default_kernel() };
    }

    #[test]
    fn log10f_error_paths() {
        let _g = LOCK.lock().unwrap();
        unsafe {
            errno_set(0);
            assert_eq!(log10f(0.0f32.to_bits()), f32::NEG_INFINITY.to_bits());
            assert_eq!(errno_get(), EDOM);
            errno_set(0);
            assert_eq!(log10f((-0.0f32).to_bits()), f32::NEG_INFINITY.to_bits());
            assert_eq!(errno_get(), EDOM);
            errno_set(0);
            assert_eq!(log10f((-2.5f32).to_bits()), FLOAT_LOG_NAN);
            assert_eq!(errno_get(), EDOM);
            errno_set(0);
            assert_eq!(log10f(f32::INFINITY.to_bits()), f32::INFINITY.to_bits());
            assert_eq!(errno_get(), 0);
            errno_set(0);
            assert_eq!(log10f(f32::NAN.to_bits()), 0x7fc0_0000);
            assert_eq!(errno_get(), 0);
        }
    }
}
