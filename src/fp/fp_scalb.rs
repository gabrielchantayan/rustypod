//! Ports of the ARM ADS 1.0.1 soft-float scaling/status routines from osos:
//!
//! - `__ieee_status` — original: `FUN_083ece54` @ 0x083ece54 (8 bytes).
//! - `__dscalb`      — original: `FUN_083ed0dc` @ 0x083ed0dc (116 bytes).
//! - `__fscalb`      — original: `FUN_083ed150` @ 0x083ed150 (164 bytes).
//!
//! retailOS is SOFT-FLOAT: doubles travel in register pairs / `u64` and
//! floats in `u32` as raw IEEE-754 bit patterns. The module below does pure
//! integer bit manipulation — no f32/f64 arithmetic anywhere (it would lower
//! to the unported `__aeabi_d*`/`__aeabi_f*` helpers). Host tests use native
//! `f64::from_bits`/`f32::from_bits` as the oracle.
//!
//! Algorithms (identical shape for double and float):
//! `scalb(x, n)` extracts the biased exponent `e`. When `x` is a normal
//! number and `-e < n < BIAS_MAX - e` (so `0 < e + n < BIAS_MAX`), the
//! answer is `x + (n << EXP_SHIFT)` — a pure add into the exponent field,
//! exact by construction. Otherwise:
//! - `e == 0` (zero or subnormal input): ADS soft-float has no subnormal
//!   support — subnormals flush to `+0.0` (sign dropped!); true zero keeps
//!   its sign. `n` is ignored entirely.
//! - `e == BIAS_MAX`: Inf passes through unchanged; NaN raises the error
//!   descriptor `0x0400009b` (double) / `0x0400000b` (float) and yields the
//!   canonical quiet NaN.
//! - normal `e` out of fast range: `n >= 0` (i.e. `e + n >= BIAS_MAX`)
//!   saturates to ±Inf; `n < 0` (i.e. `e + n <= 0`) flushes to ±0 — no
//!   gradual underflow, and NO trap on underflow (the original simply
//!   returns ±0).
//!
//! Error-descriptor / trap mechanism (modeled faithfully, see `fp_error`):
//! exceptional paths load a default result and branch to a dispatcher that
//! enters the trap decode @ 0x083ed080 with an encoded descriptor in `ip`:
//! - 0x083eb144 — double NaN/error dispatcher: loads `r1:r0 =
//!   0x7ff80000:0x00000000` (canonical double qNaN), `b 0x083ed080`.
//! - 0x83ec5f0  — float NaN/error dispatcher actually used by `__fscalb`:
//!   loads `r0 = 0x7fc00000`, `b 0x083ed080`. (The similar code at
//!   0x083eb1d4 is the float *compare* NaN check; 0x083eb154 its double
//!   counterpart — they feed the same decode with compare descriptors.)
//! - 0x083ed080 — trap decode: descriptor low nibble 8/10 rewrites the
//!   result (±0 / canonical qNaN), nibble 9 produces a CPSR-flag compare
//!   result, anything else (incl. 0xb used by scalb) returns the
//!   dispatcher's default unchanged. On device the unhandled-error path
//!   prints a register dump (printer @ 0x082c6f58) and traps.
//!
//! Deliberate deviations / simplifications:
//! - `__ieee_status` in retailOS is a stub (`mov r0, #0; bx lr`): ADS
//!   normally keeps an fp status word here (op 0 = read, 1 = clear bits,
//!   2 = set bits); the stub always reports 0. Ported exactly as-is.
//! - The on-device "print register dump and trap" is replaced by the
//!   `FP_TRAP_HANDLER` hook (default: return the canonical NaN/result the
//!   hardware path would have produced).
//! - Trap-decode nibble 9 (result returned as CPSR flags for the compare
//!   dispatchers) is not modeled — scalb never emits it, and CPSR flag
//!   results have no meaning in Rust; see `fp_compare` for compares.

/// Quiet-NaN / zero constants produced by the dispatchers + trap decode.
const DOUBLE_QNAN: u64 = 0x7ff8_0000_0000_0000;
const FLOAT_QNAN: u32 = 0x7fc0_0000;

/// Error descriptor `__dscalb` raises for a NaN input (bit 26 set = result
/// value present; low nibble 0xb passes the trap decode unchanged).
const DSCALB_NAN_DESCRIPTOR: u32 = 0x0400_009b;
/// Same for `__fscalb`.
const FSCALB_NAN_DESCRIPTOR: u32 = 0x0400_000b;

/// Default trap handler: return the canonical result untouched.
///
/// On device, an unhandled fp error instead prints a crash/register dump
/// (printer @ 0x082c6f58) and traps; the default here keeps the value the
/// original code path computes before that dump.
unsafe extern "C" fn default_fp_trap_handler(_descriptor: u32, result: u64) -> u64 {
    result
}

/// FP error/trap hook. Called with the ADS error descriptor and the result
/// the original trap decode @ 0x083ed080 would produce (double bit pattern,
/// or float bit pattern in the low 32 bits); the returned value is used as
/// the function's result instead. Default is [`default_fp_trap_handler`]
/// (return the canonical NaN/result unchanged). Replace it to observe or
/// substitute fp errors — e.g. to emulate the device's crash-dump trap.
///
/// `static mut`, written at port/bring-up time only — same discipline as the
/// firmware's own hook tables.
pub static mut FP_TRAP_HANDLER: unsafe extern "C" fn(descriptor: u32, result: u64) -> u64 =
    default_fp_trap_handler;

/// Model of the trap decode @ 0x083ed080 plus the dispatcher that loaded
/// `default_result` (0x083eb144 for doubles, 0x83ec5f0 for floats).
///
/// The decode inspects the descriptor's low nibble: 8 and 10 rewrite the
/// result, anything else (including the 0xb descriptors scalb raises, and
/// nibble 9 whose CPSR-flag compare result is not modeled — see header)
/// returns the dispatcher's default. The decoded value then goes through
/// `FP_TRAP_HANDLER`, which stands in for the device's dump-and-trap.
unsafe fn fp_error(descriptor: u32, default_result: u64) -> u64 {
    let decoded = match descriptor & 0xf {
        // Nibble 8: bit 6 set -> +0.0 (both words); bit 6 clear -> bit 4
        // selects double (0x7ff80000:0) vs float (0x7fc00000) canonical qNaN.
        8 => {
            if descriptor & 0x40 != 0 {
                0
            } else if descriptor & 0x10 != 0 {
                DOUBLE_QNAN
            } else {
                FLOAT_QNAN as u64
            }
        }
        // Nibble 10: bit 6 set -> -0.0f (r0 = 0x80000000); else unchanged.
        10 => {
            if descriptor & 0x40 != 0 {
                0x8000_0000
            } else {
                default_result
            }
        }
        _ => default_result,
    };
    // Volatile read so the hook is a real runtime dispatch: without it LLVM
    // const-folds the default handler and on-device patching of
    // `FP_TRAP_HANDLER` would silently have no effect.
    let handler = core::ptr::read_volatile(&raw const FP_TRAP_HANDLER);
    handler(descriptor, decoded)
}

/// __ieee_status — original: `FUN_083ece54` @ 0x083ece54 (8 bytes).
///
/// ADS runtime fp-status accessor: `op` 0 = read status word, 1 = clear
/// `bits`, 2 = set `bits`; returns the previous status. retailOS ships the
/// stub version (`mov r0, #0; bx lr`) — no fp status is kept, so every call
/// returns 0 and `op`/`bits` are ignored. Called around ldexp/fmod. Ported
/// exactly as the stub.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __ieee_status(_op: u32, _bits: u32) -> u32 {
    0
}

/// __dscalb — original: `FUN_083ed0dc` @ 0x083ed0dc (116 bytes).
///
/// `scalbn` for doubles in soft-float form: `x` is the raw IEEE-754 double
/// bit pattern, result is the bit pattern of `x * 2^n`. Adds `n << 20` into
/// the exponent field when the result stays normal; saturates to ±Inf on
/// exponent overflow and flushes to ±0 on underflow (no subnormals, no
/// underflow trap). Subnormal inputs flush to +0.0; NaN inputs raise
/// descriptor 0x0400009b and yield the canonical qNaN via `fp_error`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __dscalb(x: u64, n: i32) -> u64 {
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    let exponent = (hi >> 20) & 0x7ff;

    // Fast path (the original's `cmp`/`cmn` GT chain): normal input and
    // 0 < exponent + n < 0x7ff — a pure add into the exponent field.
    if exponent != 0 && exponent != 0x7ff {
        let headroom = (0x7ff - exponent) as i32;
        let floor = -(exponent as i32);
        if n < headroom && n > floor {
            let scaled_hi = hi.wrapping_add((n as u32) << 20);
            return ((scaled_hi as u64) << 32) | lo as u64;
        }
    }

    if exponent == 0 {
        // Zero/subnormal input: keep the sign of a true zero; flush a
        // subnormal to +0.0 (the original's `movne r1, #0` drops the sign).
        let fraction_nonzero = lo | (hi << 12) != 0;
        if fraction_nonzero {
            return 0;
        }
        return ((hi & 0x8000_0000) as u64) << 32;
    }

    if exponent == 0x7ff {
        let fraction_nonzero = lo | (hi << 12) != 0;
        if !fraction_nonzero {
            // ±Inf scales to itself, whatever n is.
            return x;
        }
        // NaN input: dispatcher 0x083eb144 loads the canonical double qNaN
        // and enters the trap decode with descriptor 0x0400009b.
        return fp_error(DSCALB_NAN_DESCRIPTOR, DOUBLE_QNAN);
    }

    // Normal input, exponent left the valid range: keep only the sign.
    let mut result_hi = hi & 0x8000_0000;
    if n >= 0 {
        // exponent + n >= 0x7ff: overflow to ±Inf.
        result_hi |= 0x7ff0_0000;
    }
    // n < 0: exponent + n <= 0, flush to ±0 (no subnormal result, no trap).
    (result_hi as u64) << 32
}

/// __fscalb — original: `FUN_083ed150` @ 0x083ed150 (164 bytes).
///
/// Float version of `__dscalb`: `x` is the raw IEEE-754 float bit pattern,
/// result is `x * 2^n` with bias 0xff. Identical structure: exponent-field
/// add for normal results, ±Inf on overflow, ±0 on underflow, subnormal
/// inputs flush to +0.0, NaN raises descriptor 0x0400000b via `fp_error`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __fscalb(x: u32, n: i32) -> u32 {
    let exponent = (x >> 23) & 0xff;

    // Fast path: normal input and 0 < exponent + n < 0xff.
    if exponent != 0 && exponent != 0xff {
        let headroom = (0xff - exponent) as i32;
        let floor = -(exponent as i32);
        if n < headroom && n > floor {
            return x.wrapping_add((n as u32) << 23);
        }
    }

    if exponent == 0 {
        // Zero keeps its sign; subnormal flushes to +0.0.
        if x << 9 != 0 {
            return 0;
        }
        return x & 0x8000_0000;
    }

    if exponent == 0xff {
        if x << 9 == 0 {
            // ±Inf scales to itself.
            return x;
        }
        // NaN input: dispatcher 0x83ec5f0 loads the canonical float qNaN
        // and enters the trap decode with descriptor 0x0400000b.
        return fp_error(FSCALB_NAN_DESCRIPTOR, FLOAT_QNAN as u64) as u32;
    }

    let mut result = x & 0x8000_0000;
    if n >= 0 {
        result |= 0x7f80_0000;
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// Serializes tests that exercise NaN inputs: the trap-handler test
    /// swaps `FP_TRAP_HANDLER`, which would otherwise race with the
    /// canonical-NaN assertions in the input-edge-case tests.
    static TRAP_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Exact 2^n as f64 via bit math (valid for the normal range).
    fn pow2d(n: i32) -> f64 {
        assert!((-1022..=1023).contains(&n));
        f64::from_bits(((n + 1023) as u64) << 52)
    }

    /// Exact 2^n as f32 via bit math (valid for the normal range).
    fn pow2f(n: i32) -> f32 {
        assert!((-126..=127).contains(&n));
        f32::from_bits(((n + 127) as u32) << 23)
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

    /// f32 oracle via f64 (widening is exact; narrowing a normal result is
    /// exact since power-of-two scaling never rounds).
    fn scale_f(x: f32, n: i32) -> f32 {
        scale_d(x as f64, n) as f32
    }

    fn d(exp: u64, fraction: u64, negative: bool) -> u64 {
        ((negative as u64) << 63) | (exp << 52) | fraction
    }

    fn f(exp: u32, fraction: u32, negative: bool) -> u32 {
        ((negative as u32) << 31) | (exp << 23) | fraction
    }

    // ---- __dscalb ----

    #[test]
    fn dscalb_normal_matches_host() {
        let values = [
            1.5f64.to_bits(),
            (-2.25f64).to_bits(),
            std::f64::consts::PI.to_bits(),
            (-std::f64::consts::PI).to_bits(),
            f64::MIN_POSITIVE.to_bits(),
            d(1, 0x000f_ffff_ffff_ffff, false), // just above min normal
            d(0x7fe, 0x000f_ffff_ffff_ffff, true), // near max
            d(0x355, 0x1234_5678_9abc, false),
        ];
        for &x in &values {
            let exp = ((x >> 52) & 0x7ff) as i32;
            // Keep the result normal: -exp < n < 0x7ff - exp.
            for n in [-(exp - 1), -100, -3, -1, 0, 1, 2, 17, 100, 0x7fe - exp] {
                if n <= -exp || n >= 0x7ff - exp {
                    continue;
                }
                let expect = scale_d(f64::from_bits(x), n).to_bits();
                assert_eq!(
                    unsafe { __dscalb(x, n) },
                    expect,
                    "x={x:#x} n={n}"
                );
            }
        }
    }

    #[test]
    fn dscalb_overflow_to_inf() {
        // Exponent reaches 0x7ff exactly -> Inf (boundary), beyond -> Inf.
        for n in [0x7ff - 0x3ff, 0x7ff - 0x3ff + 1, 2000, i32::MAX] {
            assert_eq!(unsafe { __dscalb(1.5f64.to_bits(), n) }, f64::INFINITY.to_bits());
            assert_eq!(
                unsafe { __dscalb((-1.5f64).to_bits(), n) },
                f64::NEG_INFINITY.to_bits()
            );
        }
        // Largest normal * 2 -> Inf.
        assert_eq!(unsafe { __dscalb(f64::MAX.to_bits(), 1) }, f64::INFINITY.to_bits());
        // One below the boundary stays normal.
        let x = 1.5f64.to_bits();
        let n = 0x7ff - 0x3ff - 1;
        assert_eq!(unsafe { __dscalb(x, n) }, (1.5f64 * pow2d(n)).to_bits());
    }

    #[test]
    fn dscalb_underflow_flushes_to_zero() {
        // 1.5 has exp 0x3ff: n == -0x3ff lands the exponent on 0 -> ±0.
        for n in [-0x3ff, -0x3ff - 1, -2000, i32::MIN] {
            assert_eq!(unsafe { __dscalb(1.5f64.to_bits(), n) }, 0);
            // Sign is preserved on underflow to zero.
            assert_eq!(unsafe { __dscalb((-1.5f64).to_bits(), n) }, (-0.0f64).to_bits());
        }
        // One above the boundary is the smallest normal-exponent result.
        let x = 1.5f64.to_bits();
        let n = -0x3ff + 1;
        assert_eq!(unsafe { __dscalb(x, n) }, (1.5f64 * pow2d(n)).to_bits());
    }

    #[test]
    fn dscalb_zero_subnormal_inf_nan_inputs() {
        let _guard = TRAP_TEST_LOCK.lock().unwrap();
        // True zero keeps its sign, n is ignored.
        assert_eq!(unsafe { __dscalb(0.0f64.to_bits(), 100) }, 0.0f64.to_bits());
        assert_eq!(unsafe { __dscalb((-0.0f64).to_bits(), -100) }, (-0.0f64).to_bits());
        // Subnormal input flushes to +0.0 — sign dropped, even for negative.
        assert_eq!(unsafe { __dscalb(1, 1000) }, 0);
        assert_eq!(unsafe { __dscalb(0x8000_0000_0000_0001, 1000) }, 0);
        assert_eq!(unsafe { __dscalb(0x000f_ffff_ffff_ffff, -5) }, 0);
        // Inf passes through unchanged for any n.
        for n in [i32::MIN, -1, 0, 1, i32::MAX] {
            assert_eq!(unsafe { __dscalb(f64::INFINITY.to_bits(), n) }, f64::INFINITY.to_bits());
            assert_eq!(
                unsafe { __dscalb(f64::NEG_INFINITY.to_bits(), n) },
                f64::NEG_INFINITY.to_bits()
            );
        }
        // NaN -> canonical quiet NaN (sign and payload dropped).
        assert_eq!(unsafe { __dscalb(f64::NAN.to_bits(), 3) }, DOUBLE_QNAN);
        assert_eq!(unsafe { __dscalb(d(0x7ff, 1, true), -3) }, DOUBLE_QNAN);
    }

    // ---- __fscalb ----

    #[test]
    fn fscalb_normal_matches_host() {
        let values = [
            1.5f32.to_bits(),
            (-2.25f32).to_bits(),
            std::f32::consts::PI.to_bits(),
            f32::MIN_POSITIVE.to_bits(),
            f(1, 0x007f_ffff, false),
            f(0xfe, 0x007f_ffff, true),
            f(0x55, 0x0056_789a, false),
        ];
        for &x in &values {
            let exp = ((x >> 23) & 0xff) as i32;
            for n in [-(exp - 1), -40, -3, -1, 0, 1, 2, 17, 40, 0xfe - exp] {
                if n <= -exp || n >= 0xff - exp {
                    continue;
                }
                let expect = scale_f(f32::from_bits(x), n).to_bits();
                assert_eq!(
                    unsafe { __fscalb(x, n) },
                    expect,
                    "x={x:#x} n={n}"
                );
            }
        }
    }

    #[test]
    fn fscalb_overflow_underflow() {
        for n in [0xff - 0x7f, 0xff - 0x7f + 1, 300, i32::MAX] {
            assert_eq!(unsafe { __fscalb(1.5f32.to_bits(), n) }, f32::INFINITY.to_bits());
            assert_eq!(
                unsafe { __fscalb((-1.5f32).to_bits(), n) },
                f32::NEG_INFINITY.to_bits()
            );
        }
        assert_eq!(unsafe { __fscalb(f32::MAX.to_bits(), 1) }, f32::INFINITY.to_bits());
        for n in [-0x7f, -0x80, -300, i32::MIN] {
            assert_eq!(unsafe { __fscalb(1.5f32.to_bits(), n) }, 0);
            assert_eq!(unsafe { __fscalb((-1.5f32).to_bits(), n) }, (-0.0f32).to_bits());
        }
        // Boundary results just inside the normal range.
        let x = 1.5f32.to_bits();
        assert_eq!(
            unsafe { __fscalb(x, 0xff - 0x7f - 1) },
            (1.5f32 * pow2f(0xff - 0x7f - 1)).to_bits()
        );
        assert_eq!(
            unsafe { __fscalb(x, -0x7f + 1) },
            (1.5f32 * pow2f(-0x7f + 1)).to_bits()
        );
    }

    #[test]
    fn fscalb_zero_subnormal_inf_nan_inputs() {
        let _guard = TRAP_TEST_LOCK.lock().unwrap();
        assert_eq!(unsafe { __fscalb(0.0f32.to_bits(), 100) }, 0.0f32.to_bits());
        assert_eq!(unsafe { __fscalb((-0.0f32).to_bits(), -100) }, (-0.0f32).to_bits());
        // Subnormal flushes to +0.0 with the sign dropped.
        assert_eq!(unsafe { __fscalb(1, 1000) }, 0);
        assert_eq!(unsafe { __fscalb(0x8000_0001, 1000) }, 0);
        assert_eq!(unsafe { __fscalb(0x007f_ffff, -5) }, 0);
        for n in [i32::MIN, -1, 0, 1, i32::MAX] {
            assert_eq!(unsafe { __fscalb(f32::INFINITY.to_bits(), n) }, f32::INFINITY.to_bits());
            assert_eq!(
                unsafe { __fscalb(f32::NEG_INFINITY.to_bits(), n) },
                f32::NEG_INFINITY.to_bits()
            );
        }
        assert_eq!(unsafe { __fscalb(f32::NAN.to_bits(), 3) }, FLOAT_QNAN);
        assert_eq!(unsafe { __fscalb(f(0xff, 1, true), -3) }, FLOAT_QNAN);
    }

    // ---- __ieee_status ----

    #[test]
    fn ieee_status_stub_always_zero() {
        // The retailOS stub ignores op/bits and returns 0 (no fp status word).
        for op in [0u32, 1, 2, 3, 0xffff_ffff] {
            for bits in [0u32, 1, 0x1f, 0xffff_ffff] {
                assert_eq!(unsafe { __ieee_status(op, bits) }, 0);
            }
        }
    }

    // ---- trap handler dispatch ----

    static LAST_DESCRIPTOR: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn mock_fp_trap_handler(descriptor: u32, result: u64) -> u64 {
        LAST_DESCRIPTOR.store(descriptor, Ordering::SeqCst);
        // Substitute a recognizable sentinel for the canonical result.
        result ^ 0x5a5a_5a5a_5a5a_5a5a
    }

    #[test]
    fn trap_handler_receives_descriptor_and_substitutes() {
        let _guard = TRAP_TEST_LOCK.lock().unwrap();
        unsafe {
            FP_TRAP_HANDLER = mock_fp_trap_handler;

            let got = __dscalb(f64::NAN.to_bits(), 0);
            assert_eq!(LAST_DESCRIPTOR.load(Ordering::SeqCst), DSCALB_NAN_DESCRIPTOR);
            assert_eq!(got, DOUBLE_QNAN ^ 0x5a5a_5a5a_5a5a_5a5a);

            let got = __fscalb(f32::NAN.to_bits(), 0);
            assert_eq!(LAST_DESCRIPTOR.load(Ordering::SeqCst), FSCALB_NAN_DESCRIPTOR);
            assert_eq!(
                got,
                ((FLOAT_QNAN as u64) ^ 0x5a5a_5a5a_5a5a_5a5a) as u32
            );

            // Restoring the default brings back the canonical NaN behavior.
            FP_TRAP_HANDLER = default_fp_trap_handler;
            assert_eq!(__dscalb(f64::NAN.to_bits(), 0), DOUBLE_QNAN);
            assert_eq!(__fscalb(f32::NAN.to_bits(), 0), FLOAT_QNAN);
        }
    }
}
