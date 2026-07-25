//! Ports of the ARM ADS 1.0.1 libm sine/cosine wrappers:
//!
//! - `cos` — original: `FUN_080319a8` @ 0x080319a8 (244 bytes + 24-byte
//!   literal pool).
//! - `sin` — original: `FUN_08031d24` @ 0x08031d24 (260 bytes + 24-byte
//!   literal pool).
//!
//! ADDRESS NOTE (important): the labels in names.yaml are swapped — the
//! disassembly proves 0x080319a8 is `cos` and 0x08031d24 is `sin`:
//!
//! - 0x080319a8's small-|x| path tail-calls the kernel @ 0x0803375c, which
//!   returns 1.0 for x == 0 (constant 0x3ff00000_00000000 @ 0x080338dc) and
//!   uses the fdlibm `__kernel_cos` qx-truncation (threshold 0x3fd33333 @
//!   0x080338e8, qx = 0.28125 @ 0x080338f0) with a 6-coefficient `_dpoly`.
//! - 0x08031d24's small-|x| path calls the kernel @ 0x08033dc8, which
//!   returns x unchanged for x == 0, evaluates fdlibm's sine polynomial
//!   (S1 = 0xbfc55555_55555549 @ 0x08033f38, 5-coefficient `_dpoly` for
//!   S2..S6), and takes a third `iy` argument on the stack.
//!
//! Hence `__kernel_sin` = 0x08033dc8, `__kernel_cos` = 0x0803375c, and the
//! quadrant dispatch below matches fdlibm's s_sin.c / s_cos.c exactly.
//!
//! Algorithms (identical shape in both wrappers):
//! `ix = hi(x) & 0x7fffffff` (sign-masked high word; all compares signed,
//! which is equivalent since the sign bit is gone):
//! - `ix <= 0x3fe921fb` (|x| <= ~pi/4, high-word compare only): skip
//!   argument reduction entirely — `sin` returns `__kernel_sin(x, 0.0, 0)`,
//!   `cos` returns `__kernel_cos(x, 0.0)`.
//! - `ix == 0x7ff00000 && lo(x) == 0` (+-Inf): call the libm raise wrapper
//!   @ 0x08032178 with code 1 (it stores the code to `*__errno()` — ADS
//!   EDOM) and return the fixed quiet NaN 0x7ff80000_00000001.
//! - `ix >= 0x7ff00000` otherwise (any NaN): return `__dscalb(x, 1)`
//!   (0x083ed0dc, ported in fp/fp_scalb.rs) purely to propagate/quiet the
//!   NaN — the fdlibm `x - x` equivalent.
//! - else: `n = __kernel_rem_pio2(x, &y)` (0x080338f4 — takes only x and
//!   the y out-pointer; the r3 the wrappers happen to hold is dead) and
//!   dispatch on `n & 3`:
//!
//! ```text
//!   sin: 0 => +__kernel_sin(y0, y1, 1)   1 => +__kernel_cos(y0, y1)
//!        2 => -__kernel_sin(y0, y1, 1)   3 => -__kernel_cos(y0, y1)
//!   cos: 0 => +__kernel_cos(y0, y1)      1 => -__kernel_sin(y0, y1, 1)
//!        2 => -__kernel_cos(y0, y1)      3 => +__kernel_sin(y0, y1, 1)
//! ```
//!
//! (Negation is the original's `eor r1, r1, #0x80000000` — a sign-bit flip
//! of the result's high word.) Note the `iy = 1` stack argument goes to
//! `__kernel_sin` in the odd quadrants, not to `__kernel_cos`.
//!
//! Kernel-dispatch design (deviation, by necessity — mirrors the HEAP_OPS
//! pattern in runtime/malloc_rt.rs): `__kernel_sin`, `__kernel_cos` and
//! `__kernel_rem_pio2` are ported in sibling modules (libm/kernel_trig.rs,
//! libm/rem_pio2.rs) that this module may not import while the port is in
//! flight, so all three — plus the libm raise wrapper @ 0x08032178 — are
//! reached indirectly through the `TRIG_KERNELS` function-pointer table.
//! The table defaults to documented stubs: the kernels return the canonical
//! quiet NaN (they cannot produce a mathematically valid result out of
//! thin air; on real hardware the table must be installed before sin/cos
//! are called), `rem_pio2` writes y = {0.0, 0.0} and returns quadrant 0,
//! and `raise` is a no-op (an errno store with nowhere to go is
//! unobservable). Host tests swap in mock kernels.
//!
//! Simplifications:
//! - The raise wrapper is reduced to its observable contract (errno =
//!   code) and stubbed; see above.
//! - `__ieee_status`/trap side effects of the original soft-float helpers
//!   are whatever fp_scalb already models; the wrappers add none of their
//!   own.
//!
//! Symbol exports (`#[no_mangle]`) are disabled in `cfg(test)` builds:
//! `sin`/`cos` are exported by libSystem and dyld would interpose the host
//! test binary's symbols (same hazard as malloc/free in malloc_rt.rs).
//! ARM/release builds export the symbols normally for match.py and linking.

use crate::fp::fp_scalb::__dscalb;

/// High-word threshold for skipping argument reduction: |x| <= ~pi/4
/// (high word of pio4 = 0x3FE921FB54442D18; the original compares only the
/// sign-masked high word).
const PIO4_HI: u32 = 0x3fe9_21fb;

/// Biased-exponent-all-ones high word (Inf/NaN boundary).
const EXP_ALL_ONES_HI: u32 = 0x7ff0_0000;

/// Fixed quiet NaN returned after the domain-error raise on +-Inf input
/// (literal pool @ 0x08031ab0 / 0x08031e3c in osos).
const DOMAIN_QNAN: u64 = 0x7ff8_0000_0000_0001;

/// ADS EDOM — the code the wrappers pass to the libm raise wrapper
/// @ 0x08032178 (which stores it to `*__errno()`).
const EDOM: i32 = 1;

/// Indirect dispatch table for the concurrently-ported trig kernels (see
/// the module header for the design and the default-stub behavior).
#[derive(Clone, Copy)]
pub struct TrigKernels {
    /// `__kernel_sin` @ 0x08033dc8 — `fn(x: u64, y: u64, iy: i32) -> u64`.
    /// The original passes `iy` as a fifth argument on the stack; the Rust
    /// extern-"C" ABI does the same for a trailing i32 after two u64s.
    pub kernel_sin: unsafe extern "C" fn(x: u64, y: u64, iy: i32) -> u64,
    /// `__kernel_cos` @ 0x0803375c — `fn(x: u64, y: u64) -> u64`.
    pub kernel_cos: unsafe extern "C" fn(x: u64, y: u64) -> u64,
    /// `__kernel_rem_pio2` @ 0x080338f4 — `fn(x: u64, y: *mut u64) -> i32`.
    /// Writes the reduced argument as y[0] (hi part) and y[1] (tail),
    /// returns the quadrant count n (only `n & 3` is consumed here).
    pub rem_pio2: unsafe extern "C" fn(x: u64, y: *mut u64) -> i32,
    /// libm raise wrapper @ 0x08032178 — stores `code` to `*__errno()`
    /// (EDOM = 1 for the +-Inf domain error here) and returns void.
    pub raise: unsafe extern "C" fn(code: i32),
}

/// Default stub: the kernel is not installed — return the canonical quiet
/// NaN rather than a silently wrong number. On real hardware TRIG_KERNELS
/// must be installed before sin/cos are called.
unsafe extern "C" fn missing_kernel_sin(_x: u64, _y: u64, _iy: i32) -> u64 {
    0x7ff8_0000_0000_0000
}

/// Default stub: like `missing_kernel_sin`, cannot compute — canonical qNaN.
unsafe extern "C" fn missing_kernel_cos(_x: u64, _y: u64) -> u64 {
    0x7ff8_0000_0000_0000
}

/// Default stub: report a zero reduced argument in quadrant 0. Paired with
/// the kernel stubs above the result is the kernels' qNaN placeholder.
unsafe extern "C" fn missing_rem_pio2(_x: u64, y: *mut u64) -> i32 {
    *y = 0;
    *y.add(1) = 0;
    0
}

/// Default stub: an errno store with no errno runtime is unobservable —
/// harmless no-op (same rationale as `missing_free` in malloc_rt.rs).
unsafe extern "C" fn missing_raise(_code: i32) {}

/// The active trig kernel implementation. Defaults to the documented stubs
/// above; replaced by host tests (mock kernels) and eventually by the
/// ported kernels in libm/kernel_trig.rs / libm/rem_pio2.rs. Written once
/// at init on target; tests serialize access.
pub static mut TRIG_KERNELS: TrigKernels = TrigKernels {
    kernel_sin: missing_kernel_sin,
    kernel_cos: missing_kernel_cos,
    rem_pio2: missing_rem_pio2,
    raise: missing_raise,
};

/// Reads the ops table. The read is volatile: the table is meant to be
/// swapped at runtime (kernel installer, host tests), and in a build where
/// nothing writes it yet LLVM would otherwise constant-fold the loads to
/// the default stubs (observed in malloc_rt.rs: `malloc` collapsed to a
/// branch-to-self in the ARM release build).
#[inline(always)]
fn trig_kernels() -> TrigKernels {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRIG_KERNELS)) }
}

/// Sign-masked high word of a soft-float double bit pattern (the
/// original's `bic r0, r0, #0x80000000`).
#[inline(always)]
fn abs_hi(x: u64) -> u32 {
    ((x >> 32) as u32) & 0x7fff_ffff
}

/// The original's `eor r1, r1, #0x80000000`: negate by flipping the sign
/// bit of the high word.
#[inline(always)]
fn negate(bits: u64) -> u64 {
    bits ^ 0x8000_0000_0000_0000
}

/// sin — original: `FUN_08031d24` @ 0x08031d24 (260 bytes).
///
/// See the module header for the full algorithm and for why this address
/// (not 0x080319a8) is the sine wrapper.
// NOTE: `#[no_mangle]` is gated to non-test builds — see the module header.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sin(x: u64) -> u64 {
    let ix = abs_hi(x);
    if ix <= PIO4_HI {
        // |x| <= ~pi/4: no argument reduction.
        return (trig_kernels().kernel_sin)(x, 0, 0);
    }
    if ix == EXP_ALL_ONES_HI && x as u32 == 0 {
        // +-Inf: domain error, fixed quiet NaN.
        (trig_kernels().raise)(EDOM);
        return DOMAIN_QNAN;
    }
    if ix >= EXP_ALL_ONES_HI {
        // NaN: propagate/quiet via the soft-float scalb (fdlibm's `x - x`).
        return __dscalb(x, 1);
    }
    let ops = trig_kernels();
    let mut y: [u64; 2] = [0; 2];
    let n = (ops.rem_pio2)(x, y.as_mut_ptr());
    match n & 3 {
        0 => (ops.kernel_sin)(y[0], y[1], 1),
        1 => (ops.kernel_cos)(y[0], y[1]),
        2 => negate((ops.kernel_sin)(y[0], y[1], 1)),
        _ => negate((ops.kernel_cos)(y[0], y[1])),
    }
}

/// cos — original: `FUN_080319a8` @ 0x080319a8 (244 bytes).
///
/// See the module header for the full algorithm and for why this address
/// (not 0x08031d24) is the cosine wrapper.
// NOTE: `#[no_mangle]` is gated to non-test builds — see the module header.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn cos(x: u64) -> u64 {
    let ix = abs_hi(x);
    if ix <= PIO4_HI {
        // |x| <= ~pi/4: no argument reduction.
        return (trig_kernels().kernel_cos)(x, 0);
    }
    if ix == EXP_ALL_ONES_HI && x as u32 == 0 {
        // +-Inf: domain error, fixed quiet NaN.
        (trig_kernels().raise)(EDOM);
        return DOMAIN_QNAN;
    }
    if ix >= EXP_ALL_ONES_HI {
        // NaN: propagate/quiet via the soft-float scalb (fdlibm's `x - x`).
        return __dscalb(x, 1);
    }
    let ops = trig_kernels();
    let mut y: [u64; 2] = [0; 2];
    let n = (ops.rem_pio2)(x, y.as_mut_ptr());
    match n & 3 {
        0 => (ops.kernel_cos)(y[0], y[1]),
        1 => negate((ops.kernel_sin)(y[0], y[1], 1)),
        2 => negate((ops.kernel_cos)(y[0], y[1])),
        _ => (ops.kernel_sin)(y[0], y[1], 1),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    // Mock call log.
    static mut REM_CALLS: u32 = 0;
    static mut REM_X: u64 = 0;
    static mut REM_N: i32 = 0;
    static mut REM_Y0: u64 = 0;
    static mut REM_Y1: u64 = 0;
    static mut KSIN_CALLS: u32 = 0;
    static mut KSIN_X: u64 = 0;
    static mut KSIN_Y: u64 = 0;
    static mut KSIN_IY: i32 = 0;
    static mut KCOS_CALLS: u32 = 0;
    static mut KCOS_X: u64 = 0;
    static mut KCOS_Y: u64 = 0;
    static mut RAISE_CALLS: u32 = 0;
    static mut RAISE_CODE: i32 = 0;

    // Sentinel results: distinct per kernel so the dispatch target is
    // identifiable from the return value alone.
    const KSIN_RET: u64 = 1.0f64.to_bits();
    const KCOS_RET: u64 = 2.0f64.to_bits();

    unsafe extern "C" fn mock_rem_pio2(x: u64, y: *mut u64) -> i32 {
        REM_CALLS += 1;
        REM_X = x;
        *y = REM_Y0;
        *y.add(1) = REM_Y1;
        REM_N
    }

    unsafe extern "C" fn mock_kernel_sin(x: u64, y: u64, iy: i32) -> u64 {
        KSIN_CALLS += 1;
        KSIN_X = x;
        KSIN_Y = y;
        KSIN_IY = iy;
        KSIN_RET
    }

    unsafe extern "C" fn mock_kernel_cos(x: u64, y: u64) -> u64 {
        KCOS_CALLS += 1;
        KCOS_X = x;
        KCOS_Y = y;
        KCOS_RET
    }

    unsafe extern "C" fn mock_raise(code: i32) {
        RAISE_CALLS += 1;
        RAISE_CODE = code;
    }

    const MOCK_KERNELS: TrigKernels = TrigKernels {
        kernel_sin: mock_kernel_sin,
        kernel_cos: mock_kernel_cos,
        rem_pio2: mock_rem_pio2,
        raise: mock_raise,
    };

    /// Resets the mock log, installs the mock table, returns the lock guard.
    /// `n` is the quadrant the mock rem_pio2 reports.
    fn mock_kernels(n: i32) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        unsafe {
            REM_CALLS = 0;
            REM_X = 0;
            REM_N = n;
            REM_Y0 = 0.25f64.to_bits();
            REM_Y1 = 0.5f64.to_bits();
            KSIN_CALLS = 0;
            KSIN_X = 0;
            KSIN_Y = 0;
            KSIN_IY = -1;
            KCOS_CALLS = 0;
            KCOS_X = 0;
            KCOS_Y = 0;
            RAISE_CALLS = 0;
            RAISE_CODE = 0;
            *core::ptr::addr_of_mut!(TRIG_KERNELS) = MOCK_KERNELS;
        }
        guard
    }

    /// A "large" argument that always takes the rem_pio2 path.
    const BIG: u64 = 100.0f64.to_bits();

    #[test]
    fn sin_small_arg_skips_rem_pio2() {
        let _lock = mock_kernels(0);
        unsafe {
            let r = sin(0.5f64.to_bits());
            assert_eq!(r, KSIN_RET);
            assert_eq!(KSIN_CALLS, 1, "small sin must call __kernel_sin");
            assert_eq!(KSIN_X, 0.5f64.to_bits());
            assert_eq!(KSIN_Y, 0, "small sin passes y = +0.0");
            assert_eq!(KSIN_IY, 0, "small sin passes iy = 0");
            assert_eq!(KCOS_CALLS, 0);
            assert_eq!(REM_CALLS, 0, "small sin must skip rem_pio2");
            assert_eq!(RAISE_CALLS, 0);
        }
    }

    #[test]
    fn cos_small_arg_skips_rem_pio2() {
        let _lock = mock_kernels(0);
        unsafe {
            let r = cos(0.5f64.to_bits());
            assert_eq!(r, KCOS_RET);
            assert_eq!(KCOS_CALLS, 1, "small cos must call __kernel_cos");
            assert_eq!(KCOS_X, 0.5f64.to_bits());
            assert_eq!(KCOS_Y, 0, "small cos passes y = +0.0");
            assert_eq!(KSIN_CALLS, 0);
            assert_eq!(REM_CALLS, 0, "small cos must skip rem_pio2");
            assert_eq!(RAISE_CALLS, 0);
        }
    }

    #[test]
    fn threshold_is_high_word_of_pio4() {
        let _lock = mock_kernels(0);
        unsafe {
            // hi word exactly 0x3fe921fb (a hair under pi/4): small path.
            let under = ((PIO4_HI as u64) << 32) | 0x54442d18;
            sin(under);
            assert_eq!(REM_CALLS, 0, "ix == 0x3fe921fb must stay small");
            // hi word one ulp higher: reduction path.
            let over = ((PIO4_HI as u64 + 1) << 32) | 0x54442d18;
            sin(over);
            assert_eq!(REM_CALLS, 1, "ix == 0x3fe921fc must reduce");
            // Same for cos.
            cos(under);
            assert_eq!(REM_CALLS, 1, "cos: ix == 0x3fe921fb must stay small");
            cos(over);
            assert_eq!(REM_CALLS, 2, "cos: ix == 0x3fe921fc must reduce");
            // Negative small argument: sign bit must be masked off.
            let neg = under | (1u64 << 63);
            sin(neg);
            assert_eq!(REM_CALLS, 2, "sign bit must not affect the threshold");
            assert_eq!(KSIN_X, neg, "kernel receives x with its sign");
        }
    }

    #[test]
    fn rem_pio2_gets_x_and_kernels_get_y() {
        let _lock = mock_kernels(0);
        unsafe {
            sin(BIG);
            assert_eq!(REM_CALLS, 1);
            assert_eq!(REM_X, BIG, "rem_pio2 receives the original x");
            assert_eq!(KSIN_CALLS, 1);
            assert_eq!(KSIN_X, REM_Y0, "kernel x argument is y[0]");
            assert_eq!(KSIN_Y, REM_Y1, "kernel y argument is y[1]");
            assert_eq!(KSIN_IY, 1, "quadrant path passes iy = 1");
        }
    }

    #[test]
    fn sin_quadrant_dispatch() {
        // (n, kernel, negated) per fdlibm s_sin.c: 0:+sin 1:+cos 2:-sin 3:-cos
        for (n, want_ret, want_ksin, want_kcos) in [
            (0, KSIN_RET, 1, 0),
            (1, KCOS_RET, 0, 1),
            (2, negate(KSIN_RET), 1, 0),
            (3, negate(KCOS_RET), 0, 1),
        ] {
            let _lock = mock_kernels(n);
            unsafe {
                let r = sin(BIG);
                assert_eq!(r, want_ret, "sin quadrant {n}");
                assert_eq!(KSIN_CALLS, want_ksin, "sin quadrant {n} ksin calls");
                assert_eq!(KCOS_CALLS, want_kcos, "sin quadrant {n} kcos calls");
                assert_eq!(REM_CALLS, 1);
                assert_eq!(RAISE_CALLS, 0);
            }
        }
    }

    #[test]
    fn cos_quadrant_dispatch() {
        // (n, kernel, negated) per fdlibm s_cos.c: 0:+cos 1:-sin 2:-cos 3:+sin
        for (n, want_ret, want_ksin, want_kcos) in [
            (0, KCOS_RET, 0, 1),
            (1, negate(KSIN_RET), 1, 0),
            (2, negate(KCOS_RET), 0, 1),
            (3, KSIN_RET, 1, 0),
        ] {
            let _lock = mock_kernels(n);
            unsafe {
                let r = cos(BIG);
                assert_eq!(r, want_ret, "cos quadrant {n}");
                assert_eq!(KSIN_CALLS, want_ksin, "cos quadrant {n} ksin calls");
                assert_eq!(KCOS_CALLS, want_kcos, "cos quadrant {n} kcos calls");
                assert_eq!(REM_CALLS, 1);
                assert_eq!(RAISE_CALLS, 0);
            }
        }
    }

    #[test]
    fn quadrant_is_masked_with_3() {
        let _lock = mock_kernels(0);
        unsafe {
            // n = 6 behaves like n = 2 for sin: -__kernel_sin.
            REM_N = 6;
            let r = sin(BIG);
            assert_eq!(r, negate(KSIN_RET), "n=6 must mask to quadrant 2");
            // n = -1: ARM `ands r0, r0, #3` on two's complement gives 3.
            REM_N = -1;
            let r = cos(BIG);
            assert_eq!(r, KSIN_RET, "n=-1 must mask to quadrant 3 (+sin)");
            assert_eq!(KSIN_CALLS, 2, "both masked calls hit __kernel_sin");
            assert_eq!(KCOS_CALLS, 0);
        }
    }

    #[test]
    fn inf_raises_domain_error_and_returns_fixed_qnan() {
        let _lock = mock_kernels(0);
        unsafe {
            for x in [f64::INFINITY.to_bits(), f64::NEG_INFINITY.to_bits()] {
                RAISE_CALLS = 0;
                let rs = sin(x);
                assert_eq!(rs, DOMAIN_QNAN, "sin(+-Inf) returns the pool qNaN");
                assert_eq!(RAISE_CALLS, 1, "sin(+-Inf) raises EDOM");
                assert_eq!(RAISE_CODE, EDOM);
                let rc = cos(x);
                assert_eq!(rc, DOMAIN_QNAN, "cos(+-Inf) returns the pool qNaN");
                assert_eq!(RAISE_CALLS, 2, "cos(+-Inf) raises EDOM");
                assert_eq!(RAISE_CODE, EDOM);
            }
            assert_eq!(REM_CALLS, 0, "Inf must skip rem_pio2");
            assert_eq!(KSIN_CALLS, 0);
            assert_eq!(KCOS_CALLS, 0);
        }
    }

    #[test]
    fn nan_propagates_via_dscalb_without_raise() {
        let _lock = mock_kernels(0);
        unsafe {
            // Canonical qNaN and a payload NaN with hi == 0x7ff00000 (the
            // Inf-high-word + nonzero-low path of the original's compare).
            for x in [
                f64::NAN.to_bits(),
                0x7ff0_0000_0000_0001u64,
                0xfff8_0000_1234_5678u64,
            ] {
                let rs = sin(x);
                assert!(f64::from_bits(rs).is_nan(), "sin(NaN) must be NaN");
                let rc = cos(x);
                assert!(f64::from_bits(rc).is_nan(), "cos(NaN) must be NaN");
            }
            assert_eq!(RAISE_CALLS, 0, "NaN is not a domain error here");
            assert_eq!(REM_CALLS, 0, "NaN must skip rem_pio2");
            assert_eq!(KSIN_CALLS, 0);
            assert_eq!(KCOS_CALLS, 0);
        }
    }

    #[test]
    fn negative_large_arg_dispatches_normally() {
        let _lock = mock_kernels(1);
        unsafe {
            let r = sin(negate(BIG));
            assert_eq!(REM_CALLS, 1, "negative large x still reduces");
            assert_eq!(REM_X, negate(BIG), "rem_pio2 sees the signed x");
            assert_eq!(r, KCOS_RET, "quadrant 1: +__kernel_cos");
        }
    }

    #[test]
    fn default_stubs_are_documented_placeholders() {
        let _lock = OPS_LOCK.lock().unwrap();
        unsafe {
            *core::ptr::addr_of_mut!(TRIG_KERNELS) = TrigKernels {
                kernel_sin: missing_kernel_sin,
                kernel_cos: missing_kernel_cos,
                rem_pio2: missing_rem_pio2,
                raise: missing_raise,
            };
            // Small path: kernel stub qNaN. Large path: rem stub reduces to
            // y = 0, quadrant 0 -> kernel stub qNaN. Neither hangs.
            assert!(f64::from_bits(sin(0.5f64.to_bits())).is_nan());
            assert!(f64::from_bits(cos(BIG)).is_nan());
            // Inf: no-op raise + fixed qNaN.
            assert_eq!(sin(f64::INFINITY.to_bits()), DOMAIN_QNAN);
        }
    }
}
