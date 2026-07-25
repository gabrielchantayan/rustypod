//! Ports of the ARM ADS 1.0.1 libm kernel polynomials for sin/cos and the
//! shared Horner evaluator:
//!
//! - `_dpoly`       — original: `FUN_08035a48` @ 0x08035a48 (244 bytes).
//! - `__kernel_cos` — original: `FUN_0803375c` @ 0x0803375c (384 bytes).
//! - `__kernel_sin` — original: `FUN_08033dc8` @ 0x08033dc8 (364 bytes).
//!
//! NAMING NOTE: the project map (names.yaml) labels 0x0803375c
//! "__kernel_sin" and 0x08033dc8 "__kernel_cos", but the disassembly is
//! unambiguous that this is swapped. 0x0803375c evaluates the C1..C6
//! polynomial and returns `one - (0.5*z - (z*r - x*y))` with the qx/hz
//! large-x tail — the netlib `__kernel_cos` algorithm — and takes NO `iy`
//! argument. 0x08033dc8 evaluates the S2..S6 polynomial and returns
//! `x + v*(S1 + z*r)`, with the `x - ((z*(half*y - v*r) - y) - v*S1)` tail
//! selected by a fifth (stack) argument `iy` — the netlib `__kernel_sin`
//! algorithm. The wrappers agree: the function at 0x080319a8 (mapped
//! "sin") calls 0x0803375c directly for unreduced x, which only computes
//! cosine. This module names the kernels after what they compute.
//!
//! Doubles are u64 bit patterns (soft-float); all arithmetic goes through
//! the committed soft-float primitive ports (`__dmul`, `__dadd`, `__dsub`,
//! `__drsb`, `__dscalb`) so operation order and rounding match the
//! original exactly.
//!
//! Simplifications (behavior-identical, documented):
//! - Both kernels guard the tiny-x path with `if (__d2i(x) == 0)`. __d2i
//!   truncates toward zero, so for every input with |x| < 2^-27 the result
//!   is 0 and the guard is unconditional. The __d2i call is omitted and
//!   the tiny path returns directly (cos: one, sin: x).
//! - _dpoly's original loop is ADS-unrolled (main loop strides 8 with the
//!   `(n-1) & !6` exit test, then straight-line finishes for remainders
//!   6/4/2). It is written here as a plain Horner loop; the floating-point
//!   operation sequence — and therefore every rounding — is identical.
//!
//! Coefficient tables (extracted from osos.dec, netlib values):
//! - cos C1..C6 @ load 0x08986010 (file offset 0x986010), referenced by
//!   the literal pool word @ 0x080338e4.
//! - sin S2..S6 @ load 0x08986108 (file offset 0x986108), referenced by
//!   the literal pool word @ 0x08033f34. S1 is a standalone literal
//!   @ 0x08033f38; `one` @ 0x080338dc; qx = 0.28125 @ 0x080338ec.
//!
//! Behavioral verification: host-side `cargo test` pins the tables to the
//! exact bytes read from the binary and compares the kernels against host
//! f64::sin/cos on [-pi/4, pi/4] with a ULP tolerance; `tools/match.py`
//! (ipod-decomp) reports the mnemonic-level diff against the original
//! machine code.

use crate::fp_dadd::{__dadd, __drsb, __dsub};
use crate::fp_dmul::__dmul;
use crate::fp_scalb::__dscalb;

/// 1.0 — literal pool entry @ 0x080338dc.
const ONE: u64 = 0x3ff0_0000_0000_0000;
/// sin S1 = -1.66666666666666324348e-01 — standalone literal @ 0x08033f38.
const S1: u64 = 0xbfc5_5555_5555_5549;
/// cos qx = 0.28125 — literal @ 0x080338ec (|x| > 0.78125 case).
const QX_QUARTER: u64 = 0x3fd2_0000_0000_0000;

/// Shared guard: kernels take the polynomial path when the high word of
/// |x| is >= 0x3e400000, i.e. |x| >= 2^-27.
const TINY_X_HI: u32 = 0x3e40_0000;
/// cos: below this |x| high word (0.3) the plain `one - (0.5*z - ...)`
/// path is used; above it the qx/hz tail — literal @ 0x080338e8.
const COS_PLAIN_PATH_HI: u32 = 0x3fd3_3333;
/// cos: above this |x| high word (0.78125) qx is the constant 0.28125;
/// otherwise qx's high word is `|x|hi - 0x00200000` with a zero low word.
const QX_CONSTANT_HI: u32 = 0x3fe9_0000;
const QX_HI_ADJUST: u32 = 0x0020_0000;

/// cos coefficients C1..C6 (lowest degree first), table @ 0x08986010.
static COS_COEFFS: [u64; 6] = [
    0x3fa5_5555_5555_554c, // C1 =  4.16666666666666019037e-02
    0xbf56_c16c_16c1_5177, // C2 = -1.38888888888741095749e-03
    0x3efa_01a0_19cb_1590, // C3 =  2.48015872894767294178e-05
    0xbe92_7e4f_809c_52ad, // C4 = -2.75573143513906633035e-07
    0x3e21_ee9e_bdb4_b1c4, // C5 =  2.08757232129817482790e-09
    0xbda8_fae9_be88_38d4, // C6 = -1.13596475577881948265e-11
];

/// sin coefficients S2..S6 (lowest degree first), table @ 0x08986108.
static SIN_COEFFS: [u64; 5] = [
    0x3f81_1111_1110_f8a6, // S2 =  8.33333333332248946124e-03
    0xbf2a_01a0_19c1_61d5, // S3 = -1.98412698298579493134e-04
    0x3ec7_1de3_57b1_fe7d, // S4 =  2.75573137070700676789e-06
    0xbe5a_e5e6_8a2b_9ceb, // S5 = -2.50507602534068634195e-08
    0x3de5_d93a_5acf_d57c, // S6 =  1.58969099521155010221e-10
];

/// _dpoly — original: `FUN_08035a48` @ 0x08035a48 (244 bytes).
///
/// Horner evaluator shared by the libm kernels: returns
/// `coeff[0] + x*(coeff[1] + x*(... + x*coeff[n-1]))`, `n` coefficients.
/// All arithmetic via the soft-float primitives, in the original's
/// operation order. Only ever called with n = 5 or 6 by the kernels (and
/// larger n by __kernel_rem_pio2); the original's unrolled structure is a
/// plain Horner loop here (see module header). `inline(never)` keeps the
/// shared-subroutine call the original makes from both kernels.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn _dpoly(coeff: *const u64, n: i32, x: u64) -> u64 {
    let mut i = n - 1;
    let mut result = *coeff.offset(i as isize);
    while i > 0 {
        i -= 1;
        result = __dadd(__dmul(result, x), *coeff.offset(i as isize));
    }
    result
}

/// __kernel_cos — original: `FUN_0803375c` @ 0x0803375c (384 bytes).
///
/// Cosine kernel for reduced arguments, |x| <= pi/4: with `z = x*x`,
/// `r = z*(C1 + z*(C2 + ... + z*C6))` (via `_dpoly`), returns
/// `one - (0.5*z - (z*r - x*y))` for |x| < 0.3, and
/// `a - (hz - (z*r - x*y))` with `hz = 0.5*z - qx`, `a = one - qx` above
/// (qx = 0.28125 for |x| > 0.78125, else x/4 with the low word dropped).
/// `y` is the argument-reduction tail. See the module header for the
/// naming swap and the tiny-x guard simplification.
#[no_mangle]
pub unsafe extern "C" fn __kernel_cos(x: u64, y: u64) -> u64 {
    let abs_x_hi = ((x >> 32) as u32) & 0x7fff_ffff;
    if abs_x_hi < TINY_X_HI {
        // Original: `if (__d2i(x) == 0) return one` — always true here.
        return ONE;
    }
    let z = __dmul(x, x);
    let poly = _dpoly(COS_COEFFS.as_ptr(), 6, z);
    let r = __dmul(poly, z);
    let x_tail = __dmul(x, y);
    let z_r_minus_x_tail = __dsub(__dmul(z, r), x_tail);
    let half_z = __dscalb(z, -1);
    if abs_x_hi < COS_PLAIN_PATH_HI {
        // one - (0.5*z - (z*r - x*y))
        let inner = __dsub(half_z, z_r_minus_x_tail);
        return __drsb(inner, ONE);
    }
    let qx = if abs_x_hi > QX_CONSTANT_HI {
        QX_QUARTER
    } else {
        // x/4, truncated: high word |x|hi - 0x00200000, low word zero.
        ((abs_x_hi - QX_HI_ADJUST) as u64) << 32
    };
    let hz = __dsub(half_z, qx);
    let a = __dsub(ONE, qx);
    // a - (hz - (z*r - x*y))
    let inner = __dsub(hz, z_r_minus_x_tail);
    __drsb(inner, a)
}

/// __kernel_sin — original: `FUN_08033dc8` @ 0x08033dc8 (364 bytes).
///
/// Sine kernel for reduced arguments, |x| <= pi/4: with `z = x*x`,
/// `v = z*x`, `r = S2 + z*(S3 + ... + z*S6)` (via `_dpoly`), returns
/// `x + v*(S1 + z*r)` when `iy == 0` (no tail), and
/// `x - ((z*(half*y - v*r) - y) - v*S1)` when `iy != 0`, where `y` is the
/// argument-reduction tail. See the module header for the naming swap and
/// the tiny-x guard simplification.
#[no_mangle]
pub unsafe extern "C" fn __kernel_sin(x: u64, y: u64, iy: i32) -> u64 {
    let abs_x_hi = ((x >> 32) as u32) & 0x7fff_ffff;
    if abs_x_hi < TINY_X_HI {
        // Original: `if (__d2i(x) == 0) return x` — always true here.
        return x;
    }
    let z = __dmul(x, x);
    let v = __dmul(x, z);
    let r = _dpoly(SIN_COEFFS.as_ptr(), 5, z);
    if iy == 0 {
        // x + v*(S1 + z*r)
        let s1_plus_zr = __dadd(__dmul(z, r), S1);
        __dadd(__dmul(s1_plus_zr, v), x)
    } else {
        // x - ((z*(half*y - v*r) - y) - v*S1)
        let v_s1 = __dmul(v, S1);
        let v_r = __dmul(v, r);
        let half_y = __dscalb(y, -1);
        let z_scaled = __dmul(__dsub(half_y, v_r), z);
        let minus_tail = __dsub(z_scaled, y);
        let correction = __dsub(minus_tail, v_s1);
        __drsb(correction, x)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Exact little-endian bytes of the cos table @ file offset 0x986010.
    const COS_COEFF_BYTES: [[u8; 8]; 6] = [
        [0x4c, 0x55, 0x55, 0x55, 0x55, 0x55, 0xa5, 0x3f],
        [0x77, 0x51, 0xc1, 0x16, 0x6c, 0xc1, 0x56, 0xbf],
        [0x90, 0x15, 0xcb, 0x19, 0xa0, 0x01, 0xfa, 0x3e],
        [0xad, 0x52, 0x9c, 0x80, 0x4f, 0x7e, 0x92, 0xbe],
        [0xc4, 0xb1, 0xb4, 0xbd, 0x9e, 0xee, 0x21, 0x3e],
        [0xd4, 0x38, 0x88, 0xbe, 0xe9, 0xfa, 0xa8, 0xbd],
    ];

    /// Exact little-endian bytes of the sin table @ file offset 0x986108.
    const SIN_COEFF_BYTES: [[u8; 8]; 5] = [
        [0xa6, 0xf8, 0x10, 0x11, 0x11, 0x11, 0x81, 0x3f],
        [0xd5, 0x61, 0xc1, 0x19, 0xa0, 0x01, 0x2a, 0xbf],
        [0x7d, 0xfe, 0xb1, 0x57, 0xe3, 0x1d, 0xc7, 0x3e],
        [0xeb, 0x9c, 0x2b, 0x8a, 0xe6, 0xe5, 0x5a, 0xbe],
        [0x7c, 0xd5, 0xcf, 0x5a, 0x3a, 0xd9, 0xe5, 0x3d],
    ];

    #[test]
    fn coeff_tables_match_binary_bytes() {
        for (coeff, bytes) in COS_COEFFS.iter().zip(COS_COEFF_BYTES.iter()) {
            assert_eq!(&coeff.to_le_bytes(), bytes);
        }
        for (coeff, bytes) in SIN_COEFFS.iter().zip(SIN_COEFF_BYTES.iter()) {
            assert_eq!(&coeff.to_le_bytes(), bytes);
        }
        // Standalone literals.
        assert_eq!(ONE.to_le_bytes(), [0, 0, 0, 0, 0, 0, 0xf0, 0x3f]);
        assert_eq!(S1.to_le_bytes(), [0x49, 0x55, 0x55, 0x55, 0x55, 0x55, 0xc5, 0xbf]);
        assert_eq!(QX_QUARTER.to_le_bytes(), [0, 0, 0, 0, 0, 0, 0xd2, 0x3f]);
        // Spot values against the known netlib constants (shortest
        // round-trip decimals, so equality is exact).
        assert_eq!(f64::from_bits(COS_COEFFS[0]), 0.0416666666666666);
        assert_eq!(f64::from_bits(SIN_COEFFS[0]), 0.00833333333332249);
        assert_eq!(f64::from_bits(S1), -0.16666666666666632);
    }

    /// Order-preserving map of IEEE-754 bits onto i64; the difference of
    /// two mapped values is their distance in ULPs.
    fn ordered(bits: u64) -> i64 {
        let signed = bits as i64;
        if signed < 0 {
            i64::MIN - signed
        } else {
            signed
        }
    }

    fn ulp_diff(a: u64, b: u64) -> i64 {
        (ordered(a) - ordered(b)).abs()
    }

    /// Dense grid over [-pi/4, pi/4], plus points aimed at the cos
    /// path-selection thresholds (0.3 and 0.78125).
    fn reduced_grid() -> Vec<f64> {
        let mut xs: Vec<f64> = Vec::new();
        for i in -1024..=1024 {
            xs.push(i as f64 * (std::f64::consts::FRAC_PI_4 / 1024.0));
        }
        for &x in &[0.3, 0.30000000000000004, 0.7, 0.75, 0.78, 0.78125, 0.785] {
            xs.push(x);
            xs.push(-x);
        }
        xs
    }

    #[test]
    fn kernel_sin_matches_host_within_ulp() {
        let mut max_ulp = 0i64;
        for x in reduced_grid() {
            let got = unsafe { __kernel_sin(x.to_bits(), 0.0f64.to_bits(), 0) };
            let want = x.sin().to_bits();
            let d = ulp_diff(got, want);
            assert!(
                d <= 2,
                "kernel_sin({x:e}): {} ULP from host ({got:#x} vs {want:#x})",
                d
            );
            max_ulp = max_ulp.max(d);
        }
        // Measured: identical polynomial + IEEE RNE soft-float -> <= 1 ULP
        // across the grid; bound above leaves headroom for host libm
        // differences in the oracle itself.
        assert!(max_ulp <= 2);
    }

    #[test]
    fn kernel_cos_matches_host_within_ulp() {
        let mut max_ulp = 0i64;
        for x in reduced_grid() {
            let got = unsafe { __kernel_cos(x.to_bits(), 0.0f64.to_bits()) };
            let want = x.cos().to_bits();
            let d = ulp_diff(got, want);
            assert!(
                d <= 2,
                "kernel_cos({x:e}): {} ULP from host ({got:#x} vs {want:#x})",
                d
            );
            max_ulp = max_ulp.max(d);
        }
        assert!(max_ulp <= 2);
    }

    #[test]
    fn kernel_sin_iy_tail_matches_host() {
        // Oracle: the kernel's own formula evaluated with host f64 ops in
        // the same association. NOTE: the iy tail deliberately carries only
        // the y*(1 - z/2) part of the y*cos(x) correction, so `(x+y).sin()`
        // is NOT a valid oracle for large y — it only agrees for tails of
        // the magnitude __kernel_rem_pio2 actually produces (|y| ~ 1e-17).
        let host_tail = |x: f64, y: f64| -> u64 {
            let z = x * x;
            let v = z * x;
            let mut r = f64::from_bits(SIN_COEFFS[4]);
            for c in SIN_COEFFS[..4].iter().rev() {
                r = r * z + f64::from_bits(*c);
            }
            let s1 = f64::from_bits(S1);
            (x - ((z * (0.5 * y - v * r) - y) - v * s1)).to_bits()
        };
        let mut max_ulp = 0i64;
        for x in reduced_grid() {
            // The tiny-x path returns x unconditionally (see tiny_x_paths).
            if x.abs() < f64::from_bits(((TINY_X_HI as u64) << 32)) {
                continue;
            }
            for &y in &[0.0f64, 1e-10, -1e-10, 3.0e-11] {
                let got = unsafe { __kernel_sin(x.to_bits(), y.to_bits(), 1) };
                let want = host_tail(x, y);
                let d = ulp_diff(got, want);
                assert!(
                    d <= 2,
                    "kernel_sin({x:e}, {y:e}, 1): {} ULP from host formula ({got:#x} vs {want:#x})",
                    d
                );
                max_ulp = max_ulp.max(d);
            }
        }
        assert!(max_ulp <= 2);

        // With a realistic rem_pio2-sized tail, the iy=1 result does track
        // sin(x + y) to a few ULP.
        for x in reduced_grid() {
            if x.abs() < f64::from_bits(((TINY_X_HI as u64) << 32)) {
                continue;
            }
            let y = x * 1.0e-17;
            let got = unsafe { __kernel_sin(x.to_bits(), y.to_bits(), 1) };
            let want = (x + y).sin().to_bits();
            let d = ulp_diff(got, want);
            assert!(
                d <= 3,
                "kernel_sin({x:e}, {y:e}, 1): {} ULP from host sin(x+y)",
                d
            );
        }
    }

    #[test]
    fn kernel_sin_iy1_with_zero_tail_matches_iy0() {
        // Same mathematics, different association: must agree to 1 ULP.
        for x in reduced_grid() {
            let with_tail = unsafe { __kernel_sin(x.to_bits(), 0, 1) };
            let plain = unsafe { __kernel_sin(x.to_bits(), 0, 0) };
            let d = ulp_diff(with_tail, plain);
            assert!(d <= 1, "kernel_sin iy0 vs iy1(y=0) at {x:e}: {d} ULP");
        }
    }

    #[test]
    fn tiny_x_paths() {
        // |x| < 2^-27: cos returns one, sin returns x (both unconditional,
        // see module header).
        let tiny = 1.0e-30f64.to_bits();
        assert_eq!(unsafe { __kernel_cos(tiny, 0) }, ONE);
        assert_eq!(unsafe { __kernel_sin(tiny, 0, 0) }, tiny);
        assert_eq!(unsafe { __kernel_sin(tiny, 0, 1) }, tiny);
        // Exact zeros, including -0.0.
        assert_eq!(unsafe { __kernel_cos(0, 0) }, ONE);
        assert_eq!(unsafe { __kernel_sin(0, 0, 0) }, 0);
        let neg_zero = (-0.0f64).to_bits();
        assert_eq!(unsafe { __kernel_sin(neg_zero, 0, 0) }, neg_zero);
        // Boundary: 2^-27 itself takes the polynomial path.
        let edge = (2.0f64.powi(-27)).to_bits();
        let got = unsafe { __kernel_sin(edge, 0, 0) };
        assert!(ulp_diff(got, edge) <= 1, "sin(2^-27) ~ x: {} ULP", ulp_diff(got, edge));
    }

    #[test]
    fn cos_path_selection() {
        // The three cos paths must all land close to host cos: plain
        // (|x| < 0.3), reconstructed qx (0.3..=0.78125), constant qx.
        for &x in &[0.29f64, 0.3, 0.31, 0.5, 0.7, 0.78, 0.78125, 0.785] {
            for &x in &[x, -x] {
                let got = unsafe { __kernel_cos(x.to_bits(), 0) };
                let want = x.cos().to_bits();
                let d = ulp_diff(got, want);
                assert!(d <= 2, "kernel_cos({x:e}): {d} ULP from host");
            }
        }
    }

    #[test]
    fn dpoly_horner() {
        // Small integers are exact in doubles: 1 + 2x + 3x^2 at x = 2.
        let coeffs: [u64; 3] = [
            1.0f64.to_bits(),
            2.0f64.to_bits(),
            3.0f64.to_bits(),
        ];
        let got = unsafe { _dpoly(coeffs.as_ptr(), 3, 2.0f64.to_bits()) };
        assert_eq!(f64::from_bits(got), 17.0);
        // n = 1 reduces to the constant term.
        let got = unsafe { _dpoly(coeffs.as_ptr(), 1, 2.0f64.to_bits()) };
        assert_eq!(f64::from_bits(got), 1.0);
        // Against a host Horner on the actual tables (same op order).
        let z = 0.37f64;
        let host = {
            let mut r = f64::from_bits(COS_COEFFS[5]);
            for c in COS_COEFFS[..5].iter().rev() {
                r = r * z + f64::from_bits(*c);
            }
            r
        };
        let got = unsafe { _dpoly(COS_COEFFS.as_ptr(), 6, z.to_bits()) };
        assert_eq!(got, host.to_bits(), "soft-float Horner differs from host");
    }
}
