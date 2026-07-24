//! Port of the scanf/strtod float back-end: the decimal-digits -> double
//! converter the `%e`/`%f`/`%g` engine calls after it has collected the
//! digit strings (ARM ADS 1.0.1 soft-float; doubles are u64 bit patterns,
//! no hardware FP).
//!
//! Port:
//! - `scanf_float_convert` — original: `FUN_08036018` @ 0x08036018
//!   (816 bytes). Called by the float input engine as
//!   `f(out, exp_digits, mant_digits, frac_adjust)` (call site
//!   0x080366ec: r0 = out, r1 = exponent buffer, r2 = mantissa buffer,
//!   r3 = fraction adjust). Both digit buffers hold *digit values* 0-9
//!   terminated by a 0xff byte (the engine has already subtracted '0');
//!   the mantissa buffer starts with an ASCII sign byte ('+'/'-'), the
//!   exponent buffer starts with a sign byte only when non-empty.
//!   Algorithm: parse the exponent string into a 32-bit int (negated if
//!   the sign byte is '-'), parse the mantissa string into a 64-bit
//!   unsigned integer with wrapping 10*x+d accumulation, add
//!   `frac_adjust` (=- number of fraction digits) to the exponent.
//!   Zero mantissa stores signed zero and returns. Exponent < -500
//!   stores signed zero and sets errno = ERANGE (2); exponent > 500
//!   stores signed infinity and sets ERANGE. Otherwise 10^|exp| is
//!   built as a 12-byte extended-float {exp_word, hi, lo}
//!   (FUN_08034228), the mantissa is normalized into the same format
//!   (biased exponent word 0x4000003e, then binary normalization shifts
//!   of 32/16/8/4/2/1), and one extended multiply (FUN_08037534,
//!   exp > 0) or divide (FUN_080374d4, exp <= 0) rounds the product to
//!   a double. The sign is XORed into the high word; a non-zero result
//!   whose exponent field is all ones is replaced by the canonical
//!   signed infinity (constant double @ 0x089d4f74) with errno = ERANGE.
//!   The result is stored lo-word-first, mirroring the store helper
//!   FUN_08036d70 (`str lo,[r0]; str hi,[r0,#4]`).
//!
//! The engine prologue @ 0x08036348 was checked and LEFT UNPORTED: it is
//! not a small veneer but the complete float input engine (~1052 bytes,
//! 0x08036348-0x08036763) — whitespace skip via ctype, width-limited
//! sign/digit/'.'/exponent collection into the two 0xff-terminated
//! buffers, inf/nan literal matching — which scanf_helpers.rs reserves
//! for the engine batch (it is the `SCANF_ENGINE` target). inf/nan
//! *input* handling therefore lives there, not here; this converter only
//! *produces* infinities on overflow.
//!
//! Soft-float dispatch design (deviation, by necessity): the extended
//! 10^n builder and the extended multiply/divide + round primitives are
//! not yet ported, and the errno accessor (FUN_0802ecb4, the `__errno`
//! veneer) is in a module this batch may not import, so all four route
//! through the `SOFTFLOAT_OPS` function-pointer table (mirroring the
//! HEAP_OPS pattern in malloc_rt.rs). The table defaults to documented
//! stubs: pow10/ext_mul/ext_div spin forever (they cannot fabricate
//! soft-float math; on real hardware the table must be installed before
//! a float conversion runs), set_errno is a harmless no-op. Host tests
//! swap in a mock built on host f64 math. The ops keep the original
//! register-level contracts, except that ext_mul/ext_div return the
//! double as one u64 of bits (hi word in bits 63..32) where the
//! originals returned hi in r0 / lo in r1 — the eventual real
//! implementations adapt at their own boundaries.
//!
//! Simplifications vs. the original:
//! - The originals' 3rd argument to pow10/ext_mul/ext_div (a rounding
//!   adjust derived from FUN_083ece54) is always 0: FUN_083ece54 in osos
//!   is the stub `mov r0, #0; bx lr`, so the whole `*5>>1 & 0xc00000`
//!   computation folds to 0. The constant 0 is passed directly.
//! - FUN_080359d4 (loads the canonical +inf double constant @ 0x089d4f74
//!   = 0x7ff00000_00000000 into the extended locals) is inlined as the
//!   constant bit pattern; both call sites only use the resulting hi/lo
//!   words as a plain double.
//! - The double store helper FUN_08036d70 (3 instructions) is inlined as
//!   two word stores.
//! - Rounding: the originals round via FUN_0803736c (round-to-nearest);
//!   the host-test mock rounds via host f64 multiply/divide, so results
//!   can differ from ADS in the last ulp on target until the real
//!   soft-float batch lands.

/// Indirect dispatch table for the not-yet-ported soft-float primitives
/// and the errno accessor (see the module header for the design and the
/// default-stub behavior).
#[derive(Clone, Copy)]
pub struct SoftfloatOps {
    /// FUN_08034228 @ 0x08034228: writes 10^exp to `out` as a 12-byte
    /// extended float {exp_word, hi, lo}. `adj` is the rounding-adjust
    /// argument (always 0 from this converter — see module docs).
    pub pow10: unsafe extern "C" fn(out: *mut u32, exp: u32, adj: i32),
    /// FUN_08037534 @ 0x08037534: extended multiply `a * b` (both
    /// 12-byte extended floats) rounded to a double, returned as its
    /// u64 bit pattern (hi word in bits 63..32; the original returned
    /// hi in r0 and lo in r1).
    pub ext_mul: unsafe extern "C" fn(a: *const u32, b: *const u32, adj: i32) -> u64,
    /// FUN_080374d4 @ 0x080374d4: extended divide `a / b`, same
    /// contract as `ext_mul`.
    pub ext_div: unsafe extern "C" fn(a: *const u32, b: *const u32, adj: i32) -> u64,
    /// errno store: the original calls FUN_0802ecb4 @ 0x0802ecb4 (the
    /// `__errno` veneer) and stores 2 (ERANGE) through the returned
    /// pointer. Routed through the table because the errno module is not
    /// importable from this batch.
    pub set_errno: unsafe extern "C" fn(value: i32),
}

/// Default stub: soft-float math is impossible without the primitives —
/// spin. On real hardware `SOFTFLOAT_OPS` must be installed before the
/// scanf/strtod float path is first used.
unsafe extern "C" fn missing_pow10(_out: *mut u32, _exp: u32, _adj: i32) {
    loop {}
}

/// Default stub: like `missing_pow10`, cannot compute — spin.
unsafe extern "C" fn missing_ext_mul(_a: *const u32, _b: *const u32, _adj: i32) -> u64 {
    loop {}
}

/// Default stub: like `missing_pow10`, cannot compute — spin.
unsafe extern "C" fn missing_ext_div(_a: *const u32, _b: *const u32, _adj: i32) -> u64 {
    loop {}
}

/// Default stub: dropping an ERANGE is harmless (mirrors the
/// missing_free leak-is-safe stub in malloc_rt.rs).
unsafe extern "C" fn missing_set_errno(_value: i32) {}

/// The active soft-float implementation. Defaults to the documented
/// stubs above; replaced by host tests (host f64 mock) and eventually by
/// the ported soft-float primitives. Written once at init on target;
/// tests serialize access.
pub static mut SOFTFLOAT_OPS: SoftfloatOps = SoftfloatOps {
    pow10: missing_pow10,
    ext_mul: missing_ext_mul,
    ext_div: missing_ext_div,
    set_errno: missing_set_errno,
};

/// Reads the ops table. Volatile for the same reason as malloc_rt's
/// `heap_ops()`: the table is meant to be swapped at runtime, and in a
/// build where nothing writes it yet LLVM would otherwise constant-fold
/// the loads to the default stubs and inline their `loop {}` bodies.
#[inline(always)]
fn softfloat_ops() -> SoftfloatOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SOFTFLOAT_OPS)) }
}

/// ADS ERANGE (stored on over/underflow).
const ERANGE: i32 = 2;

/// Canonical +infinity high word (constant double @ 0x089d4f74).
const INF_HI: u32 = 0x7ff0_0000;

/// Exponent word the original seeds for the normalized mantissa
/// (DAT_08036768): extended-format bias flag 0x40000000 plus 62.
const MANT_EXP_WORD: u32 = 0x4000_003e;

/// Stores a double lo-word-first, mirroring the original's store helper
/// FUN_08036d70 @ 0x08036d70 (`str lo,[r0]; str hi,[r0,#4]`).
#[inline(always)]
unsafe fn store_double(out: *mut u32, hi: u32, lo: u32) {
    out.write(lo);
    out.add(1).write(hi);
}

/// `scanf_float_convert` — original: `FUN_08036018` @ 0x08036018
/// (816 bytes).
///
/// Converts the engine-collected digit strings into a double bit
/// pattern. See the module header for the full algorithm, the buffer
/// formats and the simplifications.
///
/// - `out`: result `double *`, written as two u32 words (lo at [0], hi
///   at [1]) — the original's store helper takes the same shape.
/// - `exp_digits`: 0xff-terminated digit-value string for the decimal
///   exponent; empty buffer (first byte 0xff) means exponent 0,
///   otherwise byte 0 is the ASCII sign byte ('-' negates).
/// - `mant_digits`: 0xff-terminated digit-value string for the
///   mantissa, with an ASCII '+'/'-' sign byte first.
/// - `frac_adjust`: added to the parsed exponent (the engine passes the
///   negated count of fraction digits).
#[no_mangle]
pub unsafe extern "C" fn scanf_float_convert(
    out: *mut u32,
    exp_digits: *const u8,
    mant_digits: *const u8,
    frac_adjust: i32,
) {
    // Decimal exponent: digit values 0-9, 0xff terminated. Byte 0 is the
    // sign byte and is skipped by the accumulation loop; only '-' (0x2d)
    // negates. 32-bit wrapping, as in the original.
    let mut exp: i32 = 0;
    if *exp_digits != 0xff {
        let mut p = exp_digits.add(1);
        while *p != 0xff {
            exp = exp.wrapping_mul(10).wrapping_add(*p as i32);
            p = p.add(1);
        }
        if *exp_digits == b'-' {
            exp = exp.wrapping_neg();
        }
    }

    // Mantissa: optional ASCII sign byte, then digit values into a
    // wrapping 64-bit accumulator (hi:lo), umull/mla-style like the
    // original (widened u32 multiply lowers to umull, no libcall).
    let mut p = mant_digits;
    let first = *p;
    let mut negative = false;
    if first == b'-' || first == b'+' {
        negative = first == b'-';
        p = p.add(1);
    }
    let mut hi: u32 = 0;
    let mut lo: u32 = 0;
    while *p != 0xff {
        let digit = *p as u32;
        let prod = (lo as u64).wrapping_mul(10);
        let new_lo = (prod as u32).wrapping_add(digit);
        let carry = (new_lo < prod as u32) as u32;
        hi = hi
            .wrapping_mul(10)
            .wrapping_add((prod >> 32) as u32)
            .wrapping_add(carry);
        lo = new_lo;
        p = p.add(1);
    }

    exp = exp.wrapping_add(frac_adjust);
    let sign_bit = (negative as u32) << 31;

    // Zero mantissa: signed zero, no errno (checked before the range
    // guards in the original).
    if hi == 0 && lo == 0 {
        store_double(out, sign_bit, 0);
        return;
    }

    let ops = softfloat_ops();

    if exp < -500 {
        // Underflow: signed zero + ERANGE.
        store_double(out, sign_bit, 0);
        (ops.set_errno)(ERANGE);
        return;
    }
    if exp > 500 {
        // Overflow: signed infinity + ERANGE.
        store_double(out, sign_bit | INF_HI, 0);
        (ops.set_errno)(ERANGE);
        return;
    }

    // 10^|exp| as a 12-byte extended float. Third argument is the
    // rounding adjust, always 0 (FUN_083ece54 is a `mov r0,#0` stub).
    let mut pow10 = [0u32; 3];
    (ops.pow10)(pow10.as_mut_ptr(), exp.unsigned_abs(), 0);

    // Normalize the 64-bit mantissa into the same extended format:
    // exponent word starts at 0x4000003e (biased 62), top bit of `hi`
    // must end up set. Mantissa is known non-zero here.
    let mut ext = [MANT_EXP_WORD, hi, lo];
    if ext[1] == 0 {
        ext[1] = ext[2];
        ext[2] = 0;
        ext[0] = ext[0].wrapping_sub(32);
    }
    if ext[1] & 0xffff_0000 == 0 {
        ext[1] = ext[1] << 16 | ext[2] >> 16;
        ext[2] <<= 16;
        ext[0] = ext[0].wrapping_sub(16);
    }
    if ext[1] & 0xff00_0000 == 0 {
        ext[1] = ext[1] << 8 | ext[2] >> 24;
        ext[2] <<= 8;
        ext[0] = ext[0].wrapping_sub(8);
    }
    if ext[1] & 0xf000_0000 == 0 {
        ext[1] = ext[1] << 4 | ext[2] >> 28;
        ext[2] <<= 4;
        ext[0] = ext[0].wrapping_sub(4);
    }
    if ext[1] & 0xc000_0000 == 0 {
        ext[1] = ext[1] << 2 | ext[2] >> 30;
        ext[2] <<= 2;
        ext[0] = ext[0].wrapping_sub(2);
    }
    if ext[1] & 0x8000_0000 == 0 {
        ext[1] = ext[1] << 1 | ext[2] >> 31;
        ext[2] <<= 1;
        ext[0] = ext[0].wrapping_sub(1);
    }

    // exp >= 1 multiplies, exp <= 0 divides (the original's boundary:
    // `ble` takes the divide path).
    let bits = if exp < 1 {
        (ops.ext_div)(ext.as_ptr(), pow10.as_ptr(), 0)
    } else {
        (ops.ext_mul)(ext.as_ptr(), pow10.as_ptr(), 0)
    };
    let mut res_hi = (bits >> 32) as u32;
    let mut res_lo = bits as u32;
    if negative {
        res_hi ^= 0x8000_0000;
    }

    // A non-zero result whose exponent field is all ones overflowed:
    // ERANGE and canonical signed infinity (constant @ 0x089d4f74; NaN
    // payloads are flattened to infinity too, as in the original). A
    // result rounded down to zero takes no errno.
    if (res_hi & 0x7fff_ffff) | res_lo != 0 && (res_hi << 1) >> 21 == 0x7ff {
        (ops.set_errno)(ERANGE);
        res_hi = (res_hi & 0x8000_0000) | INF_HI;
        res_lo = 0;
    }
    store_double(out, res_hi, res_lo);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap the global ops table / mock state.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    // ---- Host f64 mock of the soft-float primitives ----
    //
    // The extended format is treated as value = M * 2^(field - 0x40000000 - 62)
    // where M is the 64-bit hi:lo mantissa (top bit set). This matches the
    // converter's own normalization (mantissa 1 -> field 0x3fffffff) and is
    // used consistently in both directions, so the round-trip is exact for
    // the test vectors.

    fn ext_from_f64(d: f64) -> [u32; 3] {
        if d == 0.0 {
            return [0x4000_0000, 0, 0];
        }
        let bits = d.abs().to_bits();
        let exp_bits = ((bits >> 52) & 0x7ff) as i64;
        let mant53 = (bits & 0x000f_ffff_ffff_ffff) | 0x0010_0000_0000_0000;
        let m64 = mant53 << 11;
        let field = (0x4000_0000i64 + exp_bits - 1024) as u32;
        [field, (m64 >> 32) as u32, m64 as u32]
    }

    fn ext_to_f64(e: [u32; 3]) -> f64 {
        let m = ((e[1] as u64) << 32) | e[2] as u64;
        (m as f64) * 2f64.powi(e[0] as i32 - 0x4000_0000 - 62)
    }

    static mut POW10_CALLS: usize = 0;
    static mut LAST_POW10_EXP: u32 = 0;
    static mut LAST_POW10_ADJ: i32 = -1;
    static mut MUL_CALLS: usize = 0;
    static mut DIV_CALLS: usize = 0;
    static mut LAST_OP_ADJ: i32 = -1;
    static mut ERRNO_VALUES: Vec<i32> = Vec::new();

    unsafe extern "C" fn mock_pow10(out: *mut u32, exp: u32, adj: i32) {
        POW10_CALLS += 1;
        LAST_POW10_EXP = exp;
        LAST_POW10_ADJ = adj;
        let e = ext_from_f64(10f64.powi(exp as i32));
        core::ptr::copy_nonoverlapping(e.as_ptr(), out, 3);
    }

    unsafe extern "C" fn mock_ext_mul(a: *const u32, b: *const u32, adj: i32) -> u64 {
        MUL_CALLS += 1;
        LAST_OP_ADJ = adj;
        let ea = [a.read(), a.add(1).read(), a.add(2).read()];
        let eb = [b.read(), b.add(1).read(), b.add(2).read()];
        (ext_to_f64(ea) * ext_to_f64(eb)).to_bits()
    }

    unsafe extern "C" fn mock_ext_div(a: *const u32, b: *const u32, adj: i32) -> u64 {
        DIV_CALLS += 1;
        LAST_OP_ADJ = adj;
        let ea = [a.read(), a.add(1).read(), a.add(2).read()];
        let eb = [b.read(), b.add(1).read(), b.add(2).read()];
        (ext_to_f64(ea) / ext_to_f64(eb)).to_bits()
    }

    unsafe extern "C" fn mock_set_errno(value: i32) {
        ERRNO_VALUES.push(value);
    }

    const MOCK_OPS: SoftfloatOps = SoftfloatOps {
        pow10: mock_pow10,
        ext_mul: mock_ext_mul,
        ext_div: mock_ext_div,
        set_errno: mock_set_errno,
    };

    /// Resets the mock log, installs the mock table, returns the lock guard.
    fn mock_softfloat() -> std::sync::MutexGuard<'static, ()> {
        // Stay usable even if an earlier test panicked mid-call.
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            POW10_CALLS = 0;
            LAST_POW10_EXP = 0;
            LAST_POW10_ADJ = -1;
            MUL_CALLS = 0;
            DIV_CALLS = 0;
            LAST_OP_ADJ = -1;
            ERRNO_VALUES.clear();
            *core::ptr::addr_of_mut!(SOFTFLOAT_OPS) = MOCK_OPS;
        }
        guard
    }

    /// Builds a mantissa buffer the way the engine would: sign byte,
    /// digit values, 0xff terminator.
    fn mant(negative: bool, digits: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(if negative { b'-' } else { b'+' });
        v.extend_from_slice(digits);
        v.push(0xff);
        v
    }

    /// Builds an exponent buffer: empty (just 0xff) or sign byte + digit
    /// values + 0xff.
    fn exp(negative: bool, digits: &[u8]) -> Vec<u8> {
        if digits.is_empty() {
            return std::vec![0xff];
        }
        let mut v = Vec::new();
        v.push(if negative { b'-' } else { b'+' });
        v.extend_from_slice(digits);
        v.push(0xff);
        v
    }

    /// Runs the converter, returns (double bits, errno log of this call).
    unsafe fn convert(m: &[u8], e: &[u8], frac_adjust: i32) -> (u64, Vec<i32>) {
        ERRNO_VALUES.clear();
        let mut out = [0u32; 2];
        scanf_float_convert(out.as_mut_ptr(), e.as_ptr(), m.as_ptr(), frac_adjust);
        let bits = ((out[1] as u64) << 32) | out[0] as u64;
        (bits, ERRNO_VALUES.clone())
    }

    #[test]
    fn plain_decimal_3_14() {
        let _lock = mock_softfloat();
        unsafe {
            // "3.14" -> mantissa 314, frac_adjust -2, no exponent.
            let (bits, errs) = convert(&mant(false, &[3, 1, 4]), &exp(false, &[]), -2);
            assert_eq!(bits, 3.14f64.to_bits());
            assert!(errs.is_empty());
            assert_eq!(POW10_CALLS, 1);
            assert_eq!(LAST_POW10_EXP, 2);
            assert_eq!(LAST_POW10_ADJ, 0, "rounding adjust is always 0");
            assert_eq!(DIV_CALLS, 1, "exp <= 0 divides");
            assert_eq!(MUL_CALLS, 0);
            assert_eq!(LAST_OP_ADJ, 0);
        }
    }

    #[test]
    fn negative_with_exponent_minus_1_5e3() {
        let _lock = mock_softfloat();
        unsafe {
            // "-1.5e3" -> mantissa -15, frac_adjust -1, exponent +3.
            let (bits, errs) = convert(&mant(true, &[1, 5]), &exp(false, &[3]), -1);
            assert_eq!(bits, (-1500.0f64).to_bits());
            assert!(errs.is_empty());
            assert_eq!(MUL_CALLS, 1, "exp > 0 multiplies");
            assert_eq!(DIV_CALLS, 0);
            assert_eq!(LAST_POW10_EXP, 2);
        }
    }

    #[test]
    fn negative_exponent_1e_minus_2() {
        let _lock = mock_softfloat();
        unsafe {
            // "1e-2" -> mantissa 1, frac_adjust 0, exponent -2.
            let (bits, errs) = convert(&mant(false, &[1]), &exp(true, &[2]), 0);
            assert_eq!(bits, 0.01f64.to_bits());
            assert!(errs.is_empty());
            assert_eq!(LAST_POW10_EXP, 2);
            assert_eq!(DIV_CALLS, 1);
        }
    }

    #[test]
    fn leading_dot_point_5() {
        let _lock = mock_softfloat();
        unsafe {
            // ".5" -> mantissa 5, frac_adjust -1.
            let (bits, errs) = convert(&mant(false, &[5]), &exp(false, &[]), -1);
            assert_eq!(bits, 0.5f64.to_bits());
            assert!(errs.is_empty());
        }
    }

    #[test]
    fn trailing_dot_5() {
        let _lock = mock_softfloat();
        unsafe {
            // "5." -> mantissa 5, frac_adjust 0 (exp 0 -> divide by 10^0).
            let (bits, errs) = convert(&mant(false, &[5]), &exp(false, &[]), 0);
            assert_eq!(bits, 5.0f64.to_bits());
            assert!(errs.is_empty());
            assert_eq!(LAST_POW10_EXP, 0);
            assert_eq!(DIV_CALLS, 1, "exp == 0 takes the divide path");
        }
    }

    #[test]
    fn bare_exponent_marker_1e() {
        let _lock = mock_softfloat();
        unsafe {
            // "1e" with no exponent digits: the ENGINE rejects this (it
            // would ungetc the 'e'); if the converter is still reached
            // with an empty exponent buffer the exponent is 0 -> 1.0.
            let (bits, errs) = convert(&mant(false, &[1]), &exp(false, &[]), 0);
            assert_eq!(bits, 1.0f64.to_bits());
            assert!(errs.is_empty());
            // A lone sign byte with zero digit values also parses as
            // exponent 0 (only 0xff terminates the loop).
            let (bits, _) = convert(&mant(false, &[1]), &[b'-', 0xff], 0);
            assert_eq!(bits, 1.0f64.to_bits());
        }
    }

    #[test]
    fn width_limited_field_is_engine_truncation() {
        let _lock = mock_softfloat();
        unsafe {
            // Width limiting happens during digit collection in the
            // engine (0x08036348), not here: a %3f read of "3.14159"
            // arrives as the already-truncated "3.14" buffers.
            let (bits, errs) = convert(&mant(false, &[3, 1, 4]), &exp(false, &[]), -2);
            assert_eq!(bits, 3.14f64.to_bits());
            assert!(errs.is_empty());
        }
    }

    #[test]
    fn inf_and_nan_literals_are_engine_business() {
        let _lock = mock_softfloat();
        unsafe {
            // "inf"/"nan" input is matched literally by the engine
            // (0x08036420: 'i'/'I'/'n'/'N' dispatch) and never reaches
            // this converter. The converter only *produces* infinities:
            // exponent 501 > 500 -> signed +inf + ERANGE.
            let (bits, errs) = convert(&mant(false, &[1]), &exp(false, &[5, 0, 1]), 0);
            assert_eq!(bits, f64::INFINITY.to_bits());
            assert_eq!(errs, std::vec![2]);
            assert_eq!(POW10_CALLS, 0, "range guard fires before pow10");
            // Negative overflow -> -inf.
            let (bits, errs) = convert(&mant(true, &[9, 9]), &exp(false, &[5, 0, 1]), 0);
            assert_eq!(bits, f64::NEG_INFINITY.to_bits());
            assert_eq!(errs, std::vec![2]);
        }
    }

    #[test]
    fn exponent_boundary_500_is_normal_path() {
        let _lock = mock_softfloat();
        unsafe {
            // exp == 500 stays on the normal path (10^500 overflows the
            // host f64 mock's pow10 to +inf, so 1 * inf -> inf, which
            // the overflow fix-up then canonicalizes with ERANGE).
            let (bits, errs) = convert(&mant(false, &[1]), &exp(false, &[5, 0, 0]), 0);
            assert_eq!(bits, f64::INFINITY.to_bits());
            assert_eq!(errs, std::vec![2]);
            assert_eq!(POW10_CALLS, 1);
            // exp == -500 is also normal path: divides by 10^500.
            // The host mock's 10^500 is +inf, so 1/inf -> +0, and a
            // rounded-to-zero result takes NO errno.
            let (bits, errs) = convert(&mant(false, &[1]), &exp(true, &[5, 0, 0]), 0);
            assert_eq!(bits, 0.0f64.to_bits());
            assert!(errs.is_empty());
        }
    }

    #[test]
    fn underflow_below_minus_500() {
        let _lock = mock_softfloat();
        unsafe {
            let (bits, errs) = convert(&mant(false, &[7]), &exp(true, &[5, 0, 1]), 0);
            assert_eq!(bits, 0.0f64.to_bits());
            assert_eq!(errs, std::vec![2]);
            assert_eq!(POW10_CALLS, 0);
            // Negative underflow -> -0.0.
            let (bits, _) = convert(&mant(true, &[7]), &exp(true, &[5, 0, 1]), 0);
            assert_eq!(bits, (-0.0f64).to_bits());
        }
    }

    #[test]
    fn zero_mantissa_short_circuits() {
        let _lock = mock_softfloat();
        unsafe {
            // Zero mantissa: signed zero, no errno, no soft-float calls —
            // even with an extreme exponent.
            let (bits, errs) = convert(&mant(false, &[0]), &exp(false, &[9, 9, 9]), 0);
            assert_eq!(bits, 0.0f64.to_bits());
            assert!(errs.is_empty());
            assert_eq!(POW10_CALLS, 0);
            let (bits, _) = convert(&mant(true, &[0]), &exp(false, &[]), -5);
            assert_eq!(bits, (-0.0f64).to_bits());
        }
    }

    #[test]
    fn result_overflow_via_multiply_gets_canonical_inf() {
        let _lock = mock_softfloat();
        unsafe {
            // 9.9e308: exponent in range, but the product overflows.
            let (bits, errs) = convert(&mant(false, &[9, 9]), &exp(false, &[3, 0, 8]), -1);
            assert_eq!(bits, f64::INFINITY.to_bits());
            assert_eq!(errs, std::vec![2]);
            assert_eq!(MUL_CALLS, 1);
        }
    }

    #[test]
    fn subnormal_result_passes_through_without_errno() {
        let _lock = mock_softfloat();
        unsafe {
            // 1e-308: exponent in range; the quotient is a subnormal
            // double — not zero, not inf -> no errno. (10^308 is still
            // finite for the host f64 mock; beyond ~308 the mock's
            // pow10 saturates where the real extended format would not,
            // so the test stays at 308.) The expectation mirrors the
            // mock's own two-step computation.
            let (bits, errs) = convert(&mant(false, &[1]), &exp(true, &[3, 0, 8]), 0);
            let expected = (1.0f64 / 10f64.powi(308)).to_bits();
            assert_eq!(bits, expected);
            assert!((expected >> 52) & 0x7ff == 0, "1e-308 is subnormal");
            assert!(errs.is_empty());
        }
    }

    #[test]
    fn long_mantissa_full_u64() {
        let _lock = mock_softfloat();
        unsafe {
            // 19 digits (fits u64): 1234567890123456789 * 10^-18. The
            // expectation mirrors the mock's two-step rounding (64-bit
            // mantissa rounded to f64, then correctly-rounded divide),
            // which can differ from the decimal literal in the last ulp.
            let digits = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            let (bits, errs) = convert(&mant(false, &digits), &exp(false, &[]), -18);
            let expected = (1234567890123456789u64 as f64 / 10f64.powi(18)).to_bits();
            assert_eq!(bits, expected);
            assert!(errs.is_empty());
        }
    }

    #[test]
    fn mantissa_accumulation_wraps_like_the_original() {
        let _lock = mock_softfloat();
        unsafe {
            // 21 digits overflow the 64-bit accumulator; the original
            // wraps (umull/mla, no saturation). Compute the wrapped
            // mantissa the same way and expect its f64 value.
            let digits = [9u8; 21];
            let mut acc: u64 = 0;
            for _ in 0..21 {
                acc = acc.wrapping_mul(10).wrapping_add(9);
            }
            let (bits, errs) = convert(&mant(false, &digits), &exp(false, &[]), 0);
            assert_eq!(bits, (acc as f64).to_bits());
            assert!(errs.is_empty());
        }
    }

    #[test]
    fn result_is_stored_lo_word_first() {
        let _lock = mock_softfloat();
        unsafe {
            let mut out = [0xdead_beefu32; 2];
            scanf_float_convert(
                out.as_mut_ptr(),
                exp(false, &[]).as_ptr(),
                mant(false, &[5]).as_ptr(),
                0,
            );
            let bits = 5.0f64.to_bits();
            assert_eq!(out[0], bits as u32, "lo word at [0]");
            assert_eq!(out[1], (bits >> 32) as u32, "hi word at [1]");
        }
    }
}
