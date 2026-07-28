//! FreeType `ftcalc` 16.16 fixed-point kernels — `FT_MulFix` and
//! `FT_DivFix` as compiled into retailOS (ARM ADS build of FreeType 2.1.x,
//! the pre-`FT_Int64` code paths). Pure integer functions — no hardware;
//! host tests prove complete behavior, including the 32-bit wrapping
//! quirks. Call counts are binary-scanned b/bl words.
//!
//! - `ft_mulfix` — `FUN_0804d2cc` @ 0x0804d2cc (124 bytes; 116 call
//!   sites). `a * b / 0x10000` rounded half-up on the magnitude.
//!   Identity fast-out returns `a` untouched when `a == 0 || b ==
//!   0x10000`. Works on 32-bit absolute values (`(x ^ (x>>31)) -
//!   (x>>31)`, so `i32::MIN` stays 0x80000000): when `|a| <= 0x800 &&
//!   |b| <= 0x100000` a single `mul` suffices (max intermediate
//!   0x80008000 — never wraps); otherwise the three-partial-product
//!   split `(ua>>16)*ub + (ub>>16)*(ua&0xffff) + (((ua&0xffff)*
//!   (ub&0xffff) + 0x8000) >> 16)`, all 32-bit wrapping — large products
//!   genuinely truncate, faithfully preserved. Sign restored with the
//!   same xor/sub trick on `(a^b) >> 31`.
//!
//! - `ft_divfix` — `FUN_0804c2d4` @ 0x0804c2d4 (140 bytes; 56 call
//!   sites). `(a << 16) / b` with a `|b|/2` rounding bias. `b == 0`
//!   returns 0x7fffffff (negated to 0x80000001 when `a < 0`). When
//!   `(|a| as i32) >> 16 == 0` the numerator fits: one 32-bit unsigned
//!   divide of `(ua << 16) + (ub >> 1)` (that add wraps for huge `|b|` —
//!   preserved). Otherwise the 64-bit path builds `hi = (ua as i32) >>
//!   16` (arithmetic — for `a == i32::MIN`, `ua` = 0x80000000 and `hi`
//!   becomes 0xffff8000, so the divide clamps), `lo = ua << 16`, adds
//!   the bias with carry (`FT_Add64`), and divides 64-by-32 with a
//!   0x7fffffff clamp when `hi >= |b|`. Note `ub >> 1` is *arithmetic*
//!   too: `b == i32::MIN` gives a 0xc0000000 bias.
//!
//! # Deviations
//!
//! The original reaches three helpers the port inlines with bit-identical
//! results:
//!
//! - `__rt_udiv` @ 0x08036f14 (ADS unsigned divide) → Rust `u32` `/`.
//! - `FT_Add64` @ 0x080ed3b4 → `overflowing_add` + carry into `hi`.
//! - `ft_div64by32` @ 0x0807c5b8 → [`ft_div64by32`]: the original's
//!   32-step restoring division equals `u64` division exactly when
//!   `hi < divisor` (the quotient then fits 32 bits); the `hi >=
//!   divisor` overflow clamp to 0x7fffffff is kept verbatim. (0x0807c5b8
//!   itself is outside this module's claimed range and stays unclaimed.)

/// Sign-propagating absolute value as the original computes it:
/// `(x ^ (x >> 31)) - (x >> 31)`, wrapping — `i32::MIN` maps to
/// 0x80000000. Returns (unsigned magnitude, the `x >> 31` sign word).
#[inline(always)]
fn abs_and_sign(x: i32) -> (u32, i32) {
    let sign = x >> 31;
    ((x ^ sign).wrapping_sub(sign) as u32, sign)
}

/// ft_mulfix (FreeType `FT_MulFix`) — original: `FUN_0804d2cc`
/// @ 0x0804d2cc (124 bytes).
///
/// 16.16 fixed-point multiply, rounded half-up on the magnitude. See the
/// module header for the exact paths and wrapping behavior.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ft_mulfix(a: i32, b: i32) -> i32 {
    if a == 0 || b == 0x10000 {
        return a;
    }
    let (ua, sa) = abs_and_sign(a);
    let (ub, sb) = abs_and_sign(b);
    let r = if ua <= 0x800 && ub <= 0x10_0000 {
        // Max product 0x800 * 0x100000 = 0x80000000: + 0x8000 never wraps.
        (ua * ub + 0x8000) >> 16
    } else {
        let al = ua & 0xffff;
        (ua >> 16)
            .wrapping_mul(ub)
            .wrapping_add((ub >> 16).wrapping_mul(al))
            .wrapping_add((al * (ub & 0xffff) + 0x8000) >> 16)
    };
    let s = sa ^ sb;
    ((r as i32) ^ s).wrapping_sub(s)
}

/// ft_div64by32 (FreeType) — original: `FUN_0807c5b8` @ 0x0807c5b8
/// (private inline stand-in, not claimed — see the module header).
///
/// Quotient of `(hi:lo) / divisor` when it fits in 32 bits
/// (`hi < divisor`); 0x7fffffff otherwise.
#[inline(always)]
fn ft_div64by32(hi: u32, lo: u32, divisor: u32) -> u32 {
    if hi >= divisor {
        return 0x7fff_ffff;
    }
    ((((hi as u64) << 32) | lo as u64) / divisor as u64) as u32
}

/// ft_divfix (FreeType `FT_DivFix`) — original: `FUN_0804c2d4`
/// @ 0x0804c2d4 (140 bytes).
///
/// `(a << 16) / b` with a `|b|/2` rounding bias and a 0x7fffffff clamp on
/// division by zero or overflow. See the module header for the exact
/// paths, the arithmetic-shift quirks, and the inlined helpers.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ft_divfix(a: i32, b: i32) -> i32 {
    let sign = a ^ b;
    let ua = a.wrapping_abs() as u32;
    let ub = b.wrapping_abs() as u32;
    let bias = ((ub as i32) >> 1) as u32; // arithmetic, per the original's asr
    let q: u32 = if ub == 0 {
        0x7fff_ffff
    } else if (ua as i32) >> 16 == 0 {
        (ua << 16).wrapping_add(bias) / ub
    } else {
        // FT_Add64 of {hi: (ua as i32) >> 16, lo: ua << 16} + {0, bias}.
        let (lo, carry) = (ua << 16).overflowing_add(bias);
        let hi = (((ua as i32) >> 16) as u32).wrapping_add(carry as u32);
        ft_div64by32(hi, lo, ub)
    };
    let q = q as i32;
    if sign < 0 {
        q.wrapping_neg()
    } else {
        q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact i64 reference for inputs whose magnitudes stay clear of the
    /// 32-bit wrapping paths: sign * ((|a| * |b| + 0x8000) >> 16).
    fn mulfix_exact(a: i64, b: i64) -> i64 {
        let r = (a.abs() * b.abs() + 0x8000) >> 16;
        if (a < 0) != (b < 0) {
            -r
        } else {
            r
        }
    }

    #[test]
    fn mulfix_identity_fast_outs() {
        assert_eq!(ft_mulfix(0, 555), 0);
        assert_eq!(ft_mulfix(0, 0), 0);
        assert_eq!(ft_mulfix(123, 0x10000), 123);
        assert_eq!(ft_mulfix(-123, 0x10000), -123);
        // b == 0x10000 returns a untouched even for i32::MIN.
        assert_eq!(ft_mulfix(i32::MIN, 0x10000), i32::MIN);
    }

    #[test]
    fn mulfix_matches_exact_reference_in_safe_range() {
        let vals = [
            1, -1, 3, -3, 0x8000, -0x8000, 0xffff, 0x10000, 0x18000,
            -0x18000, 0x123456, -0x123456, 0x7ff, 0x800, 0x801,
        ];
        for &a in &vals {
            for &b in &vals {
                if b == 0x10000 {
                    continue; // identity path, checked separately
                }
                let want = mulfix_exact(a as i64, b as i64);
                if want.abs() < (1 << 31) && (a as i64 * b as i64).abs() < (1 << 47) {
                    assert_eq!(
                        ft_mulfix(a, b) as i64,
                        want,
                        "ft_mulfix({a:#x}, {b:#x})"
                    );
                }
            }
        }
    }

    #[test]
    fn mulfix_fast_slow_path_boundary() {
        // |a| <= 0x800 && |b| <= 0x100000 is the single-mul fast path;
        // both boundaries agree with the exact reference.
        for (a, b) in [
            (0x800, 0x10_0000),
            (0x801, 0x10_0000),
            (0x800, 0x10_0001),
            (-0x800, 0x10_0000),
            (0x800, -0x10_0000),
        ] {
            assert_eq!(ft_mulfix(a, b) as i64, mulfix_exact(a as i64, b as i64));
        }
        // Hand-verified against the asm model (Python replication).
        assert_eq!(ft_mulfix(0x800, 0x10_0000), 0x8000);
        assert_eq!(ft_mulfix(0x801, 0x10_0000), 0x8010);
    }

    #[test]
    fn mulfix_large_products_wrap_like_the_original() {
        // Expected values computed with an independent Python model of
        // the disassembly's 32-bit wrapping arithmetic.
        assert_eq!(ft_mulfix(0x123456, -0x654321), -0x7336bf9);
        assert_eq!(ft_mulfix(0x7fffffff, 0x10001), -0x7fff8001);
        assert_eq!(ft_mulfix(i32::MIN, 0x10001), 0x7fff8000);
        assert_eq!(ft_mulfix(i32::MIN, i32::MIN), 0);
        assert_eq!(ft_mulfix(0x7fffffff, 0x7fffffff), -0x10000);
    }

    #[test]
    fn mulfix_sign_combinations() {
        assert_eq!(ft_mulfix(0x8000, 0x8000), 0x4000);
        assert_eq!(ft_mulfix(-0x8000, 0x8000), -0x4000);
        assert_eq!(ft_mulfix(0x8000, -0x8000), -0x4000);
        assert_eq!(ft_mulfix(-0x8000, -0x8000), 0x4000);
        assert_eq!(ft_mulfix(-0x10000, 0x30000), -0x30000);
    }

    #[test]
    fn mulfix_rounds_half_up_on_magnitude() {
        // 3 * 1.5 = 4.5 -> 5 (the +0x8000 bias), symmetric for negatives.
        assert_eq!(ft_mulfix(3, 0x18000), 5);
        assert_eq!(ft_mulfix(-3, 0x18000), -5);
    }

    #[test]
    fn divfix_basics() {
        assert_eq!(ft_divfix(0x10000, 0x20000), 0x8000); // 1.0 / 2.0
        assert_eq!(ft_divfix(0x30000, 0x10000), 0x30000); // 3.0 / 1.0
        assert_eq!(ft_divfix(1, 3), 0x5555);
        assert_eq!(ft_divfix(-0x10000, 0x30000), -0x5555);
        assert_eq!(ft_divfix(0xffff, 0xffff), 0x10000);
        assert_eq!(ft_divfix(0x10000, 3), 0x5555_5555);
        assert_eq!(ft_divfix(0x12345, 0x678), 0x2d_06f5);
    }

    #[test]
    fn divfix_by_zero_clamps_with_sign() {
        assert_eq!(ft_divfix(100, 0), 0x7fff_ffff);
        assert_eq!(ft_divfix(-100, 0), -0x7fff_ffff); // 0x80000001
        assert_eq!(ft_divfix(0, 0), 0x7fff_ffff);
    }

    #[test]
    fn divfix_overflow_clamps() {
        // Quotient needs > 31 bits: 64-bit path clamps at 0x7fffffff.
        assert_eq!(ft_divfix(0x7fffffff, 0x10000), 0x7fff_ffff);
        // i32::MIN: hi becomes 0xffff8000 (arithmetic shift of the
        // un-negatable magnitude), forcing the clamp; sign then applies.
        assert_eq!(ft_divfix(i32::MIN, 0x10000), -0x7fff_ffff);
        assert_eq!(ft_divfix(i32::MIN, i32::MIN), 0x7fff_ffff);
    }

    #[test]
    fn divfix_min_divisor_arithmetic_bias_quirk() {
        // b == i32::MIN: the asr bias is 0xc0000000, so 1.0 / -32768.0
        // lands on -3 instead of the mathematical -2 (asm-model verified).
        assert_eq!(ft_divfix(0x10000, i32::MIN), -3);
    }

    #[test]
    fn divfix_32bit_path_numerator_wraps_like_the_original() {
        // |a| < 0x10000 takes the single-divide path whose
        // `(ua << 16) + ub/2` add wraps at 2^32: 0xffff0000 + 0x3fffffff
        // wraps to 0x3ffeffff, quotient 0 (not the unwrapped 2).
        assert_eq!(ft_divfix(0xffff, 0x7fffffff), 0);
    }

    #[test]
    fn divfix_matches_exact_reference_in_safe_range() {
        // Where no wrap/clamp applies: sign * ((|a| << 16) + |b|/2) / |b|.
        let avals = [1, -1, 0x8000, -0x8000, 0xffff, 0x10000, 0x123456, -0x123456];
        let bvals = [1, -1, 3, -3, 0x678, 0x10000, -0x10000, 0x7fffffff];
        for &a in &avals {
            for &b in &bvals {
                let (a64, b64) = (a as i64, b as i64);
                let num = (a64.abs() << 16) + b64.abs() / 2;
                let want = num / b64.abs();
                let want = if (a < 0) != (b < 0) { -want } else { want };
                // Exclude the 32-bit path's wrapping numerator (|a| <
                // 0x10000 with num >= 2^32 wraps in the original too —
                // covered by the quirk tests, not this reference).
                let wraps_32 = a64.abs() < 0x10000 && num >= (1i64 << 32);
                if want.abs() < (1 << 31) && !wraps_32 {
                    assert_eq!(
                        ft_divfix(a, b) as i64,
                        want,
                        "ft_divfix({a:#x}, {b:#x})"
                    );
                }
            }
        }
    }
}
