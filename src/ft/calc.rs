//! FreeType `ftcalc` kernels — `FT_MulFix`, `FT_DivFix`, `FT_MulDiv` and
//! the `FT_Matrix` ops as compiled into retailOS (ARM ADS build of
//! FreeType 2.x, the pre-`FT_Int64` code paths; the binary's license
//! blob says "copyright 2000-2006, 2007 The FreeType Project", so a
//! 2.3-era tree). Pure integer functions — no hardware; host tests prove
//! complete behavior, including the 32-bit wrapping quirks. Call counts
//! are binary-scanned b/bl words.
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
//! The original reaches two helpers the port inlines with bit-identical
//! results:
//!
//! - `__rt_udiv` @ 0x08036f14 (ADS unsigned divide) → Rust `u32` `/`.
//! - `FT_Add64` @ 0x080ed3b4 → `overflowing_add` + carry into `hi`.
//!
//! Its third, `ft_div64by32` @ 0x0807c5b8, is now the real ported
//! [`ft_div64by32`] and both callers go through it. It used to be
//! stubbed here as `u64` division, which is *not* the same function:
//! the original's remainder is a single 32-bit register and truncates
//! for divisors above 0x80000000. Neither caller can produce one — they
//! divide by an `i32` magnitude — but the symbol on its own does, so the
//! restoring loop is what got ported.

use crate::ft::types::{FtInt64, FtMatrix};

/// ft_add64 (FreeType `FT_Add64`) — original: `FUN_080ed3b4`
/// @ 0x080ed3b4 (68 bytes; 2 call sites, both inside this module's
/// `ft_divfix`/`ft_muldiv` where the port inlines it).
///
/// `*z = *x + *y` on the software `FT_Int64` pair: `lo = x.lo + y.lo`
/// (wrapping), `hi = x.hi + y.hi + (lo < x.lo)`. The original spells the
/// carry test as `lo < max(x.lo, y.lo)` (`movhi`/`movls` then `cmp`),
/// which is the same predicate. Both halves are computed from register
/// copies before either store, so `z` may alias `x` or `y`.
///
/// # Safety
/// `x`, `y` and `z` must be valid `FtInt64` pointers (the original does
/// not null-check them).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_add64(x: *const FtInt64, y: *const FtInt64, z: *mut FtInt64) {
    let (x, y) = (*x, *y);
    let (lo, carry) = x.lo.overflowing_add(y.lo);
    *z = FtInt64 {
        lo,
        hi: x.hi.wrapping_add(y.hi).wrapping_add(carry as u32),
    };
}

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

/// ft_div64by32 (FreeType `ft_div64by32`, the static ftcalc.c helper) —
/// original: `FUN_0807c5b8` @ 0x0807c5b8 (64 bytes; 2 call sites, both
/// in this module — [`ft_divfix`] @ 0x0804c34c and [`ft_muldiv`]
/// @ 0x0804d2ac).
///
/// Quotient of the 64-bit `(hi:lo)` by `divisor`, by 32 rounds of
/// restoring division: shift the next bit of `lo` into the remainder,
/// shift the quotient, and subtract `divisor` when it fits. An
/// out-of-range result — `hi >= divisor`, which includes
/// `divisor == 0`, since every unsigned value is `>= 0` — short-circuits
/// to 0x7fffffff (`mvncs r0, #0x80000000`) instead of overflowing or
/// trapping.
///
/// The remainder lives in one 32-bit register, so `r <<= 1` drops its
/// top bit. That is harmless exactly while `divisor <= 0x80000000`
/// (then `r <= divisor - 1 <= 0x7fffffff` and `2r + 1` still fits), and
/// both callers reach here with `divisor` an `i32` magnitude, so they
/// never exceed that. Above it the truncation makes the result diverge
/// from true 64-by-32 division — e.g. `ft_div64by32(0x90000000, 0,
/// 0xffffffff)` is 0 where the true quotient is 0x90000000. Upstream
/// behavior, preserved and pinned by a test; the host tests use `u64`
/// division as the reference over the domain where the two agree.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ft_div64by32(hi: u32, lo: u32, divisor: u32) -> u32 {
    if hi >= divisor {
        return 0x7fff_ffff;
    }
    let (mut remainder, mut lo, mut quotient) = (hi, lo, 0u32);
    for _ in 0..32 {
        remainder = (remainder << 1) | (lo >> 31);
        quotient <<= 1;
        if remainder >= divisor {
            remainder -= divisor;
            quotient |= 1;
        }
        lo <<= 1;
    }
    quotient
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

/// ft_muldiv (FreeType `FT_MulDiv`) — original: `FUN_0804d1a8`
/// @ 0x0804d1a8 (288 bytes; 33 call sites).
///
/// `a * b / c` with a `|c|/2` rounding bias on the magnitude. Identity
/// fast-out returns `a` when `a == 0 || b == c`. Sign is
/// `(a ^ b ^ c) >> 31`; magnitudes come from conditional negation
/// (`rsblt`, wrapping — `i32::MIN` stays 0x80000000).
///
/// Path selection replicates the original's *signed* comparisons on the
/// wrapped magnitudes (upstream's `FT_ABS`-then-`long`-compare behavior
/// on a 32-bit machine, quirks included — `|a| == 0x80000000` passes the
/// "small" test because it is negative as an `i32`):
///
/// - `|a| <= 46340 && |b| <= 46340` (signed) and `0 < |c| < 176096`
///   (signed): one 32-bit `mul` plus `__rt_sdiv` @ 0x08031568 — for
///   genuine magnitudes `46340 * 46340 + 176095/2 == 0x7fffffff`
///   exactly, so nothing wraps; only the `i32::MIN` quirk inputs wrap
///   the `mul` (faithfully preserved).
/// - both small but `|c| >= 176096` (signed), or either large and
///   `|c| > 0` (signed): the 64-bit path [`ft_muldiv64`].
/// - otherwise (`c == 0` or `|c| == 0x80000000`): 0x7fffffff.
///
/// The quotient is truncated to `u32` and sign-restored with a wrapping
/// negate, so an unclamped 64-bit-path quotient in `2^31..2^32` comes
/// back sign-flipped (e.g. `ft_muldiv(0x7fffffff, 2, 1) == -2`) — the
/// stock overflow behavior, kept.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ft_muldiv(a: i32, b: i32, c: i32) -> i32 {
    if a == 0 || b == c {
        return a;
    }
    let sign = a ^ b ^ c;
    let ua = a.wrapping_abs() as u32;
    let ub = b.wrapping_abs() as u32;
    let uc = c.wrapping_abs() as u32;
    let q: u32 = if (ua as i32) <= 46340 && (ub as i32) <= 46340 {
        if (uc as i32) >= 176_096 {
            ft_muldiv64(ua, ub, uc)
        } else if (uc as i32) > 0 {
            // uc > 0 here, so the original's `asr 1` bias == `uc >> 1`.
            let num = ua.wrapping_mul(ub).wrapping_add(uc >> 1);
            // __rt_sdiv: signed truncating divide; uc > 0 rules out both
            // division by zero and the i32::MIN / -1 overflow.
            ((num as i32) / (uc as i32)) as u32
        } else {
            0x7fff_ffff
        }
    } else if (uc as i32) > 0 {
        ft_muldiv64(ua, ub, uc)
    } else {
        0x7fff_ffff
    };
    let q = q as i32;
    if sign < 0 {
        q.wrapping_neg()
    } else {
        q
    }
}

/// ft_muldiv's 64-bit path: the original inlines `ft_multo64` (whose
/// four-partial-product 32-bit sequence computes the exact 64-bit
/// product — bit-identical to a `u64` multiply), calls `FT_Add64`
/// @ 0x080ed3b4 to add the `|c| >> 1` bias (callers guarantee `uc > 0`,
/// so `asr` == `lsr` and the 64-bit sum cannot wrap:
/// max `0xfffffffe00000001 + 0x3fffffff`), then [`ft_div64by32`].
#[inline(always)]
fn ft_muldiv64(ua: u32, ub: u32, uc: u32) -> u32 {
    let total = (ua as u64) * (ub as u64) + (uc >> 1) as u64;
    ft_div64by32((total >> 32) as u32, total as u32, uc)
}

/// ft_matrix_multiply (FreeType `FT_Matrix_Multiply`) — original:
/// `FUN_0804d0dc` @ 0x0804d0dc (160 bytes; 1 call site).
///
/// `*b = *a * *b` in 16.16 fixed point: each result cell is the
/// wrapping sum of two [`ft_mulfix`] products (`xx = a.xx*b.xx +
/// a.xy*b.yx`, etc.). Null `a` or `b` is a no-op. The original computes
/// all eight products before storing any cell, so `a == b` aliasing
/// reads only pre-multiply values — preserved by snapshotting both
/// matrices up front.
///
/// # Safety
/// `a` and `b` must be null or valid `FtMatrix` pointers.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_matrix_multiply(a: *const FtMatrix, b: *mut FtMatrix) {
    if a.is_null() || b.is_null() {
        return;
    }
    let (a, bm) = (*a, *b);
    (*b).xx = ft_mulfix(a.xx, bm.xx).wrapping_add(ft_mulfix(a.xy, bm.yx));
    (*b).xy = ft_mulfix(a.xx, bm.xy).wrapping_add(ft_mulfix(a.xy, bm.yy));
    (*b).yx = ft_mulfix(a.yx, bm.xx).wrapping_add(ft_mulfix(a.yy, bm.yx));
    (*b).yy = ft_mulfix(a.yx, bm.xy).wrapping_add(ft_mulfix(a.yy, bm.yy));
}

/// ft_matrix_invert (FreeType `FT_Matrix_Invert`) — original:
/// `FUN_0804d054` @ 0x0804d054 (136 bytes; 1 call site).
///
/// In-place 16.16 inverse. `delta = mulfix(xx, yy) - mulfix(xy, yx)`
/// (wrapping sub); null matrix or `delta == 0` returns error 6
/// (`FT_Err_Invalid_Argument`) with the matrix untouched. Otherwise
/// `xy = -divfix(xy, delta)`, `yx = -divfix(yx, delta)` (wrapping
/// negate), then `xx_new = divfix(yy, delta)` and `yy_new =
/// divfix(xx_old, delta)` — the original stashes the old `xx` before
/// overwriting it. Returns 0.
///
/// # Safety
/// `matrix` must be null or a valid `FtMatrix` pointer.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_matrix_invert(matrix: *mut FtMatrix) -> i32 {
    if matrix.is_null() {
        return 6;
    }
    let m = &mut *matrix;
    let delta = ft_mulfix(m.xx, m.yy).wrapping_sub(ft_mulfix(m.xy, m.yx));
    if delta == 0 {
        return 6;
    }
    m.xy = ft_divfix(m.xy, delta).wrapping_neg();
    m.yx = ft_divfix(m.yx, delta).wrapping_neg();
    let xx_old = m.xx;
    m.xx = ft_divfix(m.yy, delta);
    m.yy = ft_divfix(xx_old, delta);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference `FT_Add64`: exact 64-bit wrapping addition of the two
    /// {lo,hi} pairs.
    fn add64_ref(x: FtInt64, y: FtInt64) -> FtInt64 {
        let x64 = ((x.hi as u64) << 32) | x.lo as u64;
        let y64 = ((y.hi as u64) << 32) | y.lo as u64;
        let s = x64.wrapping_add(y64);
        FtInt64 { lo: s as u32, hi: (s >> 32) as u32 }
    }

    fn i64pair(lo: u32, hi: u32) -> FtInt64 {
        FtInt64 { lo, hi }
    }

    fn add64(x: FtInt64, y: FtInt64) -> FtInt64 {
        let mut z = i64pair(0xdead_beef, 0xfeed_face);
        unsafe { ft_add64(&x, &y, &mut z) };
        z
    }

    #[test]
    fn add64_carry_boundaries() {
        assert_eq!(add64(i64pair(1, 0), i64pair(2, 0)), i64pair(3, 0));
        // lo sum exactly 0xffffffff: no carry.
        assert_eq!(
            add64(i64pair(0xffff_fffe, 5), i64pair(1, 7)),
            i64pair(0xffff_ffff, 12)
        );
        // lo sum wraps to 0: carry into hi.
        assert_eq!(add64(i64pair(0xffff_ffff, 5), i64pair(1, 7)), i64pair(0, 13));
        // hi wraps too — the whole 64-bit sum is modular.
        assert_eq!(
            add64(i64pair(0xffff_ffff, 0xffff_ffff), i64pair(1, 0)),
            i64pair(0, 0)
        );
    }

    #[test]
    fn add64_matches_reference_on_randomized_inputs() {
        let mut s: u32 = 0x1357_9bdf;
        let mut rnd = || {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s
        };
        for _ in 0..100_000 {
            let x = i64pair(rnd(), rnd());
            let y = i64pair(rnd(), rnd());
            assert_eq!(add64(x, y), add64_ref(x, y), "{x:?} + {y:?}");
        }
        // Plus the extremes the random sweep will not hit.
        for &lo in &[0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            for &hi in &[0u32, 1, 0x8000_0000, 0xffff_ffff] {
                let x = i64pair(lo, hi);
                for &lo2 in &[0u32, 1, 0xffff_ffff] {
                    let y = i64pair(lo2, hi);
                    assert_eq!(add64(x, y), add64_ref(x, y), "{x:?} + {y:?}");
                }
            }
        }
    }

    #[test]
    fn add64_destination_may_alias_a_source() {
        // The original loads both operands before either store.
        let mut a = i64pair(0xffff_ffff, 1);
        let b = i64pair(2, 3);
        unsafe { ft_add64(&a, &b, &mut a) };
        assert_eq!(a, i64pair(1, 5));
        // z == x == y: doubling.
        let mut c = i64pair(0x8000_0000, 0x1234);
        unsafe { ft_add64(&c, &c, &mut c) };
        assert_eq!(c, i64pair(0, 0x2469));
    }

    /// Exact i64 reference for inputs whose magnitudes stay clear of the
    /// 32-bit wrapping paths: sign * ((|a| * |b| + 0x8000) >> 16).
    /// Reference 64-by-32 division: what the restoring loop computes
    /// wherever its 32-bit remainder cannot overflow, i.e. for every
    /// `divisor <= 0x80000000` — which is every divisor `ft_divfix` and
    /// `ft_muldiv` can hand it, both being `i32` magnitudes.
    fn div64by32_ref(hi: u32, lo: u32, divisor: u32) -> u32 {
        if hi >= divisor {
            return 0x7fff_ffff;
        }
        ((((hi as u64) << 32) | lo as u64) / divisor as u64) as u32
    }

    #[test]
    fn div64by32_matches_exact_division_over_the_callers_domain() {
        let mut s: u32 = 0x2468_ace1;
        let mut rnd = || {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s
        };
        for _ in 0..200_000 {
            // Divisors are i32 magnitudes: 1..=0x80000000.
            let divisor = (rnd() & 0x7fff_ffff).max(1);
            let hi = rnd() % divisor;
            let lo = rnd();
            assert_eq!(
                ft_div64by32(hi, lo, divisor),
                div64by32_ref(hi, lo, divisor),
                "{hi:#010x}:{lo:#010x} / {divisor:#010x}"
            );
        }
        // The magnitude extremes the random sweep will not hit.
        for &divisor in &[1u32, 2, 3, 0x7fff_ffff, 0x8000_0000] {
            for &hi in &[0u32, 1, divisor - 1, divisor / 2] {
                for &lo in &[0u32, 1, 0x8000_0000, 0xffff_ffff] {
                    assert_eq!(
                        ft_div64by32(hi, lo, divisor),
                        div64by32_ref(hi, lo, divisor),
                        "{hi:#010x}:{lo:#010x} / {divisor:#010x}"
                    );
                }
            }
        }
    }

    #[test]
    fn div64by32_clamps_when_the_quotient_would_not_fit() {
        // hi >= divisor, including every divisor of zero.
        assert_eq!(ft_div64by32(1, 0, 1), 0x7fff_ffff);
        assert_eq!(ft_div64by32(0x8000_0000, 0, 0x8000_0000), 0x7fff_ffff);
        assert_eq!(ft_div64by32(0, 0, 0), 0x7fff_ffff);
        assert_eq!(ft_div64by32(0, 12345, 0), 0x7fff_ffff);
        assert_eq!(ft_div64by32(0xffff_ffff, 0xffff_ffff, 0), 0x7fff_ffff);
        // One below the clamp still divides.
        assert_eq!(ft_div64by32(0, 0xffff_ffff, 1), 0xffff_ffff);
        assert_eq!(ft_div64by32(0x7fff_ffff, 0xffff_ffff, 0x8000_0000), 0xffff_ffff);
    }

    #[test]
    fn div64by32_truncates_its_remainder_above_the_i32_magnitude_range() {
        // The quirk: the remainder is one 32-bit register, so `r <<= 1`
        // drops a bit once `divisor > 0x80000000`. Neither caller can
        // get here (both divide by an i32 magnitude), but the symbol
        // does, and it is not 64-by-32 division there.
        assert_eq!(ft_div64by32(0x9000_0000, 0, 0xffff_ffff), 0);
        assert_ne!(
            ft_div64by32(0x9000_0000, 0, 0xffff_ffff),
            div64by32_ref(0x9000_0000, 0, 0xffff_ffff)
        );
        assert_eq!(div64by32_ref(0x9000_0000, 0, 0xffff_ffff), 0x9000_0000);
        // Below the threshold the two agree again.
        assert_eq!(
            ft_div64by32(0x7fff_ffff, 0, 0x8000_0000),
            div64by32_ref(0x7fff_ffff, 0, 0x8000_0000)
        );
    }

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

    const ONE: i32 = 0x10000; // 1.0 in 16.16

    fn mat(xx: i32, xy: i32, yx: i32, yy: i32) -> FtMatrix {
        FtMatrix { xx, xy, yx, yy }
    }

    /// Reference product per the documented FreeType formula, built on
    /// the already-proven ft_mulfix.
    fn matmul_ref(a: FtMatrix, b: FtMatrix) -> FtMatrix {
        mat(
            ft_mulfix(a.xx, b.xx).wrapping_add(ft_mulfix(a.xy, b.yx)),
            ft_mulfix(a.xx, b.xy).wrapping_add(ft_mulfix(a.xy, b.yy)),
            ft_mulfix(a.yx, b.xx).wrapping_add(ft_mulfix(a.yy, b.yx)),
            ft_mulfix(a.yx, b.xy).wrapping_add(ft_mulfix(a.yy, b.yy)),
        )
    }

    #[test]
    fn matrix_multiply_identity_and_scale() {
        let id = mat(ONE, 0, 0, ONE);
        let mut b = mat(0x28000, -0x8000, 0x4000, 0x18000);
        unsafe { ft_matrix_multiply(&id, &mut b) };
        assert_eq!(b, mat(0x28000, -0x8000, 0x4000, 0x18000));
        // 2x scale on the left doubles every cell.
        let two = mat(2 * ONE, 0, 0, 2 * ONE);
        unsafe { ft_matrix_multiply(&two, &mut b) };
        assert_eq!(b, mat(0x50000, -0x10000, 0x8000, 0x30000));
    }

    #[test]
    fn matrix_multiply_matches_reference_grid() {
        let vals = [0, ONE, -ONE, 0x8000, -0x28000, 0x123456, 0x7fffffff];
        for &p in &vals {
            for &q in &vals {
                let a = mat(p, q, q.wrapping_neg(), p);
                let b0 = mat(q, p, p, q.wrapping_neg());
                let mut b = b0;
                unsafe { ft_matrix_multiply(&a, &mut b) };
                assert_eq!(b, matmul_ref(a, b0), "a={a:?} b={b0:?}");
            }
        }
    }

    #[test]
    fn matrix_multiply_aliased_reads_premultiply_values() {
        // a == b: the original finishes all eight products before the
        // first store, so the result is m * m of the original cells.
        let m0 = mat(ONE, 0x8000, -0x4000, 0x20000);
        let mut m = m0;
        unsafe { ft_matrix_multiply(&m, &mut m) };
        assert_eq!(m, matmul_ref(m0, m0));
    }

    #[test]
    fn matrix_multiply_null_is_noop() {
        let mut b = mat(1, 2, 3, 4);
        unsafe {
            ft_matrix_multiply(core::ptr::null(), &mut b);
            ft_matrix_multiply(&b, core::ptr::null_mut());
        }
        assert_eq!(b, mat(1, 2, 3, 4));
    }

    #[test]
    fn matrix_invert_diagonal_and_rotation() {
        // diag(2, 4) inverts to diag(0.5, 0.25).
        let mut m = mat(2 * ONE, 0, 0, 4 * ONE);
        assert_eq!(unsafe { ft_matrix_invert(&mut m) }, 0);
        assert_eq!(m, mat(0x8000, 0, 0, 0x4000));
        // 90-degree rotation [0,-1;1,0] inverts to [0,1;-1,0].
        let mut r = mat(0, -ONE, ONE, 0);
        assert_eq!(unsafe { ft_matrix_invert(&mut r) }, 0);
        assert_eq!(r, mat(0, ONE, -ONE, 0));
    }

    #[test]
    fn matrix_invert_roundtrip_recovers_matrix() {
        let m0 = mat(0x18000, 0x4000, -0x8000, 0x20000);
        let mut m = m0;
        assert_eq!(unsafe { ft_matrix_invert(&mut m) }, 0);
        assert_eq!(unsafe { ft_matrix_invert(&mut m) }, 0);
        // Sanity only (exact per-cell behavior is proven elsewhere):
        // divfix roundings compound through delta, so allow a few ulp.
        for (got, want) in [
            (m.xx, m0.xx),
            (m.xy, m0.xy),
            (m.yx, m0.yx),
            (m.yy, m0.yy),
        ] {
            assert!((got - want).abs() <= 8, "{got:#x} vs {want:#x}");
        }
    }

    #[test]
    fn matrix_invert_singular_returns_error_untouched() {
        // delta == 0: [1,2;2,4] scaled to 16.16.
        let mut m = mat(ONE, 2 * ONE, 2 * ONE, 4 * ONE);
        assert_eq!(unsafe { ft_matrix_invert(&mut m) }, 6);
        assert_eq!(m, mat(ONE, 2 * ONE, 2 * ONE, 4 * ONE));
        assert_eq!(unsafe { ft_matrix_invert(core::ptr::null_mut()) }, 6);
    }

    #[test]
    fn matrix_invert_uses_old_xx_for_new_yy() {
        // yy_new = divfix(xx_old, delta), not the freshly written xx.
        let mut m = mat(0x30000, 0, 0, 0x10000); // delta = 3.0
        assert_eq!(unsafe { ft_matrix_invert(&mut m) }, 0);
        assert_eq!(m.xx, ft_divfix(0x10000, 0x30000)); // 1/3
        assert_eq!(m.yy, ft_divfix(0x30000, 0x30000)); // 3/3 = 1.0
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

    /// Reference FT_MulDiv from the documented FreeType semantics on a
    /// 32-bit machine: sign * ((|a|*|b| + |c|/2) / |c|), quotient
    /// truncated to u32 (so 2^31..2^32 flips sign), clamped to
    /// 0x7fffffff when it needs more than 32 bits or c == 0. Exact for
    /// every input with no i32::MIN operand (those hit the wrapped-abs
    /// bound-check quirks, covered by the asm-model vector tests).
    fn muldiv_ref(a: i32, b: i32, c: i32) -> i64 {
        if a == 0 || b == c {
            return a as i64;
        }
        let neg = (a ^ b ^ c) < 0;
        let (ua, ub, uc) = ((a as i64).abs(), (b as i64).abs(), (c as i64).abs());
        let q: i64 = if uc == 0 {
            0x7fff_ffff
        } else {
            let t = (ua * ub + uc / 2) / uc;
            if t >= 1i64 << 32 {
                0x7fff_ffff
            } else {
                (t as u32) as i32 as i64
            }
        };
        // Sign restore is a 32-bit rsb: negate at i32 width (q always
        // fits — it is a u32 reinterpreted as i32, or the clamp).
        if neg {
            (q as i32).wrapping_neg() as i64
        } else {
            q
        }
    }

    #[test]
    fn muldiv_identity_fast_outs() {
        assert_eq!(ft_muldiv(0, 55, 7), 0);
        assert_eq!(ft_muldiv(123, 99, 99), 123); // b == c
        assert_eq!(ft_muldiv(-123, 0, 0), -123); // b == c == 0 beats clamp
        assert_eq!(ft_muldiv(i32::MIN, 7, 7), i32::MIN);
    }

    #[test]
    fn muldiv_sign_combinations() {
        for (a, b, c, want) in [
            (-100, 50, 3, -0x683),
            (100, -50, 3, -0x683),
            (100, 50, -3, -0x683),
            (-100, -50, -3, -0x683),
            (100, 50, 3, 0x683),
            (-100, -50, 3, 0x683),
        ] {
            assert_eq!(ft_muldiv(a, b, c), want, "ft_muldiv({a}, {b}, {c})");
        }
    }

    #[test]
    fn muldiv_fast_slow_boundary() {
        // 46340*46340 + 176095/2 == 0x7fffffff exactly: the fast path's
        // widest case, and its 176096 neighbor lands in the 64-bit path.
        assert_eq!(ft_muldiv(46340, 46340, 176095), 0x2fa3);
        assert_eq!(ft_muldiv(46341, 46341, 176095), 0x2fa3);
        assert_eq!(ft_muldiv(46340, 46340, 176096), 0x2fa2);
        assert_eq!(ft_muldiv(0x10000, 0x10000, 0x10000), 0x10000);
    }

    #[test]
    fn muldiv_zero_divisor_clamps_with_sign() {
        assert_eq!(ft_muldiv(1000, 2000, 0), 0x7fff_ffff);
        assert_eq!(ft_muldiv(-1000, 2000, 0), -0x7fff_ffff);
        // c == i32::MIN: wrapped |c| stays negative, same clamp path.
        assert_eq!(ft_muldiv(5, 3, i32::MIN), -0x7fff_ffff);
    }

    #[test]
    fn muldiv_overflow_behavior() {
        // Quotient needs > 32 bits: clamp.
        assert_eq!(ft_muldiv(0x40000000, 4, 1), 0x7fff_ffff);
        assert_eq!(ft_muldiv(0x7fffffff, 0x7fffffff, 0x7fffffff), 0x7fff_ffff);
        // Quotient in 2^31..2^32: truncates to u32 and flips sign (the
        // stock unclamped overflow), asm-model verified.
        assert_eq!(ft_muldiv(0x7fffffff, 2, 1), -2);
    }

    #[test]
    fn muldiv_int_min_quirks_match_asm_model() {
        // |i32::MIN| == 0x80000000 is negative as an i32, so it passes
        // the signed "small" bound checks; expected values from an
        // independent Python model of the disassembly.
        assert_eq!(ft_muldiv(i32::MIN, 3, 7), 0x12492491);
        assert_eq!(ft_muldiv(i32::MIN, 2, 0x10000), 0);
        assert_eq!(ft_muldiv(i32::MIN, 46340, 176095), 0);
        assert_eq!(ft_muldiv(i32::MIN, -0x7fffffff, 7), 0x7fff_ffff);
        assert_eq!(ft_muldiv(7, i32::MIN, 3), 0x2aaa_aaaa);
    }

    #[test]
    fn muldiv_matches_reference_on_randomized_inputs() {
        // xorshift32 sweep; i32::MIN operands excluded (quirk tests
        // above own those).
        let mut x: u32 = 0x2468ace1;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for _ in 0..200_000 {
            let (a, b, c) = (rnd() as i32, rnd() as i32, rnd() as i32);
            if a == i32::MIN || b == i32::MIN || c == i32::MIN {
                continue;
            }
            assert_eq!(
                ft_muldiv(a, b, c) as i64,
                muldiv_ref(a, b, c),
                "ft_muldiv({a:#x}, {b:#x}, {c:#x})"
            );
        }
    }

    #[test]
    fn muldiv_matches_reference_on_small_grid() {
        let vals = [
            0, 1, -1, 2, 3, -3, 7, 46339, 46340, 46341, -46340, 0x8000,
            0x10000, -0x10000, 176095, 176096, -176096, 0x123456,
            0x7fffffff, -0x7fffffff,
        ];
        for &a in &vals {
            for &b in &vals {
                for &c in &vals {
                    assert_eq!(
                        ft_muldiv(a, b, c) as i64,
                        muldiv_ref(a, b, c),
                        "ft_muldiv({a:#x}, {b:#x}, {c:#x})"
                    );
                }
            }
        }
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
