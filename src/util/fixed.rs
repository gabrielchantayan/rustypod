//! 16.16 fixed-point and widening integer multiply @ 0x080e9878 / 0x080f0fa4,
//! the software count-leading-zeros @ 0x0824980c that feeds them, the
//! 64-bit round-and-extract @ 0x08076214 that closes dot products, and the
//! guarded reciprocal @ 0x08076204 that divides by a Q16.16 value.
//!
//! Three pure leaf helpers built on the ARMv5TE `smull` (signed 32x32 -> 64)
//! instruction, one bit-scan leaf, one 64-bit rounding leaf, and one guard
//! wrapper. Sizes from decomp/functions.csv; call-site counts from decoding
//! every `b`/`bl` word in osos.dec (osos.asm drops lines):
//!
//! - `fixed16_mul` — `FUN_080e9878` @ 0x080e9878 (20 bytes; 94 call sites).
//! - `mul_wide_i64` — `FUN_080f0fa4` @ 0x080f0fa4 (12 bytes; 49 call sites).
//! - `clz_31` — `FUN_0824980c` @ 0x0824980c (68 bytes; 3 call sites).
//! - `fixed16_round_64` — `FUN_08076214` @ 0x08076214 (20 bytes; 12 sites).
//! - `fixed16_recip` — `FUN_08076204` @ 0x08076204 (16 bytes; 36 sites).
//!
//! All but `fixed16_recip` are leaves and touch no hardware, so host tests
//! against `i64` / `u32::leading_zeros` arithmetic prove complete behavior.
//! `fixed16_recip` tail-branches to the unguarded reciprocal body @
//! 0x080377e4 (an unrolled 32-bit restoring division of 0xffffffff by |x|,
//! sign reapplied), which is not yet ported; it rides a target/host seam
//! (the `app/h264_decode_forwarder.rs` pattern) that invokes the retailOS
//! address on hardware and a recording stub in host tests.
//!
//! `fixed16_mul` is the multiply of retailOS's own Q16.16 fixed-point
//! arithmetic — *not* FreeType's. FreeType's `FT_MulFix`/`ft_muldiv` (see
//! `ft/calc.rs`) bias the product by half an ulp before shifting, so they
//! round to nearest; this one shifts straight out of the `smull` result
//! pair, so it truncates toward negative infinity. The two are not
//! interchangeable and the addresses are unrelated.
//!
//! Its most instructive caller is `FUN_08076154` @ 0x08076154, a Q16.16
//! inverse square root: an 8-entry seed table indexed by three exponent
//! bits, then Newton-Raphson iterations of `y = y * (3 - x*y*y) / 2` — the
//! `rsb r1, r1, #0x30000` there is literally 3.0 in Q16.16. That routine
//! also open-codes this exact `smull`/`lsl`/`orr` idiom inline twice before
//! calling out to it, which is what pins down the semantics.

/// fixed16_mul — original: `FUN_080e9878` @ 0x080e9878 (20 bytes).
///
/// Q16.16 fixed-point multiply: forms the full signed 64-bit product of
/// `a` and `b` with `smull`, then returns bits [47:16] of it — the
/// original assembles them as `(hi << 16) | (lo >> 16)`, which is exactly a
/// 32-bit truncation of `product >> 16`.
///
/// Truncating, not rounding: negative results round toward negative
/// infinity. Products that do not fit in 32 bits after the shift wrap,
/// exactly as the original's register assembly does — there is no clamp.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn fixed16_mul(a: i32, b: i32) -> i32 {
    (((a as i64) * (b as i64)) >> 16) as i32
}

/// clz_31 — original: `FUN_0824980c` @ 0x0824980c (68 bytes).
///
/// Software count-leading-zeros for a 32-bit word, by binary search over
/// half-ranges: start with the answer 31, then for the masks 0xffff0000,
/// 0xff00, 0xf0, 0xc, 0x2 in turn, if the value has any bit in the upper
/// half of the current window subtract that half's width from the answer
/// and shift the value down. ARMv5TE has a `clz` instruction, but ADS
/// 1.0.1 emitted this branchy `movs`/`movne`/`tst`/`subne` sequence —
/// the target predates reliable `clz` codegen and the routine also runs
/// on the zero input where `clz` is the identity anyway.
///
/// The zero-input quirk: a hardware `clz` of 0 yields 32; this routine
/// yields 31, because the first `movs r2, r0, lsr #0x10` test fails and
/// every subsequent `tst` fails, leaving the initial 0x1f untouched.
/// Callers rely on it — `fixed16_rsqrt` @ 0x08076154 computes
/// `idx = (x >> (28 - lz)) & 7` and `e = lz - 16` from the result, where
/// a 32 would break the seed-table index. For every nonzero input the
/// result equals `x.leading_zeros()`.
///
/// 3 bl call sites: 0x08076170 (`fixed16_rsqrt`), 0x082417e8 and
/// 0x08242530.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn clz_31(x: u32) -> u32 {
    let mut lz = 31u32;
    let mut v = x;
    if v >> 16 != 0 {
        lz = 15;
        v >>= 16;
    }
    if v & 0xff00 != 0 {
        lz -= 8;
        v >>= 8;
    }
    if v & 0xf0 != 0 {
        lz -= 4;
        v >>= 4;
    }
    if v & 0xc != 0 {
        lz -= 2;
        v >>= 2;
    }
    if v & 0x2 != 0 {
        lz -= 1;
    }
    lz
}

/// mul_wide_i64 — original: `FUN_080f0fa4` @ 0x080f0fa4 (12 bytes).
///
/// Signed widening multiply: the full 64-bit product of two 32-bit
/// operands, returned in r0 (low) : r1 (high) per AAPCS. The original is
/// a bare `smull ip, r1, r0, r1` plus the `mov r0, ip` needed to land the
/// low word in the return register.
///
/// Callers use it as the multiply of a 64-bit-accumulated dot product —
/// e.g. `FUN_082a01e4` multiplies four field pairs and sums the results
/// with `adds`/`adc`.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn mul_wide_i64(a: i32, b: i32) -> i64 {
    (a as i64) * (b as i64)
}

/// fixed16_round_64 — original: `FUN_08076214` @ 0x08076214 (20 bytes).
///
/// Round-to-nearest extraction of a 64-bit fixed-point accumulator to
/// 32-bit Q16.16: add half an ulp (`0x8000`) to the full 64-bit value
/// with carry propagation across the word boundary (`adds`/`adc`), then
/// return bits [47:16] of the sum — the original assembles them as
/// `(hi << 16) | (lo >> 16)`, which is exactly a 32-bit truncation of
/// `(acc + 0x8000) >> 16`. Ties go toward positive infinity (round half
/// up, in the `floor(acc + 1/2)` sense), negative fractions included;
/// results that do not fit in 32 bits after the shift wrap — there is
/// no clamp, exactly as the original's register assembly wraps.
///
/// This is the rounding counterpart to `fixed16_mul`'s truncation: every
/// one of its 12 call sites (11 `bl` plus one tail `b` at 0x082a0254)
/// sits at the end of a `mul_wide_i64` dot-product chain in the 0x082a
/// geometry code — e.g. `FUN_082a1368`/`FUN_082a05d4` are 4x4
/// matrix-times-vector transforms that `adds`/`adc` four Q16.16 products
/// into a 64-bit accumulator and round it here to a Q16.16 coordinate.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn fixed16_round_64(acc: i64) -> i32 {
    (acc.wrapping_add(0x8000) >> 16) as i32
}

/// ABI of the unguarded reciprocal body at retailOS address `0x080377e4`.
pub type Fixed16RecipUnguarded = unsafe extern "C" fn(i32) -> i32;

/// RetailOS load address of the unguarded reciprocal body.
pub const FIXED16_RECIP_UNGUARDED_ADDRESS: usize = 0x0803_77e4;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_fixed16_recip_unguarded(x: i32) -> i32 {
    let body: Fixed16RecipUnguarded = core::mem::transmute(FIXED16_RECIP_UNGUARDED_ADDRESS);
    body(x)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_fixed16_recip_unguarded(_x: i32) -> i32 {
    panic!("fixed16_recip requires unguarded body 0x080377e4")
}

/// Active boundary for the unported unguarded reciprocal body @ 0x080377e4.
/// On the target it calls directly into retailOS; host tests replace it with
/// a recording implementation.
#[cfg(target_os = "none")]
pub static mut FIXED16_RECIP_UNGUARDED: Fixed16RecipUnguarded = retail_fixed16_recip_unguarded;

/// Active host boundary for the unported unguarded reciprocal body.
#[cfg(not(target_os = "none"))]
pub static mut FIXED16_RECIP_UNGUARDED: Fixed16RecipUnguarded = missing_fixed16_recip_unguarded;

/// Volatile read so LLVM cannot fold the default in and delete the dispatch
/// (the `app/h264_decode_forwarder.rs` rationale).
#[inline(always)]
fn fixed16_recip_unguarded(x: i32) -> i32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(FIXED16_RECIP_UNGUARDED))(x) }
}

/// fixed16_recip — original: `FUN_08076204` @ 0x08076204 (16 bytes).
///
/// Guarded Q16.16 reciprocal, `1 / x`. A zero input returns `0x7fff_ffff`
/// (i32::MAX — the original's `mvneq r0, #0x80000000` materializes the
/// bitwise NOT of `0x80000000`); any nonzero input tail-branches (`b`, not
/// `bl`) unchanged to the unguarded body @ 0x080377e4, which negates `x`
/// into |x| (keeping the sign in r3), counts `clz(|x|)`, and jumps into an
/// unrolled 32-bit restoring division of `0xffff_ffff` by |x| at the entry
/// for quotient bit `31 - clz(|x|)`, negating the quotient when `x` was
/// negative. The dividend is `2^32 - 1` rather than `2^32` because `2^32`
/// does not fit in a register, so the result is the Q16.16 reciprocal
/// truncated one ulp low; the zero guard is the saturation of `1 / 0`.
///
/// Callers treat the result as a divisor inverse: all 36 call sites (35
/// `bl` plus one tail `b`) sit in the 0x082a geometry / 0x0824 transform
/// code and multiply the result into Q16.16 values with `fixed16_mul` or
/// its open-coded idiom — e.g. `FUN_082a0920` is Gaussian elimination that
/// scales a pivot row by `recip(pivot)`, and `FUN_082a06d4` normalizes a
/// 3x3 matrix by its bottom-right term.
///
/// The body @ 0x080377e4 is a separate function and is NOT ported here;
/// it remains behind the [`FIXED16_RECIP_UNGUARDED`] target/host seam.
/// The original's tail `b` becomes a plain call returning the seam's
/// result unchanged; LLVM decides whether to keep it a tail call (the
/// `app/message_arena.rs` precedent).
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn fixed16_recip(x: i32) -> i32 {
    if x == 0 { 0x7fff_ffff } else { fixed16_recip_unguarded(x) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One Q16.16 unit.
    const ONE: i32 = 0x0001_0000;

    #[test]
    fn fixed16_mul_identity_and_sign() {
        assert_eq!(fixed16_mul(ONE, ONE), ONE);
        assert_eq!(fixed16_mul(ONE, -ONE), -ONE);
        assert_eq!(fixed16_mul(-ONE, -ONE), ONE);
        assert_eq!(fixed16_mul(0, ONE), 0);
        assert_eq!(fixed16_mul(ONE, 0), 0);
        // 2.5 * 4.0 = 10.0
        assert_eq!(fixed16_mul(5 * ONE / 2, 4 * ONE), 10 * ONE);
        // 0.5 * 0.5 = 0.25
        assert_eq!(fixed16_mul(ONE / 2, ONE / 2), ONE / 4);
    }

    /// The defining property, over a grid that crosses zero and both
    /// halves of the 32-bit range: the result is a 32-bit truncation of
    /// the arithmetic-shifted 64-bit product.
    #[test]
    fn fixed16_mul_matches_i64_reference() {
        let values = [
            0i32,
            1,
            -1,
            ONE,
            -ONE,
            0x7fff,
            -0x8000,
            0x0001_2345,
            -0x0001_2345,
            0x00ff_ffff,
            0x7fff_ffff,
            -0x8000_0000,
            0x4000_0000,
            -0x4000_0000,
            0x0002_0000,
            0x5555_5555,
            -0x5555_5555,
        ];
        for &a in &values {
            for &b in &values {
                let want = (((a as i64) * (b as i64)) >> 16) as i32;
                assert_eq!(fixed16_mul(a, b), want, "a={a:#x} b={b:#x}");
            }
        }
    }

    /// The port must reproduce the original's register assembly exactly:
    /// `(hi << 16) | (lo >> 16)` over the smull result pair.
    #[test]
    fn fixed16_mul_equals_the_original_register_assembly() {
        for &(a, b) in &[
            (0x1234_5678i32, 0x0000_1000i32),
            (-0x1234_5678, 0x0000_1000),
            (0x7fff_ffff, 0x7fff_ffff),
            (-0x8000_0000, -0x8000_0000),
            (-0x8000_0000, 1),
            (0x0001_0001, -0x0001_0001),
            (3, -1),
        ] {
            let product = (a as i64).wrapping_mul(b as i64) as u64;
            let lo = product as u32;
            let hi = (product >> 32) as u32;
            let want = ((hi << 16) | (lo >> 16)) as i32;
            assert_eq!(fixed16_mul(a, b), want, "a={a:#x} b={b:#x}");
        }
    }

    /// Truncation toward negative infinity, not round-to-nearest — the
    /// distinction from FreeType's `FT_MulFix`.
    #[test]
    fn fixed16_mul_truncates_it_does_not_round() {
        // 1 * 1 in Q16.16 is 2^-32, which truncates to 0 either way.
        assert_eq!(fixed16_mul(1, 1), 0);
        // A product of exactly half an ulp: 0x8000 * 0x10000 >> 16 = 0x8000.
        assert_eq!(fixed16_mul(0x8000, ONE), 0x8000);
        // 0x18000 * 0x18000 = 0x2_40000000; >> 16 = 0x24000 (2.25). Exact.
        assert_eq!(fixed16_mul(0x0001_8000, 0x0001_8000), 0x0002_4000);
        // Negative fractions floor rather than truncate toward zero:
        // -1 * 1 = -1, and -1 >> 16 = -1, not 0.
        assert_eq!(fixed16_mul(-1, 1), -1);
        assert_eq!(fixed16_mul(-1, 0xffff), -1);
    }

    /// No clamping: results that overflow 32 bits after the shift wrap.
    #[test]
    fn fixed16_mul_wraps_on_overflow() {
        // 0x7fffffff * 0x7fffffff >> 16 keeps bits [47:16], which wraps.
        let a = 0x7fff_ffffi32;
        let want = (((a as i64) * (a as i64)) >> 16) as i32;
        assert_eq!(fixed16_mul(a, a), want);
        assert_ne!(fixed16_mul(a, a), i32::MAX, "no saturation, unlike ft_muldiv");
    }

    #[test]
    fn mul_wide_i64_matches_i64_reference() {
        let values = [
            0i32,
            1,
            -1,
            2,
            -2,
            0x7fff,
            -0x8000,
            0x0001_0000,
            0x7fff_ffff,
            -0x8000_0000,
            0x1234_5678,
            -0x1234_5678,
            0x5555_5555,
            -0x5555_5555,
        ];
        for &a in &values {
            for &b in &values {
                assert_eq!(mul_wide_i64(a, b), (a as i64) * (b as i64), "a={a:#x} b={b:#x}");
            }
        }
    }

    /// The widening product is genuinely 64-bit — the extremes cannot fit
    /// in 32 bits and must not be truncated.
    #[test]
    fn mul_wide_i64_keeps_the_high_word() {
        assert_eq!(mul_wide_i64(i32::MAX, i32::MAX), 0x3fff_ffff_0000_0001);
        assert_eq!(mul_wide_i64(i32::MIN, i32::MIN), 0x4000_0000_0000_0000);
        assert_eq!(mul_wide_i64(i32::MIN, 1), -0x8000_0000);
        assert_eq!(mul_wide_i64(-1, i32::MIN), 0x8000_0000);
        assert_eq!(mul_wide_i64(0x1_0000, 0x1_0000), 0x1_0000_0000);
    }

    /// `fixed16_mul` is `mul_wide_i64` shifted right 16 and truncated —
    /// the relationship the ADS codegen makes explicit.
    #[test]
    fn fixed16_mul_is_mul_wide_shifted() {
        for a in [-0x7fff_0000i32, -1, 0, 1, 0x1234, 0x7fff_0000] {
            for b in [-0x10_0000i32, -3, 0, 3, 0x10_0000, 0x7fff_ffff] {
                assert_eq!(fixed16_mul(a, b), (mul_wide_i64(a, b) >> 16) as i32);
            }
        }
    }

    /// The zero-input edge case that names the function: 31, not the 32
    /// a hardware `clz` (or `u32::leading_zeros`) would give.
    #[test]
    fn clz_31_zero_input_returns_31_not_32() {
        assert_eq!(clz_31(0), 31);
        assert_ne!(clz_31(0), 0u32.leading_zeros());
    }

    /// Every boundary of the binary search: each mask edge, each
    /// single-bit value, and the range extremes.
    #[test]
    fn clz_31_single_bits_and_mask_edges() {
        for bit in 0..32 {
            assert_eq!(clz_31(1u32 << bit), 31 - bit, "bit {bit}");
        }
        assert_eq!(clz_31(0x8000_0000), 0);
        assert_eq!(clz_31(0xffff_ffff), 0);
        assert_eq!(clz_31(0x0001_0000), 15);
        assert_eq!(clz_31(0x0000_ffff), 16);
        assert_eq!(clz_31(0x0000_ff00), 16);
        assert_eq!(clz_31(0x0000_00ff), 24);
        assert_eq!(clz_31(0x0000_00f0), 24);
        assert_eq!(clz_31(0x0000_000c), 28);
        assert_eq!(clz_31(0x0000_0002), 30);
        assert_eq!(clz_31(0x0000_0001), 31);
    }

    /// For all nonzero inputs the result is exactly
    /// `u32::leading_zeros`; zero is the lone exception. Sweep a dense
    /// low range, every power of two and its neighbors, and patterned
    /// values crossing each search boundary.
    #[test]
    fn clz_31_matches_leading_zeros_reference() {
        let mut check = |x: u32| {
            let want = if x == 0 { 31 } else { x.leading_zeros() };
            assert_eq!(clz_31(x), want, "x={x:#010x}");
        };
        for x in 0..=0x1_0000u32 {
            check(x);
        }
        for bit in 0..32 {
            let p = 1u32 << bit;
            check(p.wrapping_sub(1));
            check(p);
            check(p + 1);
            check(p | (p >> 1));
            check(0xffff_ffffu32 << bit);
        }
        for &x in &[
            0x1234_5678u32,
            0x8765_4321,
            0x5555_5555,
            0xaaaa_aaaa,
            0x00ff_ff00,
            0x0f0f_0f0f,
            0xf0f0_f0f0,
            0x7fff_ffff,
        ] {
            check(x);
        }
    }

    /// The semantics `fixed16_rsqrt` @ 0x08076154 depends on: for every
    /// input that reaches it (`x != 0` returns early there) the seed
    /// index `(x >> (28 - lz)) & 7` stays in 0..=7 — a lz of 32 would
    /// wrap the shift amount. (For x < 8 the shift amount is negative;
    /// ARM register-shift semantics yield 0, i.e. index 0, which is in
    /// range too.)
    #[test]
    fn clz_31_keeps_rsqrt_seed_index_in_range() {
        for x in 1..=0x1_0000u32 {
            let lz = clz_31(x);
            if lz <= 28 {
                let idx = (x >> (28 - lz)) & 7;
                assert!(idx <= 7, "x={x:#x} idx={idx}");
            }
        }
    }

    /// The original's register assembly, computed bit by bit:
    /// `(hi << 16) | (lo >> 16)` over the `adds`/`adc`-incremented pair.
    fn round_64_register_assembly(acc: i64) -> i32 {
        let bits = (acc as u64).wrapping_add(0x8000);
        let lo = bits as u32;
        let hi = (bits >> 32) as u32;
        ((hi << 16) | (lo >> 16)) as i32
    }

    #[test]
    fn fixed16_round_64_identity_values() {
        // 1.0 in the accumulator (Q16.16 value shifted left 16) -> 1.0 out.
        assert_eq!(fixed16_round_64(0x0000_0001_0000_0000), ONE);
        assert_eq!(fixed16_round_64(-0x0000_0001_0000_0000), -ONE);
        assert_eq!(fixed16_round_64(0), 0);
        // 2.5 -> 2.5, exact values pass through unchanged.
        assert_eq!(fixed16_round_64(0x0000_0002_8000_0000), 5 * ONE / 2);
    }

    /// Half-ulp ties go up (toward positive infinity); just below half
    /// truncates down. This is the distinction from `fixed16_mul`.
    #[test]
    fn fixed16_round_64_rounds_half_up() {
        // +0.5 ulp exactly -> rounds up to 1.
        assert_eq!(fixed16_round_64(0x8000), 1);
        // Just under half -> 0.
        assert_eq!(fixed16_round_64(0x7fff), 0);
        assert_eq!(fixed16_round_64(0x8001), 1);
        // -0.5 ulp exactly -> ties toward +inf land on 0, not -1.
        assert_eq!(fixed16_round_64(-0x8000), 0);
        // Just past -0.5 ulp -> -1.
        assert_eq!(fixed16_round_64(-0x8001), -1);
        assert_eq!(fixed16_round_64(-0x7fff), 0);
    }

    /// The `adds`/`adc` pair: adding 0x8000 to a low word of 0xffff8000
    /// carries into the high word, and the extraction must see it.
    #[test]
    fn fixed16_round_64_carry_crosses_word_boundary() {
        // hi=0, lo=0xffff_8000: +0x8000 wraps lo to 0 and carries 1 ->
        // bits [47:16] of 0x1_0000_0000 = 0x1_0000 = 1.0.
        assert_eq!(fixed16_round_64(0x0000_0000_ffff_8000), ONE);
        // Without the carry the answer would be 0xffff; the carry into
        // the high word is what makes the high-word extraction see it.
        assert_eq!(fixed16_round_64(0x0000_0000_ffff_7fff), 0xffff);
        // Negative high word: hi=-1, lo=0xffff_8000 -> acc=-0x8000,
        // +0x8000 = 0 exactly (carry propagates hi -1 -> 0).
        assert_eq!(fixed16_round_64(-0x8000), 0);
        // hi=-1 (0xffff_ffff), lo=0xffff_7fff: no carry, result keeps
        // the sign-extended high bits.
        assert_eq!(fixed16_round_64(-0x8001), -1);
    }

    /// The result is bits [47:16] — the high word's low half lands in
    /// the result's high half, and bits above 47 are discarded (wrap).
    #[test]
    fn fixed16_round_64_high_word_extraction_and_wrap() {
        // acc = 0x1234_5678_9abc_def0: +0x8000 stays within the low
        // word (0x9abd_5ef0, no carry), so bits [47:16] = 0x5678_9abd.
        assert_eq!(fixed16_round_64(0x1234_5678_9abc_def0), 0x5678_9abd);
        // Bits [63:48] never appear: 0x00xx and 0xffxx high bytes give
        // the same low-32 result modulo sign of the shifted value.
        assert_eq!(
            fixed16_round_64(0x00aa_bbcc_ddee_0000),
            fixed16_round_64(0x11aa_bbcc_ddee_0000)
        );
        // i64::MAX wraps on the add, exactly as adds/adc wrap.
        assert_eq!(fixed16_round_64(i64::MAX), round_64_register_assembly(i64::MAX));
        assert_eq!(fixed16_round_64(i64::MIN), round_64_register_assembly(i64::MIN));
    }

    /// The defining property over a grid crossing zero, both word
    /// boundaries and the carry edge: equality with the original's
    /// register assembly, computed independently.
    #[test]
    fn fixed16_round_64_matches_register_assembly_reference() {
        let his = [
            0u32,
            1,
            0xffff_ffff,
            0xffff_0000,
            0x0000_ffff,
            0x8000_0000,
            0x7fff_ffff,
            0x1234_5678,
            0xdead_beef,
        ];
        let los = [
            0u32,
            1,
            0x7fff,
            0x8000,
            0x8001,
            0xffff_7fff,
            0xffff_8000,
            0xffff_ffff,
            0x9abc_def0,
        ];
        for &hi in &his {
            for &lo in &los {
                let acc = (((hi as u64) << 32) | lo as u64) as i64;
                assert_eq!(
                    fixed16_round_64(acc),
                    round_64_register_assembly(acc),
                    "acc={acc:#018x}"
                );
            }
        }
    }

    /// The call-site idiom: four `mul_wide_i64` products summed with
    /// adds/adc, then rounded here — the rounding counterpart to
    /// `fixed16_mul`'s truncation, never off by more than one ulp.
    #[test]
    fn fixed16_round_64_rounds_mul_wide_dot_products() {
        let values = [
            0i32,
            1,
            -1,
            ONE,
            -ONE,
            5 * ONE / 2,
            -5 * ONE / 2,
            0x0001_2345,
            -0x0001_2345,
            0x7fff_ffff,
            -0x8000_0000,
        ];
        for &a in &values {
            for &b in &values {
                let acc = mul_wide_i64(a, b);
                let rounded = fixed16_round_64(acc);
                let truncated = fixed16_mul(a, b);
                assert_eq!(rounded, ((acc + 0x8000) >> 16) as i32, "a={a:#x} b={b:#x}");
                let diff = (rounded as i64 - truncated as i64).abs();
                assert!(diff <= 1, "a={a:#x} b={b:#x} diff={diff}");
                // A product that is exact in Q16.16 rounds to itself.
                if acc & 0xffff == 0 {
                    assert_eq!(rounded, truncated);
                }
            }
        }
    }

    extern crate std;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes the tests that swap the unguarded-body seam (the
    /// h264_decode_forwarder.rs FORWARDER_LOCK precedent).
    static RECIP_LOCK: Mutex<()> = Mutex::new(());
    static mut RECIP_RECEIVED: Vec<i32> = Vec::new();
    static mut RECIP_RETURN: i32 = 0;

    unsafe extern "C" fn recording_fixed16_recip_unguarded(x: i32) -> i32 {
        RECIP_RECEIVED.push(x);
        RECIP_RETURN
    }

    /// Faithful model of the unported body @ 0x080377e4, recovered from its
    /// raw disassembly: unsigned restoring division of 0xffff_ffff by |x|,
    /// quotient negated when x is negative (x = i32::MIN wraps its magnitude
    /// to 0x8000_0000, exactly as the original's rsbmi does).
    unsafe extern "C" fn reference_fixed16_recip_unguarded(x: i32) -> i32 {
        let magnitude = if x < 0 { (x as u32).wrapping_neg() } else { x as u32 };
        let quotient = 0xffff_ffffu32 / magnitude;
        if x < 0 { (quotient as i32).wrapping_neg() } else { quotient as i32 }
    }

    struct RecipReset;

    impl Drop for RecipReset {
        fn drop(&mut self) {
            unsafe {
                FIXED16_RECIP_UNGUARDED = missing_fixed16_recip_unguarded;
                RECIP_RECEIVED = Vec::new();
                RECIP_RETURN = 0;
            }
        }
    }

    /// The guard itself: x == 0 returns 0x7fffffff (the original's
    /// `mvneq r0, #0x80000000`) without touching the unguarded body.
    #[test]
    fn fixed16_recip_zero_returns_i32_max_without_calling_the_body() {
        let _lock = RECIP_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = RecipReset;
        unsafe {
            FIXED16_RECIP_UNGUARDED = recording_fixed16_recip_unguarded;
            assert_eq!(fixed16_recip(0), 0x7fff_ffff);
            assert_eq!(fixed16_recip(0), i32::MAX);
            assert!(RECIP_RECEIVED.is_empty(), "zero input must not reach the body");
        }
    }

    /// Every nonzero input forwards unchanged to the body and returns its
    /// result unchanged — the original's tail `b` is transparent both ways.
    #[test]
    fn fixed16_recip_forwards_nonzero_inputs_unchanged() {
        let _lock = RECIP_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = RecipReset;
        let values = [
            1i32,
            -1,
            2,
            -2,
            ONE,
            -ONE,
            0x7fff,
            -0x8000,
            0x0001_2345,
            -0x0001_2345,
            0x7fff_ffff,
            -0x8000_0000,
            0x1234_5678,
            -0x1234_5678,
        ];
        unsafe {
            FIXED16_RECIP_UNGUARDED = recording_fixed16_recip_unguarded;
            RECIP_RETURN = 0x5a5a_5a5a;
            for &x in &values {
                assert_eq!(fixed16_recip(x), 0x5a5a_5a5a, "x={x:#x}");
            }
            assert_eq!(RECIP_RECEIVED, values, "arguments forwarded in order, unmodified");
        }
    }

    /// Call-site sanity against the recovered body semantics: with the
    /// reference model wired in, the composite is the Q16.16 reciprocal
    /// (one ulp low from the 2^32 - 1 dividend), so `fixed16_mul(x,
    /// recip(x))` lands within a couple ulps of 1.0 — the normalization
    /// idiom FUN_082a06d4 / FUN_082a0920 rely on.
    #[test]
    fn fixed16_recip_is_the_q16_reciprocal_callers_expect() {
        let _lock = RECIP_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = RecipReset;
        unsafe {
            FIXED16_RECIP_UNGUARDED = reference_fixed16_recip_unguarded;
            // recip(1.0) = 0xffff_ffff / 0x1_0000 = 0xffff — one ulp under 1.0.
            assert_eq!(fixed16_recip(ONE), 0xffff);
            // recip(2.0) = 0x7fff, half of 1.0 one ulp low.
            assert_eq!(fixed16_recip(2 * ONE), 0x7fff);
            // Sign handling: recip(-2.0) = -0x7fff.
            assert_eq!(fixed16_recip(-2 * ONE), -0x7fff);
            // The division idiom: x * recip(x) ~= 1.0 for exact powers.
            // The quotient's truncation costs up to one ulp of the
            // reciprocal, i.e. up to |x| / 2^16 ulps of the product.
            for &x in &[ONE / 4, ONE / 2, ONE, 2 * ONE, 4 * ONE, 0x100 * ONE] {
                let product = fixed16_mul(x, fixed16_recip(x));
                let tolerance = (x as i64 / ONE as i64) + 2;
                assert!((ONE as i64 - product as i64).abs() <= tolerance,
                    "x={x:#x} product={product:#x}");
                let neg = fixed16_mul(-x, fixed16_recip(-x));
                assert_eq!(neg, product, "x={x:#x}");
            }
            // Zero stays saturated even with a live body behind it.
            assert_eq!(fixed16_recip(0), 0x7fff_ffff);
        }
    }
}
