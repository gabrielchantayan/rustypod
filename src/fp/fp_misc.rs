//! Port of the ARM ADS 1.0.1 soft-float square-root core and the
//! remainder core used by `__kernel_rem_pio2`.
//!
//! retailOS is SOFT-FLOAT: doubles travel as u64 bit patterns (r0:r1
//! register pairs). This module does pure integer bit manipulation — no
//! f64 arithmetic, which would lower to unported __aeabi_d* helpers.
//! Variable 64-bit shifts are done as u32-limb shifts so LLVM never
//! emits __aeabi_llsl/__aeabi_lsrl calls.
//!
//! `_dsqrt` — original: `FUN_083ebf28` @ 0x083ebf28 (348 bytes).
//! Correctly rounded double square root. Exponent is adjusted by
//! ((e + 253) >> 1) + 384 with the mantissa doubled when (e + 253) is
//! odd, then a shift-subtract (digit recurrence) root loop extracts
//! 29 high root bits into the top word and 23 more into the low word,
//! finishing with round-to-nearest-even from a round bit plus sticky
//! (remainder nonzero). Result is EXACTLY rounded — host f64::sqrt is
//! a perfect oracle.
//!
//! `__dmod` — original: `FUN_083ebc48` @ 0x083ebc48 (484 bytes).
//! Called only from the __kernel_rem_pio2 region (bl sites
//! 0x08033d30/68/84). IMPORTANT: despite the traditional name, this is
//! NOT fmod. It computes the IEEE 754 `remainder()` — the quotient is
//! rounded to NEAREST (ties to even), not truncated. Verified against
//! host libm remainder() on 20k+ random cases and all tie cases; it
//! diverges from fmod on ~25% of random inputs (e.g. dmod(5.5, 2.0) =
//! -0.5 where fmod gives +1.5). The core keeps both significands
//! normalized, subtracts |a_sig - b_sig|, negating and flipping a sign
//! track bit on borrow, renormalizes (chunked clz on the rare deep
//! path, single shifts otherwise) and repeats while a_exp >= b_exp;
//! the tail handles the final half-way comparison including the
//! round-half-even tie flip.
//!
//! `iabs` — original: `FUN_080e9788` @ 0x080e9788 (12 bytes).
//! Plain 32-bit integer absolute value: `cmp r0,#0; rsblt r0,r0,#0;
//! bx lr`. The rsb computes `0 - x` in 32 bits, so iabs(INT_MIN) wraps
//! back to INT_MIN (mirrored with wrapping_neg). 3 bl call sites
//! (0x08241e4c/0x08241e58 in FUN_08241acc, 0x082424cc in FUN_0824039c),
//! all in 0x0824xxxx graphics-region code that compares two |deltas|
//! and keeps the larger. The two immediately following functions
//! 0x080e9794 and 0x080e97a0 are byte-identical duplicate emissions
//! (all 12 bytes verified against osos.dec). Both are aliases with
//! their own ledger entries: no separate Rust symbols, hooks point at
//! the single `iabs` (the load_be32 alias precedent). 0x080e9794 has
//! 6 bl sites in 0x0824xxxx graphics code; 0x080e97a0 has 12 bl sites
//! in the 0x082axxxx fixed-point matrix routine FUN_082a0920, which
//! compares |entries| and keeps the largest magnitude.
//!
//! Behavioral deviations from IEEE 754, mirrored from the original:
//! - _dsqrt: denormal inputs flush to +0 (even negative denormals;
//!   -0.0 returns -0.0). sqrt(NaN) returns the canonical quiet NaN
//!   0x7ff80000_00000000 (payload/sign dropped, via the shared
//!   exception stub @ 0x083ed080 which returns immediately for error
//!   descriptor 0x04000017). sqrt of a negative finite or -Inf returns
//!   the NaN 0x7ff80000_00000001 (NOT the canonical NaN — r0 is loaded
//!   with 1 in that tail). sqrt(+Inf) = +Inf.
//! - __dmod: any NaN input returns the canonical quiet NaN
//!   0x7ff80000_00000000 (error descriptor 0x04000015, no traps).
//!   +-Inf % finite and Inf % Inf return the NaN 0x7ff80000_00000001.
//!   finite % +-Inf returns the finite dividend unchanged. A zero or
//!   denormal DIVISOR returns the NaN 0x7ff80000_00000001 (denormal
//!   divisor flushes to zero first). A denormal dividend flushes to
//!   +0; +-0 % normal preserves the signed zero. A result whose
//!   exponent underflows (would-be denormal remainder) flushes to +0.
//!
//! Behavioral verification: host-side `cargo test` compares _dsqrt
//! against native aarch64 f64::sqrt (correctly rounded oracle) and
//! __dmod against host libm remainder() (exact operation), plus
//! directed tests pinning the deviations above; `tools/match.py`
//! (ipod-decomp) reports the mnemonic-level diff against the original
//! machine code.

/// Canonical quiet NaN (hi 0x7ff80000, lo 0): NaN inputs to either core.
const QNAN: u64 = 0x7ff8_0000_0000_0000;
/// Quiet NaN with low word 1: sqrt(negative)/sqrt(-Inf) and
/// __dmod's Inf % x / x % 0 results (the original loads r0 with 1).
const QNAN_LO1: u64 = 0x7ff8_0000_0000_0001;

/// _dsqrt — original @ 0x083ebf28. Double square root, soft-float
/// bit pattern in/out. Correctly rounded (round-to-nearest-even).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _dsqrt(x: u64) -> u64 {
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    let exp_field = hi & 0x7ff0_0000;

    if exp_field == 0 {
        // Zero or denormal: +-0 returns unchanged (sqrt(-0) = -0);
        // any nonzero denormal flushes to +0 (sign not tested here).
        if (hi << 12) | lo == 0 {
            return x;
        }
        return 0;
    }
    if exp_field == 0x7ff0_0000 {
        // Inf/NaN: NaN input -> canonical qNaN (exception stub tail);
        // +Inf returns unchanged; -Inf -> qNaN with low word 1.
        if (hi << 12) | lo != 0 {
            return QNAN;
        }
        if hi & 0x8000_0000 == 0 {
            return x;
        }
        return QNAN_LO1;
    }
    if hi & 0x8000_0000 != 0 {
        // Negative finite -> qNaN with low word 1.
        return QNAN_LO1;
    }

    // Split exponent and 53-bit significand (hidden bit restored).
    let biased_exp = hi >> 20;
    let mut sig = (x & 0x000f_ffff_ffff_ffff) | 0x0010_0000_0000_0000;
    let halved = biased_exp + 253;
    if halved & 1 != 0 {
        // Odd exponent: double the mantissa first (root exponent even).
        sig <<= 1;
    }
    let out_exp = ((halved >> 1) + 384) as u64;

    // Remainder register: sig scaled so the root emerges aligned to
    // bit 52; sig >= 2^52 so this never underflows.
    let mut rem = (sig << 10) - (1u64 << 62);
    let mut root: u64 = 0x4000_0000u64 << 32;

    // First root loop: 29 iterations extract the high root word
    // (root low word stays 0, so trials live entirely in the top half).
    let mut bit: u64 = 0x1000_0000;
    while bit != 0 {
        let trial = root + (bit << 32);
        if rem >= trial {
            rem -= trial;
            root += bit << 33;
        }
        rem <<= 1;
        bit >>= 1;
    }
    // One refinement step straddling the word boundary (root low = 0).
    let trial = root + 0x8000_0000;
    if rem >= trial {
        rem -= trial;
        root += 1u64 << 32;
    }
    rem <<= 1;

    // Second root loop: 23 iterations extract the low root word.
    let mut bit: u64 = 0x4000_0000;
    loop {
        let trial = root + bit;
        if rem >= trial {
            rem -= trial;
            root += bit << 1;
        }
        rem <<= 1;
        bit >>= 1;
        if bit == 0x80 {
            break;
        }
    }

    // Round to nearest even: round bit = root bit 9, sticky = leftover.
    let sticky = rem != 0;
    let round = (root >> 9) & 1 != 0;
    let mut result = (root >> 10) + (out_exp << 52);
    if round || sticky {
        result += round as u64;
        if !sticky {
            result &= !1; // exact tie: round to even
        }
    }
    result
}

/// __dmod — original @ 0x083ebc48. IEEE 754 remainder core (NOT fmod:
/// the quotient rounds to nearest, ties to even). Soft-float bit
/// patterns in/out. Exact operation — host libm remainder() oracle.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __dmod(a: u64, b: u64) -> u64 {
    let a_hi = (a >> 32) as u32;
    let a_lo = a as u32;
    let b_hi = (b >> 32) as u32;
    let b_lo = b as u32;
    // Exponent fields in "<<16" units (the original keeps (hi >> 4) &
    // 0x07ff0000 so exponent arithmetic mixes with sign-track bits).
    const EXP_SHIFTED_MASK: u32 = 0x07ff_0000;
    let a_exp = (a_hi >> 4) & EXP_SHIFTED_MASK;
    let b_exp = (b_hi >> 4) & EXP_SHIFTED_MASK;

    if a_exp == EXP_SHIFTED_MASK || b_exp == EXP_SHIFTED_MASK {
        // Inf/NaN involved. NaN anywhere -> canonical qNaN.
        let a_nan = a_exp == EXP_SHIFTED_MASK && ((a_hi & 0x000f_ffff) | a_lo) != 0;
        let b_nan = b_exp == EXP_SHIFTED_MASK && ((b_hi & 0x000f_ffff) | b_lo) != 0;
        if a_nan || b_nan {
            return QNAN;
        }
        if a_exp == EXP_SHIFTED_MASK {
            // +-Inf % anything -> qNaN with low word 1.
            return QNAN_LO1;
        }
        // b = +-Inf, a finite: normal a returns unchanged; +-0 returns
        // unchanged; denormal a flushes to +0.
        if a_exp != 0 || (a_hi & 0x7fff_ffff) | a_lo == 0 {
            return a;
        }
        return 0;
    }

    // Sign track: bit 0 = running result sign (flipped whenever the
    // remainder is negated), bit 2 = sign of a (used for zero results).
    let a_negative = a_hi & 0x8000_0000 != 0;
    let mut sign_track: i32 = (b_exp | if a_negative { 5 } else { 0 }) as i32;

    if a_exp == 0 || b_exp == 0 {
        if b_exp != 0 {
            // a is zero/denormal, b normal: +-0 returns unchanged,
            // denormal dividend flushes to +0.
            if (a_hi & 0x7fff_ffff) | a_lo == 0 {
                return a;
            }
            return 0;
        }
        // Zero/denormal divisor -> qNaN with low word 1.
        return QNAN_LO1;
    }

    let mut a_x: i32 = a_exp as i32; // remainder exponent (<<16 units)
    let mut prev_x: i32 = sign_track; // exponent before last subtraction
    let mut b_m1: i32 = sign_track - 0x1_0000; // b exponent - 1 | sign bits

    // Significands with hidden bit restored (top bit = bit 52).
    let mut rem: u64 = ((((a_hi & 0x000f_ffff) as u64) | 0x10_0000) << 32) | a_lo as u64;
    let mut div: u64 = ((((b_hi & 0x000f_ffff) as u64) | 0x10_0000) << 32) | b_lo as u64;

    loop {
        if a_x <= b_m1 {
            // Tail: remainder exponent is below the divisor's.
            if rem == 0 {
                // Exact multiple: signed zero, sign of the dividend.
                return (sign_track as u64 & 4) << 61;
            }
            if a_x >> 16 < b_m1 >> 16 {
                break;
            }
            // a_exp == b_exp - 1: compare significands for the final
            // half-way step.
            if rem > div {
                // rem in [div, 2*div): scale divisor up and subtract.
                div <<= 1;
            } else {
                if rem == div && (prev_x as u32) >> 16 == (a_x as u32) >> 16 {
                    // Exact tie (rem == b/2): round half to even —
                    // flip the result sign when the quotient is odd.
                    sign_track ^= 1;
                }
                break;
            }
        }

        // rem = |rem - div|, flipping the running sign on borrow.
        let diff;
        if rem >= div {
            diff = rem - div;
        } else {
            diff = div - rem;
            sign_track ^= 1;
        }
        prev_x = a_x - 0x1_0000;
        rem = diff;

        // Renormalize so bit 52 is set again.
        let mut hi = (rem >> 32) as u32;
        let mut lo = rem as u32;
        if hi & 0x001e_0000 == 0 {
            // Deep shift (>= 4 places): the original counts via 20/40
            // chunk shifts plus a binary clz; equivalent to a single
            // clz here. diff == 0 shifts 71 places in the original
            // (20 + 20 + 31) — the zero is caught at the tail above,
            // only the exponent debit matters.
            if rem == 0 {
                a_x -= 71 * 0x1_0000;
            } else {
                let shift = 52 - (63 - rem.leading_zeros());
                if shift >= 32 {
                    hi = lo << (shift - 32);
                    lo = 0;
                } else {
                    hi = (hi << shift) | (lo >> (32 - shift));
                    lo <<= shift;
                }
                rem = ((hi as u64) << 32) | lo as u64;
                a_x -= (shift as i32) * 0x1_0000;
            }
        } else {
            while hi & 0x0010_0000 == 0 {
                hi = (hi << 1) | (lo >> 31);
                lo <<= 1;
                a_x -= 0x1_0000;
            }
            rem = ((hi as u64) << 32) | lo as u64;
        }
    }

    // Merge exponent back over the hidden bit and apply the sign.
    // Exponent underflow (denormal remainder) flushes to +0.
    let exp_minus_1 = a_x - 0x1_0000;
    if exp_minus_1 >= 0 {
        let hi = ((rem >> 32) as u32)
            .wrapping_add((exp_minus_1 as u32) << 4)
            ^ ((sign_track as u32) << 31);
        return ((hi as u64) << 32) | (rem & 0xffff_ffff);
    }
    0
}

/// iabs — original @ 0x080e9788 (12 bytes). 32-bit integer absolute
/// value: `cmp r0,#0; rsblt r0,r0,#0; bx lr`. Negative inputs are
/// negated with a 32-bit reverse subtract, so iabs(INT_MIN) wraps to
/// INT_MIN — wrapping_neg mirrors the original exactly. The
/// byte-identical duplicates @ 0x080e9794 (6 bl sites) and
/// 0x080e97a0 (12 bl sites) hook this same symbol; no separate ports
/// exist for them (see their names.yaml entries).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iabs(x: i32) -> i32 {
    if x < 0 { x.wrapping_neg() } else { x }
}

/// Host-swappable entry point for the reciprocal helper `FUN_08076204`.
/// [`fixed16_div`] calls it with the divisor when that value fits in 24
/// signed bits, otherwise with both operands shifted right by eight. The
/// target build calls the fixed firmware address directly; host tests swap
/// this writable cell to record the exact dispatch behavior.
#[cfg(not(target_os = "none"))]
pub static mut FIXED16_RECIPROCAL: usize = 0x0807_6204;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn fixed16_reciprocal(divisor: i32) -> i32 {
    let reciprocal: unsafe extern "C" fn(i32) -> i32 = core::mem::transmute(0x0807_6204usize);
    reciprocal(divisor)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fixed16_reciprocal(divisor: i32) -> i32 {
    let address = core::ptr::addr_of!(FIXED16_RECIPROCAL).read_volatile();
    let reciprocal: unsafe extern "C" fn(i32) -> i32 = core::mem::transmute(address);
    reciprocal(divisor)
}

/// fixed16_div — original: `FUN_080e9834` @ 0x080e9834 (68 bytes).
///
/// Divides two Q16.16 values by obtaining the divisor's Q16.16 reciprocal
/// from `FUN_08076204` and multiplying it by the numerator. The reciprocal
/// helper handles values whose signed top byte is zero or all ones directly.
/// For every other divisor this function calls it with `divisor >> 8`, then
/// shifts `numerator` right by eight too, retaining the Q16.16 scale without
/// overflowing the helper's input range. The original restores its frame
/// and falls through into the immediately following `fixed16_mul`
/// (`FUN_080e9878`), which returns signed product bits [47:16] through its
/// `smull` plus `lsl #16`/`lsr #16` funnel. Calling that existing port keeps
/// the same truncation-toward-negative-infinity and wrapping behavior.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_div(mut numerator: i32, divisor: i32) -> i32 {
    let divisor_high_byte = divisor >> 24;
    let reciprocal = if divisor_high_byte == 0 || divisor_high_byte == -1 {
        fixed16_reciprocal(divisor)
    } else {
        let reciprocal = fixed16_reciprocal(divisor >> 8);
        numerator >>= 8;
        reciprocal
    };

    crate::util::fixed::fixed16_mul(numerator, reciprocal)
}

/// Host-swappable entry point for the signed-division core
/// `FUN_08037a84` (344 bytes), ported as
/// [`crate::runtime::rt_div::fixed16_div_core`]: the Q16.16 quotient-only
/// shift-subtract sdiv — both operands reduced to magnitude with a sign
/// track (`sign(dividend) ^ sign(divisor)`), a `clz` difference
/// dispatching into an unrolled shift-subtract cascade (quotient bits
/// 31..16 against the pre-shifted divisor, then fractional bits 15..0),
/// and the quotient negated when the signs differed.
/// [`fixed16_div_indirect`] tail-calls it with the dereferenced dividend
/// and the divisor. The target build calls the port directly; host tests
/// swap this writable cell to record the exact dispatch behavior.
#[cfg(not(target_os = "none"))]
pub static mut FIXED16_SDIV32: usize = 0x0803_7a84;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn sdiv32(dividend: i32, divisor: i32) -> i32 {
    crate::runtime::rt_div::fixed16_div_core(dividend, divisor)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn sdiv32(dividend: i32, divisor: i32) -> i32 {
    let address = core::ptr::addr_of!(FIXED16_SDIV32).read_volatile();
    let divide: unsafe extern "C" fn(i32, i32) -> i32 = core::mem::transmute(address);
    divide(dividend, divisor)
}

/// fixed16_div_indirect — original: `FUN_082a182c` @ 0x082a182c (8
/// bytes; 6 bl call sites, binary-scanned: 0x08273e2c, 0x0827403c,
/// 0x08274140, 0x0827cf54, 0x0827cfa4, 0x0827cfd0).
///
/// Truncating signed 32-bit division with the DIVIDEND fetched through
/// a pointer: the whole body is `ldr r0,[r0,#0x0]; b 0x08037a84` —
/// load `*a` into r0 and TAIL-CALL the Q16.16 quotient-only division
/// core @ 0x08037a84 (ported as
/// [`crate::runtime::rt_div::fixed16_div_core`], reached through the
/// `sdiv32` seam above) with the divisor passed straight
/// through in r1, so the callee's quotient returns directly to this
/// function's caller. Heads the indirect fixed16 helper run
/// 0x082a182c-0x082a18c8 (div, eq, gt, lt, sub, mul, ne, add); the eq
/// comparator @ 0x082a1834 sits immediately below it. Unlike
/// [`fixed16_div`] (@ 0x080e9834), which computes a true Q16.16
/// quotient by reciprocal-multiply, this helper is a PLAIN integer
/// sdiv — callers pre-scale: FUN_08273dc8 divides a Q16.16 delta by
/// `row_count << 16` to get a per-row step, and FUN_0827cf10 forms
/// ratios of two Q16.16 values (e.g. `d / (300.0 - d)`), the 2^16
/// scales cancelling. The tail call means there is no frame and no
/// result handling of its own; the port mirrors that by delegating to
/// `sdiv32` after the single pointer load, so the only observable
/// behavior added here is the dereference.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_div_indirect(a: *const i32, b: i32) -> i32 {
    sdiv32(*a, b)
}

/// fixed16_eq_indirect — original: `FUN_082a1834` @ 0x082a1834 (24
/// bytes; 4 bl call sites, all in FUN_0827d380: 0x0827d5f4,
/// 0x0827d608, 0x0827d61c, 0x0827d630).
///
/// Q16.16 equality comparator with BOTH operands fetched through
/// pointers: `ldr r0,[r0]; ldr r1,[r1]; cmp r0,r1; movne r0,#0;
/// moveq r0,#1` — returns 1 when the two values are equal, else 0
/// (Ghidra: `return *param_1 == *param_2`). Unlike the signed
/// movle/movgt and movge/movlt pairs of `fixed16_gt_indirect`
/// (@ 0x082a184c) and `fixed16_lt_indirect` (@ 0x082a1864), the
/// EQ/NE conditions test raw bit-pattern equality, so this is the
/// exact counterpart of `fixed16_ne_indirect` (@ 0x082a18a8) with the
/// sense inverted. The sole caller FUN_0827d380 compares four
/// consecutive Q16.16 struct fields (param_1+5..+8) edge-by-edge
/// against the stack-materialized 1.0 constant (0x10000) and ANDs the
/// results — an identity-scale check that skips further work only when
/// every component is exactly 1.0. Sits immediately above
/// `fixed16_gt_indirect` and heads the indirect fixed16 helper run
/// 0x082a1834-0x082a18c8 (eq, gt, lt, sub, mul, ne, add).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_eq_indirect(a: *const i32, b: *const i32) -> bool {
    *a == *b
}

/// fixed16_gt_indirect — original: `FUN_082a184c` @ 0x082a184c (24
/// bytes; 11 bl call sites, binary-scanned: 0x080f7884, 0x080f7938,
/// 0x080fe64c, 0x08152a54, 0x08167a1c, 0x08197788, 0x08257300,
/// 0x0825732c, 0x08257408, 0x0825749c, 0x0827b6fc).
///
/// Q16.16 greater-than comparator with BOTH operands fetched through
/// pointers: `ldr r0,[r0]; ldr r1,[r1]; cmp r0,r1; movle r0,#0;
/// movgt r0,#1` — a SIGNED compare returning 1 when `*a > *b`, else 0
/// (Ghidra: `return *param_2 < *param_1`). Strict ordering: equal
/// values return 0, and the signed movle/movgt pair makes it an
/// ordering comparator, unlike the raw bit-pattern
/// `fixed16_ne_indirect` (@ 0x082a18a8). Callers use it for threshold
/// tests and range folding: FUN_082572e4 folds a Q16.16 angle by
/// comparing against 0xb40000 (180.0) and 0x1680000 (360.0);
/// FUN_080fe5fc tests a struct field against the stack-materialized
/// 1.0 constant (0x10000) before clamping; FUN_080f780c compares
/// offsets against -100.0 (0xff9c0000) and a global bound. Sits
/// immediately before the indirect fixed16 helper cluster
/// 0x082a1864-0x082a18c8 (lt, sub, mul, ne, add) and is that family's
/// greater-than sibling; `fixed16_eq_indirect` (@ 0x082a1834) just
/// above it heads the run.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_gt_indirect(a: *const i32, b: *const i32) -> bool {
    *a > *b
}

/// fixed16_lt_indirect — original: `FUN_082a1864` @ 0x082a1864 (24
/// bytes; 7 bl call sites, binary-scanned: 0x080f7a68, 0x080f7b10,
/// 0x080fe630, 0x08152a80, 0x08152bdc, 0x08167a34, 0x081977a0).
///
/// Q16.16 less-than comparator with BOTH operands fetched through
/// pointers: `ldr r0,[r0]; ldr r1,[r1]; cmp r0,r1; movge r0,#0;
/// movlt r0,#1` — a SIGNED compare returning 1 when `*a < *b`, else 0
/// (Ghidra: `return *param_1 < *param_2`). The signed movge/movlt pair
/// makes it an ordering comparator, unlike the raw bit-pattern
/// `fixed16_ne_indirect` (@ 0x082a18a8) next to it. Callers use it for
/// range checks: FUN_080fe5fc clamps a freshly multiplied Q16.16 result
/// into [0, 1.0] — `if (!lt(&v, &ZERO)) { if (ge(&v, &ONE)) v = ONE }`
/// — and the FUN_080f79d8/FUN_081529d8 sites compare locals edge-by-edge
/// against live geometry values.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_lt_indirect(a: *const i32, b: *const i32) -> bool {
    *a < *b
}

/// fixed16_sub_indirect — original: `FUN_082a187c` @ 0x082a187c (16
/// bytes; 3 bl call sites, binary-scanned: 0x08273e1c, 0x082a5d6c,
/// 0x082a5d7c).
///
/// Q16.16 subtraction with BOTH operands fetched through pointers:
/// `ldr r0,[r0]; ldr r1,[r1]; sub r0,r0,r1; bx lr` — returns
/// `*a - *b` as a plain 32-bit difference (Ghidra:
/// `return *param_1 - *param_2`). The non-flag-setting `sub` wraps
/// modulo 2^32 with no saturation, so the port uses wrapping_sub.
/// FUN_082a5d54 calls it twice to subtract the +0x8 and +0x4 Q16.16
/// components of two structs edge-by-edge (the +0x0 component uses an
/// inline `sub` on directly loaded words), forming a fixed-point
/// vector delta handed to FUN_0828018c; the 0x08273e1c site subtracts
/// a stack-materialized zero from a local before calling the
/// 0x082a182c helper. Second member of the indirect fixed16 helper
/// cluster 0x082a1864-0x082a18c8 (lt, sub, mul, ne, add).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_sub_indirect(a: *const i32, b: *const i32) -> i32 {
    (*a).wrapping_sub(*b)
}

/// fixed16_mul_indirect — original: `FUN_082a188c` @ 0x082a188c (28
/// bytes; 57 bl call sites, binary-scanned: 0x080fxxxx/0x0816xxxx and the
/// 0x0825xxxx/0x0827xxxx geometry code).
///
/// Q16.16 fixed-point multiply returning exactly what `fixed16_mul`
/// (@ 0x080e9878) returns, except the multiplicand is fetched through a
/// pointer: `ldr r2,[r0]` then `smull r0,r1,r2,<b>` followed by the same
/// `(hi << 16) | (lo >> 16)` funnel that yields signed product bits
/// [47:16] — arithmetic-shift semantics (negative products truncate toward
/// minus infinity) and silent 32-bit wrap of the returned word. The
/// original's stmdb/ldmia frame only spills both arguments so `b` can be
/// reloaded after the pointer load (an ADS register-allocation artifact);
/// it has no semantic effect. Call sites materialize the first operand on
/// the stack and pass `sp + N` (e.g. 0x08257354/0x0825735c), which is why
/// the operand is indirect at all.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_mul_indirect(a: *const i32, b: i32) -> i32 {
    (((*a as i64) * (b as i64)) >> 16) as i32
}

/// fixed16_ne_indirect — original: `FUN_082a18a8` @ 0x082a18a8 (20
/// bytes; 20 bl call sites, binary-scanned: 0x0810xxxx, 0x0814xxxx,
/// 0x0820xxxx and the 0x0827xxxx geometry code).
///
/// Q16.16 not-equal comparator with BOTH operands fetched through
/// pointers: `ldr r0,[r0]; ldr r1,[r1]; subs r0,r0,r1; movne r0,#1` —
/// returns 1 when the two values differ, 0 when they are equal
/// (Ghidra: `return *param_1 != *param_2`). Callers use it as a
/// geometry dirty check: FUN_0810da8c compares a cached rectangle
/// against the live one edge-by-edge and recomputes clipping only when
/// any edge moved. The subs difference in r0 is dead — only Z feeds
/// the movne — so the port compares the dereferenced values directly
/// and never materializes the subtraction.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_ne_indirect(a: *const i32, b: *const i32) -> bool {
    *a != *b
}

/// fixed16_add_indirect — original: `FUN_082a18bc` @ 0x082a18bc (16
/// bytes; 4 bl call sites, binary-scanned: 0x0827b8bc, 0x0827b8d0,
/// 0x082a5dc8, 0x082a5dd8).
///
/// Q16.16 addition with BOTH operands fetched through pointers:
/// `ldr r0,[r0]; ldr r1,[r1]; add r0,r0,r1; bx lr` — returns
/// `*a + *b` as a plain 32-bit sum (Ghidra:
/// `return *param_1 + *param_2`). The non-flag-setting `add` wraps
/// modulo 2^32 with no saturation, so the port uses wrapping_add.
/// FUN_082a5db0 calls it twice to add the +0x8 and +0x4 Q16.16
/// components of two structs edge-by-edge (the +0x0 component uses an
/// inline `add` on directly loaded words), packing the fixed-point
/// vector sum into a 12-byte record handed to FUN_0828018c; the two
/// FUN_0827b5a8 sites add stack-materialized locals. Last member of
/// the indirect fixed16 helper cluster 0x082a1864-0x082a18c8 (lt,
/// sub, mul, ne, add).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed16_add_indirect(a: *const i32, b: *const i32) -> i32 {
    (*a).wrapping_add(*b)
}

/// message_kind_byte — original: `FUN_082a18cc` @ 0x082a18cc (8
/// bytes; 2 bl call sites: 0x081d6ad4 in FUN_081d6ac4, 0x081d7e7c in
/// FUN_081d7e68).
///
/// Kind/discriminant byte getter of the 12-byte UI message envelope
/// constructed @ 0x0825790c (a vtable word at +0x0, this kind byte at
/// +0x4 — the constructor zeroes it with `strb` — and a union word at
/// +0x8 holding either a nested message pointer or a plain id). The
/// whole body is `ldrb r0,[r0,#0x4]; bx lr` (Ghidra:
/// `return *(undefined1 *)(param_1 + 4)`), so the port is a single
/// byte load at offset 4. Both callers dispatch on the tag: 0 takes
/// the nested-message path (the +0x8 word is a payload pointer whose
/// own +0x4 message code is compared against 0x500/0x501), 1 takes
/// the plain-id path, and any other value is ignored. Sits
/// immediately after the indirect fixed16 helper cluster
/// 0x082a1834-0x082a18c8 and heads a tiny accessor run with the +0x8
/// word getter @ 0x082a18d4 and the +0x4 word getter @ 0x082a18dc
/// (separate ports).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_kind_byte(message: *const u8) -> u8 {
    *message.add(4)
}

/// message_payload_word — original: `FUN_082a18d4` @ 0x082a18d4 (8
/// bytes; 1 bl call site: 0x081d6f88 in FUN_081d6f7c).
///
/// Union-word getter of the 12-byte UI message envelope constructed
/// @ 0x0825790c (a vtable word at +0x0, the `message_kind_byte` tag
/// at +0x4, and this word at +0x8). The whole body is
/// `ldr r0,[r0,#0x8]; bx lr` (Ghidra:
/// `return *(undefined4 *)(param_1 + 8)`), so the port is a single
/// aligned word load at offset 8. The word is a tag-selected union:
/// kind 0 makes it a nested-message payload pointer (whose own +0x4
/// message code is compared against 0x500/0x501), kind 1 a plain id.
/// The sole caller FUN_081d6f7c takes the plain-id path: it hands the
/// returned word to FUN_081d70d4 as the id, uses the resulting index
/// to fetch an entry from the 8-byte-stride table at param_1+0x158,
/// and vtable-dispatches that entry with code 0x20. Middle member of
/// the envelope accessor run 0x082a18cc-0x082a18e0 (kind byte, this
/// word, +0x4 word); sits between `message_kind_byte` (@ 0x082a18cc)
/// and the +0x4 word getter @ 0x082a18dc (a separate port).
///
/// Codegen note: the body compiles to bytes identical to
/// `ft::stream::ft_stream_pos` (`ldr r0,[r0,#8]; bx lr`), so it
/// carries its own `link_section` — without it LLVM's identical-code
/// folding collapses the two exports into one section and this symbol
/// would no longer head its own disassembly (the
/// `cxx::clock_source_destroy` precedent). They are separate
/// functions in the original and must stay separately hookable.
#[cfg_attr(target_os = "none", link_section = ".text.message_payload_word")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_payload_word(message: *const u32) -> u32 {
    *message.add(2)
}

/// message_code_word — original: `FUN_082a18dc` @ 0x082a18dc (8
/// bytes; 2 bl call sites: 0x081d71f0 in FUN_081d71d8, 0x081d7eac in
/// FUN_081d7e68).
///
/// Message-code word getter of the UI message object: a vtable word
/// at +0x0 and this code word at +0x4. The whole body is
/// `ldr r0,[r0,#0x4]; bx lr` (Ghidra:
/// `return *(undefined4 *)(param_1 + 4)`), so the port is a single
/// aligned word load at offset 4. Note this is a WORD load, unlike
/// the sibling `message_kind_byte` (@ 0x082a18cc) whose `ldrb` reads
/// only the tag byte of the 12-byte envelope — the two accessors sit
/// on different object types: FUN_081d7e68 first unwraps the kind-0
/// envelope with FUN_08257904, then applies THIS getter to the nested
/// message it yields. Callers dispatch on the code: FUN_081d71d8
/// compares it against 0x500 (routes the message's +0x0 word to
/// FUN_081d6b5c) and 0x501 (routes to FUN_081d6760), returning false
/// for any other code; FUN_081d7e68 proceeds down its
/// nested-message path only when the code is 0. Last member of the
/// envelope/message accessor run 0x082a18cc-0x082a18e0 (kind byte,
/// +0x8 union word, this +0x4 code word).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_code_word(message: *const u32) -> u32 {
    *message.add(1)
}

use crate::cxx::string::{cxx_string_default_ctor, cxx_string_rep_create, empty_rep, rep_data};
use crate::cxx::string_object::{
    string_object_c_str, string_object_release_payload, StringObject, STRING_OBJECT_VTABLE,
};
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;

/// Byte size of the stack-local query object the constructor
/// `FUN_0813e474` builds (the original's frame reserves `sp+0x8` ..
/// `sp+0x50` for it; fields observed out to the mode byte at +0x45).
const QUERY_OBJECT_SIZE: usize = 0x48;

/// Minimum fresh capacity of the produced string (`mov r0, #0x20` @
/// 0x082a195c): the original stages 0x20 and the measured length in two
/// stack slots and picks the larger with an `addhi`/`movls` address
/// select, so a name of 0x20 characters or fewer gets capacity 0x20.
const QUERY_NAME_CAPACITY_FLOOR: u32 = 0x20;

/// Host-swappable entry point for the query-object constructor
/// `FUN_0813e474` @ 0x0813e474 (252 bytes, unported): builds the
/// 72-byte stack-local query object util/inner_state.rs documents (its
/// word at +0x40 points at the much larger inner object), storing `id`
/// as the byte at +0x44 and `mode` as the byte at +0x45. Returns the
/// object pointer, which the original's caller discards. The target
/// build calls the fixed firmware address directly; host tests swap
/// this writable cell to install recording mocks.
#[cfg(not(target_os = "none"))]
pub static mut QUERY_OBJECT_CONSTRUCT: usize = 0x0813_e474;

/// Host-swappable entry point for the query-object name getter
/// `FUN_0813c2ec` @ 0x0813c2ec (160 bytes, unported): resolves the
/// query object's display name into the two-word [`StringObject`] at
/// `out` (through the inner object's backend and the id word its +0xf64
/// pointer carries, defaulting to a static name when the inner object
/// has none). The target build calls the fixed firmware address
/// directly; host tests swap this writable cell.
#[cfg(not(target_os = "none"))]
pub static mut QUERY_OBJECT_NAME: usize = 0x0813_c2ec;

/// Host-swappable entry point for the query-object destructor
/// `FUN_0813e5c4` @ 0x0813e5c4 (192 bytes, unported): tears down the
/// object `FUN_0813e474` built. Its r0:r1 return is discarded by the
/// original's caller, so the seam models it as void. The target build
/// calls the fixed firmware address directly; host tests swap this
/// writable cell.
#[cfg(not(target_os = "none"))]
pub static mut QUERY_OBJECT_DESTROY: usize = 0x0813_e5c4;

/// Constructor seam signature: `(this, id, mode) -> this`.
type QueryConstructFn = unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8;
/// Name-getter seam signature: `(out, query)`.
type QueryNameFn = unsafe extern "C" fn(*mut StringObject, *const u8);
/// Destructor seam signature: `(query)`.
type QueryDestroyFn = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn query_object_construct(query: *mut u8, id: u32, mode: u32) {
    let construct: QueryConstructFn = core::mem::transmute(0x0813_e474usize);
    construct(query, id, mode);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn query_object_construct(query: *mut u8, id: u32, mode: u32) {
    let address = core::ptr::addr_of!(QUERY_OBJECT_CONSTRUCT).read_volatile();
    let construct: QueryConstructFn = core::mem::transmute(address);
    construct(query, id, mode);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn query_object_name(out: *mut StringObject, query: *const u8) {
    let name: QueryNameFn = core::mem::transmute(0x0813_c2ecusize);
    name(out, query);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn query_object_name(out: *mut StringObject, query: *const u8) {
    let address = core::ptr::addr_of!(QUERY_OBJECT_NAME).read_volatile();
    let name: QueryNameFn = core::mem::transmute(address);
    name(out, query);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn query_object_destroy(query: *mut u8) {
    let destroy: QueryDestroyFn = core::mem::transmute(0x0813_e5c4usize);
    destroy(query);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn query_object_destroy(query: *mut u8) {
    let address = core::ptr::addr_of!(QUERY_OBJECT_DESTROY).read_volatile();
    let destroy: QueryDestroyFn = core::mem::transmute(address);
    destroy(query);
}

/// query_name_to_cxx_string — original: `FUN_082a1918` @ 0x082a1918
/// (156 bytes; NO `bl` call sites in osos.asm and no direct pointer to
/// the address anywhere in osos.dec, so the original is reached
/// indirectly — a vtable or computed table outside the image body).
///
/// Materializes the DEFAULT query object and hands its name back as a
/// freshly allocated COW `basic_string<char>` (the class ported in
/// cxx/string.rs; `string` is the one-word string object, a `char **`):
///
/// 1. construct the 72-byte stack-local query object with id byte 0 and
///    mode 0 (`FUN_0813e474` @ 0x0813e474, unported, behind the
///    [`QUERY_OBJECT_CONSTRUCT`] seam),
/// 2. resolve its display name into a two-word [`StringObject`]
///    (`FUN_0813c2ec` @ 0x0813c2ec, unported, behind the
///    [`QUERY_OBJECT_NAME`] seam),
/// 3. read the name's C string ([`string_object_c_str`] @ 0x082a50b0,
///    ported) and measure it ([`strlen`] @ 0x08392478, ported),
/// 4. allocate a string rep with capacity max(0x20, length) and the
///    measured length stamped ([`cxx_string_rep_create`] @ 0x083d8a64,
///    ported) — an empty name skips the allocation and selects the
///    shared empty rep 0x08b31804 straight from the literal pool
///    (`DAT_082a19b4`, binary-verified against osos.dec),
/// 5. store the data pointer (rep + 0xc) into the one-word string
///    object BEFORE the copy, then [`__rt_memcpy`] the bytes (ROM
///    veneer thunk @ 0x08037db0, ported) — the store-ahead order and
///    the unconditional copy call (length 0 included) match the
///    original instruction sequence,
/// 6. plant the StringObject class vtable 0x089a6044 (`DAT_082a19b8`,
///    binary-verified) and run the shared payload release
///    ([`string_object_release_payload`] @ 0x08275d74, ported) on the
///    name holder,
/// 7. destroy the query object (`FUN_0813e5c4` @ 0x0813e5c4, unported,
///    behind the [`QUERY_OBJECT_DESTROY`] seam).
///
/// Step 4 is `basic_string(const char *)` with the growth policy
/// inlined: `cxx_string_rep_reserve(this, 0, len, len)` would compute
/// the same max(0, 32, len) capacity, but the original calls rep_create
/// DIRECTLY with the floor select staged on its stack (the
/// `stmia sp,{r0,r4}` / `addhi` / `movls` pointer pick @
/// 0x082a1964-0x082a1970), so the port calls rep_create too.
///
/// Deviations:
/// - The shared empty rep is the modeled [`empty_rep`] static (the
///   cxx/string.rs simplification), not the RAM address 0x08b31804.
/// - The planted vtable is the modeled [`STRING_OBJECT_VTABLE`] static
///   (the cxx/string_object.rs simplification), not 0x089a6044.
/// - The three query-class callees are unported firmware; each sits
///   behind a host-swappable seam (this module's FIXED16_RECIPROCAL
///   pattern): the target build calls the fixed firmware addresses,
///   host tests install recording mocks.
/// - The original's 0x58-byte frame, the r4-r6 spills and the two-slot
///   capacity staging are ADS register-allocation artifacts; the port
///   computes max(0x20, length) directly. The two stack objects are
///   zero-initialized where the original leaves them uninitialized —
///   the constructor writes every field the later steps read, so the
///   difference is unobservable.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn query_name_to_cxx_string(string: *mut *mut u8) {
    let mut query = [0u8; QUERY_OBJECT_SIZE];
    let mut name = StringObject {
        vtable: core::ptr::null(),
        payload: core::ptr::null_mut(),
    };
    query_object_construct(query.as_mut_ptr(), 0, 0);
    query_object_name(&mut name, query.as_ptr());
    let source = string_object_c_str(&name);
    let length = strlen(source) as u32;
    let rep = if length != 0 {
        let capacity = if length > QUERY_NAME_CAPACITY_FLOOR {
            length
        } else {
            QUERY_NAME_CAPACITY_FLOOR
        };
        cxx_string_rep_create(string as *mut u8, capacity, length)
    } else {
        empty_rep()
    };
    let data = rep_data(rep);
    *string = data;
    __rt_memcpy(data, source, length as usize);
    name.vtable = &STRING_OBJECT_VTABLE;
    string_object_release_payload(&mut name);
    query_object_destroy(query.as_mut_ptr());
}

/// Size in u16 units of the stack-local counted-u16 staging buffer
/// [`context_text_to_cxx_string`] uses: one u16 codepoint count
/// followed by up to 0xff u16 code units (0x200 bytes total — the
/// original's `sub sp,sp,#0x208` frame reserves them at sp+0x4). The
/// serializer truncates to 0xff codepoints (`movhi r1,#0xff` @
/// 0x08053a44 feeding `FUN_08277044`), so 0x100 u16s always suffices.
const COUNTED_U16_BUFFER_UNITS: usize = 0x100;

/// Host-swappable entry point for the context-text serializer
/// `FUN_080539f0` @ 0x080539f0 (156 bytes, unported): fetches the
/// process-wide shared context (lazy getter @ 0x08369bec), builds a
/// StringObject from the C string at context+0x98 (a first byte of
/// 0xff marks the field unset and yields count 0), appends the lookup
/// name of the u16 code at context+0x92 (`FUN_08068fe8` maps it to
/// short layout tags — "ABC"/"B19"/"DK"/"CH"/"KH"…), truncates to
/// 0xff codepoints, and expands the result into `counted` as a u16
/// codepoint count followed by that many u16 code units
/// (UTF-8→UTF-16 decode loop @ 0x082767fc). The target build calls
/// the fixed firmware address directly; host tests swap this writable
/// cell to install recording mocks.
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_TEXT_TO_COUNTED_U16: usize = 0x0805_39f0;

/// Host-swappable entry point for the counted-u16 deserializer
/// `FUN_082596f4` @ 0x082596f4 (72 bytes, unported): rebuilds a
/// StringObject from the counted u16 units (`FUN_082773b4`), converts
/// it (`FUN_08276db4`), assigns its c_str into `string` through
/// [`cxx_string_assign_cstr`] @ 0x083d8ca0, then plants the
/// StringObject vtable (`DAT_0825973c`) and releases the payload
/// ([`string_object_release_payload`] @ 0x08275d74). The target build
/// calls the fixed firmware address directly; host tests swap this
/// writable cell.
#[cfg(not(target_os = "none"))]
pub static mut COUNTED_U16_TO_CXX_STRING: usize = 0x0825_96f4;

/// Serializer seam signature: `(counted)` — writes the u16 count at
/// counted[0] and the code units from counted[1].
type ContextTextSerializeFn = unsafe extern "C" fn(*mut u16);
/// Deserializer seam signature: `(counted, string)`.
type CountedU16DeserializeFn = unsafe extern "C" fn(*const u16, *mut *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_text_serialize(counted: *mut u16) {
    let serialize: ContextTextSerializeFn = core::mem::transmute(0x0805_39f0usize);
    serialize(counted);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn context_text_serialize(counted: *mut u16) {
    let address = core::ptr::addr_of!(CONTEXT_TEXT_TO_COUNTED_U16).read_volatile();
    let serialize: ContextTextSerializeFn = core::mem::transmute(address);
    serialize(counted);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn counted_u16_deserialize(counted: *const u16, string: *mut *mut u8) {
    let deserialize: CountedU16DeserializeFn = core::mem::transmute(0x0825_96f4usize);
    deserialize(counted, string);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn counted_u16_deserialize(counted: *const u16, string: *mut *mut u8) {
    let address = core::ptr::addr_of!(COUNTED_U16_TO_CXX_STRING).read_volatile();
    let deserialize: CountedU16DeserializeFn = core::mem::transmute(address);
    deserialize(counted, string);
}

/// context_text_to_cxx_string — original: `FUN_082a19bc` @ 0x082a19bc
/// (48 bytes; NO `bl` call sites in osos.asm and no direct pointer to
/// the address anywhere in osos.dec, so — like its neighbor
/// [`query_name_to_cxx_string`] @ 0x082a1918 — the original is reached
/// indirectly, a vtable or computed table outside the image body).
///
/// Hands the shared context's text field back as a COW
/// `basic_string<char>` (the class ported in cxx/string.rs; `string`
/// is the one-word string object, a `char **`), staged through a
/// counted-u16 (UTF-16) stack buffer:
///
/// 1. default-construct `*string`, parking it on the shared empty rep
///    ([`cxx_string_default_ctor`] @ 0x083d8c20, ported) — the
///    original keeps the constructor's r0 return in r4 and threads
///    THAT into step 3, so the port binds the return value too,
/// 2. serialize the context field into the 512-byte stack buffer as a
///    u16 codepoint count plus that many u16 code units
///    (`FUN_080539f0` @ 0x080539f0, unported, behind the
///    [`CONTEXT_TEXT_TO_COUNTED_U16`] seam),
/// 3. deserialize the buffer back into `*string`
///    (`FUN_082596f4` @ 0x082596f4, unported, behind the
///    [`COUNTED_U16_TO_CXX_STRING`] seam) — called unconditionally,
///    count 0 included.
///
/// The field is the same shared-context text the about/diagnostics
/// record at 0x08112800 collects (0x080539f0 is one of its four
/// field fillers; see object_set_version_text's ledger entry): the C
/// string at context+0x98 with the lookup name of the u16 code at
/// context+0x92 appended — the concrete field is not recovered, but
/// the code-name table holds short layout tags ("ABC", "B19", "DK",
/// "CH", "KH"…), pointing at an input/keyboard-layout name.
///
/// Deviations:
/// - The two text-marshaling callees are unported firmware; each sits
///   behind a host-swappable seam (this module's FIXED16_RECIPROCAL
///   pattern): the target build calls the fixed firmware addresses,
///   host tests install recording mocks.
/// - The original's `add r1,sp,#0x204` before the constructor call is
///   dead — the constructor clobbers r1 with the empty-rep pointer it
///   loads (`ldr r1,[0x83d8c2c]`), and no later instruction reads it.
///   An ADS scheduling artifact, omitted.
/// - The staging buffer is zero-initialized where the original leaves
///   it uninitialized: the serializer writes the count and every unit
///   the deserializer reads (count 0 writes the count word alone), so
///   the difference is unobservable.
/// - The 4 spare frame bytes at sp+0x204 and the r4 spill are ADS
///   frame artifacts; the port keeps only the 512-byte buffer.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_text_to_cxx_string(string: *mut *mut u8) {
    let string = cxx_string_default_ctor(string);
    let mut counted = [0u16; COUNTED_U16_BUFFER_UNITS];
    context_text_serialize(counted.as_mut_ptr());
    counted_u16_deserialize(counted.as_ptr(), string);
}

/// Host-swappable entry point for the PMU register-0x87 bit-1 query
/// `FUN_08086e4c` @ 0x08086e4c (28 bytes, unported; the original
/// reaches it through the 4-byte branch veneer `thunk_FUN_08086e4c`
/// @ 0x0805381c, `b 0x08086e4c`): stages a u32 stack slot, runs the
/// mutexed single-register PMU I2C read `FUN_082e55dc` @ 0x082e55dc
/// (68 bytes: sem 0x11 / sem 5 lock pair around the raw transfer
/// `FUN_0836d3b8` — PCF50635 register 0x87, one byte — extracting
/// `(byte & 2) >> 1` into the slot and returning the transfer
/// status), then answers 1 when the extracted bit is 0, else 0
/// (`rsbs r0,r0,#1` / `movcc r0,#0`: slot 0 -> 1, slot >= 1 -> 0).
/// The target build calls the fixed firmware address directly; host
/// tests swap this writable cell to install recording mocks.
#[cfg(not(target_os = "none"))]
pub static mut PMU_REG87_BIT1_QUERY: usize = 0x0808_6e4c;

/// Query seam signature: `() -> status` (1 when the bit is clear).
type PmuReg87Bit1QueryFn = unsafe extern "C" fn() -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pmu_reg87_bit1_query() -> i32 {
    let query: PmuReg87Bit1QueryFn = core::mem::transmute(0x0808_6e4cusize);
    query()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pmu_reg87_bit1_query() -> i32 {
    let address = core::ptr::addr_of!(PMU_REG87_BIT1_QUERY).read_volatile();
    let query: PmuReg87Bit1QueryFn = core::mem::transmute(address);
    query()
}

/// pmu_reg87_bit1_clear — original: `FUN_082a19ec` @ 0x082a19ec (20
/// bytes; NO `bl` call sites in osos.asm and no direct pointer to the
/// address anywhere in osos.dec (binary-scanned), so — like its
/// neighbors [`query_name_to_cxx_string`] @ 0x082a1918 and
/// [`context_text_to_cxx_string`] @ 0x082a19bc — the original is
/// reached indirectly, a vtable or computed table outside the image
/// body).
///
/// Booleanizes the PMU register-0x87 bit-1 query: the whole body is
/// `stmdb sp!,{r4,lr}; bl 0x0805381c; cmp r0,#0; movne r0,#1;
/// ldmia sp!,{r4,pc}` (Ghidra: `iVar1 = thunk_FUN_08086e4c(); return
/// iVar1 != 0`), where the veneer target `FUN_08086e4c` @ 0x08086e4c
/// (unported, behind the [`PMU_REG87_BIT1_QUERY`] seam) returns 1
/// when bit 1 of the PCF50635 register 0x87 byte is clear, else 0 —
/// so this function answers whether that flag is clear. The concrete
/// meaning of the bit is NOT recovered: register 0x87 lies outside
/// the public PCF5063x register map (which ends at DCDCPFM 0x84) and
/// Rockbox's ipod6g PMU driver never touches it. The same query's
/// other consumers — FUN_080617c0 (early-returns when the flag is
/// clear after mapping a charger/accessory-kind enum through a byte
/// table) and FUN_081a5940 (flags bit 0x200 set + flag clear ->
/// result code 0xf) — are consistent with a charger/accessory status
/// flag but do not pin it down. Middle member of the indirectly
/// reached diagnostics run 0x082a1918-0x082a1a6c (query name string,
/// context text string, this flag, two more *_to_cxx_string
/// wrappers, a u16-pair splitter).
///
/// Deviations:
/// - The query callee is unported firmware behind a host-swappable
///   usize seam (this module's FIXED16_RECIPROCAL pattern): the
///   target build transmutes the fixed firmware address 0x08086e4c
///   (the veneer @ 0x0805381c is folded away — it is a bare `b`),
///   host tests install recording mocks.
/// - The pushed r4 is never used (the `stmdb sp!,{r4,lr}` / `ldmia
///   sp!,{r4,pc}` pair spills and restores it gratuitously — an ADS
///   frame artifact); the port keeps no frame.
/// - The `cmp r0,#0` / `movne r0,#1` pair is the ADS `!= 0` bool
///   conversion; Rust's `bool` return models it directly, mapping
///   every nonzero query value to true.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_reg87_bit1_clear() -> bool {
    pmu_reg87_bit1_query() != 0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    use std::sync::{Mutex, MutexGuard};

    const INF: u64 = 0x7ff0_0000_0000_0000;
    const MIN_NORMAL: u64 = 0x0010_0000_0000_0000;
    const MAX_DENORM: u64 = 0x000f_ffff_ffff_ffff;

    fn sqrt(x: u64) -> u64 {
        unsafe { _dsqrt(x) }
    }

    fn dmod(a: u64, b: u64) -> u64 {
        unsafe { __dmod(a, b) }
    }

    /// Host IEEE oracle: aarch64 f64::sqrt is correctly rounded.
    fn host_sqrt(x: u64) -> u64 {
        f64::from_bits(x).sqrt().to_bits()
    }

    /// Host libm remainder(): exact operation, perfect oracle.
    fn host_remainder(a: u64, b: u64) -> u64 {
        extern "C" {
            fn remainder(x: f64, y: f64) -> f64;
        }
        unsafe { remainder(f64::from_bits(a), f64::from_bits(b)) }.to_bits()
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

    // ---- _dsqrt ----

    #[test]
    fn sqrt_perfect_squares() {
        for i in 1..=1000u64 {
            let v = i as f64 * i as f64;
            let bits = v.to_bits();
            assert_eq!(sqrt(bits), (i as f64).to_bits(), "sqrt({v})");
            assert_eq!(sqrt(bits), host_sqrt(bits));
        }
    }

    #[test]
    fn sqrt_directed_normals() {
        let cases: &[u64] = &[
            0x3ff0_0000_0000_0000, // 1.0
            0x4000_0000_0000_0000, // 2.0
            0x3fe0_0000_0000_0000, // 0.5
            MIN_NORMAL,
            0x7fef_ffff_ffff_ffff, // DBL_MAX
            0x3e69_1234_5678_9abc, // random-ish small
            0x7fe0_0000_0000_0001, // just above 2^1023
            0x0010_0000_0000_0001, // just above min normal
        ];
        for &x in cases {
            assert_eq!(sqrt(x), host_sqrt(x), "x={x:#x}");
        }
    }

    #[test]
    fn sqrt_zero_inf_nan_negative() {
        assert_eq!(sqrt(0), 0); // +0
        assert_eq!(sqrt(0x8000_0000_0000_0000), 0x8000_0000_0000_0000); // -0
        assert_eq!(sqrt(INF), INF); // +Inf
        // -Inf -> qNaN with low word 1 (NOT the canonical NaN).
        assert_eq!(sqrt(INF | 0x8000_0000_0000_0000), QNAN_LO1);
        // Negative finite -> qNaN with low word 1.
        assert_eq!(sqrt(0xbff0_0000_0000_0000), QNAN_LO1); // -1.0
        assert_eq!(sqrt(0xc4f8_7654_3210_fedc), QNAN_LO1);
        // NaN inputs -> canonical qNaN, payload and sign dropped.
        assert_eq!(sqrt(0x7ff8_0000_0000_0000), QNAN);
        assert_eq!(sqrt(0x7ff4_0000_dead_beef), QNAN);
        assert_eq!(sqrt(0xfff8_0000_0000_0001), QNAN);
        assert_eq!(sqrt(0x7ff0_0000_0000_0001), QNAN); // sNaN
    }

    #[test]
    fn sqrt_denormals_flush_to_zero() {
        assert_eq!(sqrt(1), 0); // smallest positive denormal -> +0
        assert_eq!(sqrt(MAX_DENORM), 0);
        // Even negative denormals flush to +0 (sign never tested).
        assert_eq!(sqrt(0x8000_0000_0000_0001), 0);
    }

    #[test]
    fn sqrt_random_matches_host() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        for _ in 0..100_000 {
            let x = rng.next() & 0x7fff_ffff_ffff_ffff; // positive only
            if f64::from_bits(x).is_nan() {
                continue; // NaN payload behavior differs by design
            }
            if x != 0 && x < MIN_NORMAL {
                assert_eq!(sqrt(x), 0, "denormal x={x:#x} flushes to +0");
                continue;
            }
            assert_eq!(sqrt(x), host_sqrt(x), "x={x:#x}");
        }
    }

    // ---- __dmod (IEEE remainder core) ----

    #[test]
    fn dmod_is_remainder_not_fmod() {
        // Pin the semantics: quotient rounds to NEAREST, not truncated.
        let five_half = 0x4016_0000_0000_0000u64; // 5.5
        let two = 0x4000_0000_0000_0000u64; // 2.0
        // fmod(5.5, 2) = +1.5, remainder(5.5, 2) = -0.5.
        assert_eq!(dmod(five_half, two), 0xbfe0_0000_0000_0000);
        assert_eq!(dmod(five_half, two), host_remainder(five_half, two));
        // Truncated cases agree with fmod.
        let ten = 0x4024_0000_0000_0000u64;
        let three = 0x4008_0000_0000_0000u64;
        assert_eq!(dmod(ten, three), 0x3ff0_0000_0000_0000); // 1.0
    }

    #[test]
    fn dmod_ties_round_half_even() {
        for &(a, b, expect) in &[
            (2.0f64, 4.0f64, 2.0f64),   // q = 0.5 -> 0 (even): rem = 2
            (6.0f64, 4.0f64, -2.0f64),  // q = 1.5 -> 2 (even): rem = -2
            (10.0f64, 4.0f64, 2.0f64),  // q = 2.5 -> 2 (even): rem = 2
            (14.0f64, 4.0f64, -2.0f64), // q = 3.5 -> 4 (even): rem = -2
            (1.5f64, 1.0f64, -0.5f64),  // q = 1.5 -> 2
            (2.5f64, 1.0f64, 0.5f64),   // q = 2.5 -> 2
            (3.5f64, 1.0f64, -0.5f64),  // q = 3.5 -> 4
        ] {
            let (ab, bb) = (a.to_bits(), b.to_bits());
            assert_eq!(dmod(ab, bb), expect.to_bits(), "remainder({a}, {b})");
            assert_eq!(dmod(ab, bb), host_remainder(ab, bb));
        }
    }

    #[test]
    fn dmod_sign_cases() {
        let a = 5.5f64.to_bits();
        let neg_a = (-5.5f64).to_bits();
        let b = 2.0f64.to_bits();
        let neg_b = (-2.0f64).to_bits();
        // Sign follows the dividend; divisor sign is irrelevant.
        assert_eq!(dmod(a, b), (-0.5f64).to_bits());
        assert_eq!(dmod(a, neg_b), (-0.5f64).to_bits());
        assert_eq!(dmod(neg_a, b), 0.5f64.to_bits());
        assert_eq!(dmod(neg_a, neg_b), 0.5f64.to_bits());
        // Zero results carry the dividend's sign.
        let four = 4.0f64.to_bits();
        assert_eq!(dmod(four, b), 0.0f64.to_bits());
        assert_eq!(dmod((-4.0f64).to_bits(), b), (-0.0f64).to_bits());
        assert_eq!(dmod((-4.0f64).to_bits(), b), host_remainder((-4.0f64).to_bits(), b));
    }

    #[test]
    fn dmod_special_values() {
        let one = 1.0f64.to_bits();
        // x % 0 -> qNaN with low word 1 (payload differs from host).
        assert_eq!(dmod(one, 0), QNAN_LO1);
        assert_eq!(dmod(one, 0x8000_0000_0000_0000), QNAN_LO1); // -0
        assert_eq!(dmod(0, 0), QNAN_LO1); // 0 % 0
        // Inf % x -> qNaN low word 1.
        assert_eq!(dmod(INF, one), QNAN_LO1);
        assert_eq!(dmod(INF | 0x8000_0000_0000_0000, one), QNAN_LO1);
        assert_eq!(dmod(INF, INF), QNAN_LO1); // Inf % Inf
        // NaN anywhere -> canonical qNaN.
        assert_eq!(dmod(0x7ff8_0000_dead_beef, one), QNAN);
        assert_eq!(dmod(one, 0xfff0_0000_0000_0001), QNAN);
        assert_eq!(dmod(0x7ff8_0000_0000_0000, 0x7ff8_0000_0000_0000), QNAN);
        // finite % Inf -> the finite dividend unchanged.
        assert_eq!(dmod(one, INF), one);
        assert_eq!(dmod((-5.5f64).to_bits(), INF | 0x8000_0000_0000_0000), (-5.5f64).to_bits());
        assert_eq!(dmod(0, INF), 0); // +0 % Inf
        assert_eq!(dmod(0x8000_0000_0000_0000, INF), 0x8000_0000_0000_0000); // -0 % Inf
        // +-0 % normal -> signed zero unchanged.
        assert_eq!(dmod(0, one), 0);
        assert_eq!(dmod(0x8000_0000_0000_0000, one), 0x8000_0000_0000_0000);
    }

    #[test]
    fn dmod_denormals() {
        let one = 1.0f64.to_bits();
        // Denormal dividend, normal divisor -> +0 (host gives the
        // denormal itself; the original flushes).
        assert_eq!(dmod(1, one), 0);
        assert_eq!(dmod(MAX_DENORM, one), 0);
        // Denormal divisor flushes to zero -> NaN low word 1.
        assert_eq!(dmod(one, 1), QNAN_LO1);
        assert_eq!(dmod(one, MAX_DENORM), QNAN_LO1);
        assert_eq!(dmod(1, 1), QNAN_LO1); // both denormal
        // Denormal dividend % Inf -> +0.
        assert_eq!(dmod(1, INF), 0);
        // Result that would be denormal flushes to +0: min_normal is an
        // exact multiple of 2^-1040-ish divisors; use remainder of
        // min_normal * 3 by min_normal * 2 -> min_normal (normal), and
        // a genuinely-denormal result: remainder(3 * 2^-1074-ish)...
        // Simpler: remainder(DBL_MIN, 3.0) = DBL_MIN (normal); craft
        // underflow: remainder(min_normal + denorm...) is flushed by
        // input rule, so instead check a normal pair whose remainder
        // underflows: remainder(2^-1022 * (1+2^-52), 2^-1022) = tiny
        // denormal -> +0.
        let x = MIN_NORMAL | 1; // min_normal * (1 + 2^-52)
        assert!(f64::from_bits(host_remainder(x, MIN_NORMAL)) > 0.0); // host: denormal
        assert_eq!(dmod(x, MIN_NORMAL), 0); // original flushes to +0
    }

    #[test]
    fn dmod_random_matches_host_remainder() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        let mut checked = 0u32;
        while checked < 100_000 {
            let a = rng.next() & 0x7fff_ffff_ffff_ffff;
            let b = rng.next() & 0x7fff_ffff_ffff_ffff;
            let (fa, fb) = (f64::from_bits(a), f64::from_bits(b));
            // Skip cases where the original deliberately diverges:
            // NaNs, non-finite, zero/denormal operands (flush rules).
            if !fa.is_finite() || !fb.is_finite() {
                continue;
            }
            // Zero/denormal operands follow flush rules (directed tests).
            if fa == 0.0 || fb == 0.0 || fa.abs() < f64::MIN_POSITIVE || fb.abs() < f64::MIN_POSITIVE
            {
                continue;
            }
            let got = dmod(a, b);
            let want = host_remainder(a, b);
            // Underflowing results flush to +0 in the original.
            if f64::from_bits(want) != 0.0 && f64::from_bits(want).abs() < f64::MIN_POSITIVE {
                assert_eq!(got, 0, "underflow a={a:#x} b={b:#x}");
            } else {
                assert_eq!(got, want, "a={a:#x} b={b:#x}");
            }
            checked += 1;
        }
    }

    #[test]
    fn dmod_extreme_exponent_spans() {
        // Very large % very small exercises the full exponent walk.
        let cases: &[(f64, f64)] = &[
            (1e300, 1e-300),
            (1e-300, 1e300),
            (f64::MAX, f64::MIN_POSITIVE),
            (f64::MIN_POSITIVE, f64::MAX),
            (1.0, f64::MIN_POSITIVE),
            (0.1, 0.03),
            (123456.789, 0.00001234),
        ];
        for &(x, y) in cases {
            let (a, b) = (x.to_bits(), y.to_bits());
            let want = host_remainder(a, b);
            if f64::from_bits(want) != 0.0 && f64::from_bits(want).abs() < f64::MIN_POSITIVE {
                assert_eq!(dmod(a, b), 0, "underflow x={x} y={y}");
            } else {
                assert_eq!(dmod(a, b), want, "x={x} y={y}");
            }
        }
    }

    #[test]
    fn dmod_exact_multiples_ping_pong() {
        // a = b * 2^k for large k walks the rem==div ping-pong path.
        let b = (2.0f64).to_bits();
        for k in [1, 10, 100, 500, 1000] {
            let a = (2.0f64 * 2f64.powi(k)).to_bits();
            assert_eq!(dmod(a, b), 0.0f64.to_bits(), "k={k}");
            assert_eq!(dmod(a, b), host_remainder(a, b));
        }
        // Negative dividend: -0 with dividend sign.
        let a = (-8.0f64).to_bits();
        assert_eq!(dmod(a, b), (-0.0f64).to_bits());
        assert_eq!(dmod(a, b), host_remainder(a, b));
        // Odd multiples land on +-b/2 style residues.
        let mut rng = Rng(0x0ddc_0ffe_e15e_5eed);
        let mut vals: Vec<u64> = Vec::new();
        for _ in 0..1000 {
            let y = f64::from_bits(rng.next() & 0x7fff_ffff_ffff_ffff);
            if !y.is_finite() || y == 0.0 {
                continue;
            }
            let n = (rng.next() % 2000) as i32 - 1000;
            let x = y * n as f64;
            if !x.is_finite() {
                continue;
            }
            let (ab, bb) = (x.to_bits(), y.to_bits());
            let want = host_remainder(ab, bb);
            if f64::from_bits(want) != 0.0 && f64::from_bits(want).abs() < f64::MIN_POSITIVE {
                assert_eq!(dmod(ab, bb), 0);
            } else {
                assert_eq!(dmod(ab, bb), want, "x={x} y={y}");
            }
            vals.push(dmod(ab, bb));
        }
        assert!(!vals.is_empty());
    }

    // ---- iabs ----

    fn abs32(x: i32) -> i32 {
        unsafe { iabs(x) }
    }

    /// Reference: the original's `rsblt r0,r0,#0` is a 32-bit `0 - x`,
    /// which wraps for INT_MIN.
    fn ref_abs(x: i32) -> i32 {
        if x < 0 { 0i32.wrapping_sub(x) } else { x }
    }

    #[test]
    fn iabs_directed() {
        assert_eq!(abs32(0), 0);
        assert_eq!(abs32(1), 1);
        assert_eq!(abs32(-1), 1);
        assert_eq!(abs32(42), 42);
        assert_eq!(abs32(-42), 42);
        assert_eq!(abs32(i32::MAX), i32::MAX);
        assert_eq!(abs32(-i32::MAX), i32::MAX);
        // INT_MIN edge: 0 - INT_MIN wraps back to INT_MIN, matching
        // the original rsb; i32::abs would overflow.
        assert_eq!(abs32(i32::MIN), i32::MIN);
        assert_eq!(abs32(i32::MIN + 1), i32::MAX);
    }

    #[test]
    fn iabs_random_matches_reference() {
        let mut rng = Rng(0x5eed_5eed_5eed_5eed);
        for _ in 0..100_000 {
            let x = rng.next() as i32;
            assert_eq!(abs32(x), ref_abs(x), "x={x}");
            assert_eq!(abs32(x), x.wrapping_abs(), "x={x}");
        }
    }

    // ---- fixed16_div ----

    static FIXED16_DIV_LOCK: Mutex<()> = Mutex::new(());
    static mut RECIPROCAL_RESULT: i32 = 0;
    static mut RECIPROCAL_CALLS: usize = 0;
    static mut LAST_RECIPROCAL_INPUT: i32 = 0;

    unsafe extern "C" fn recording_reciprocal(divisor: i32) -> i32 {
        RECIPROCAL_CALLS += 1;
        LAST_RECIPROCAL_INPUT = divisor;
        RECIPROCAL_RESULT
    }

    struct ReciprocalInstall {
        previous: usize,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for ReciprocalInstall {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(FIXED16_RECIPROCAL).write_volatile(self.previous);
            }
        }
    }

    fn install_reciprocal(result: i32) -> ReciprocalInstall {
        let lock = FIXED16_DIV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let previous = core::ptr::addr_of!(FIXED16_RECIPROCAL).read_volatile();
            core::ptr::addr_of_mut!(FIXED16_RECIPROCAL)
                .write_volatile(recording_reciprocal as usize);
            RECIPROCAL_RESULT = result;
            RECIPROCAL_CALLS = 0;
            LAST_RECIPROCAL_INPUT = 0;
            ReciprocalInstall {
                previous,
                _lock: lock,
            }
        }
    }

    fn fixed_div(numerator: i32, divisor: i32) -> i32 {
        unsafe { fixed16_div(numerator, divisor) }
    }

    /// The two-register result construction from `smull`: `lsl hi,#16`
    /// and `orr` with `lsr lo,#16`, rather than a rounded multiply.
    fn funnel_product(a: i32, b: i32) -> i32 {
        let product = (a as i64) * (b as i64);
        (((product >> 32) as u32) << 16 | (product as u32 >> 16)) as i32
    }

    #[test]
    fn fixed16_div_dispatches_signed_top_byte_cases() {
        let _reciprocal = install_reciprocal(0x0001_0000);
        for (divisor, expected_input) in [
            (0x007f_ffff, 0x007f_ffff),
            (-0x0080_0000, -0x0080_0000),
            (0x0100_0000, 0x0001_0000),
            (-0x0200_0000, -0x0002_0000),
        ] {
            assert_eq!(fixed_div(0, divisor), 0);
            unsafe {
                assert_eq!(LAST_RECIPROCAL_INPUT, expected_input, "divisor={divisor:#x}");
            }
        }
        unsafe {
            assert_eq!(RECIPROCAL_CALLS, 4);
        }
    }

    #[test]
    fn fixed16_div_scales_both_operands_only_outside_24bit_range() {
        let reciprocal = -0x0001_8000;
        let _reciprocal = install_reciprocal(reciprocal);
        let numerator = 0x1234_8000;
        let divisor = 0x0100_0000;

        assert_eq!(
            fixed_div(numerator, divisor),
            funnel_product(reciprocal, numerator >> 8)
        );
        unsafe {
            assert_eq!(LAST_RECIPROCAL_INPUT, divisor >> 8);
            assert_eq!(RECIPROCAL_CALLS, 1);
        }
    }

    #[test]
    fn fixed16_div_preserves_the_wrapping_funnel_product() {
        let reciprocal = i32::MAX;
        let _reciprocal = install_reciprocal(reciprocal);
        let numerator = i32::MIN;
        let divisor = -1; // sign-extended top byte: no operand scaling.

        assert_eq!(
            fixed_div(numerator, divisor),
            funnel_product(reciprocal, numerator)
        );
        unsafe {
            assert_eq!(LAST_RECIPROCAL_INPUT, divisor);
        }
    }

    // ---- fixed16_div_indirect ----

    static FIXED16_DIV_INDIRECT_LOCK: Mutex<()> = Mutex::new(());
    static mut SDIV_RESULT: i32 = 0;
    static mut SDIV_CALLS: usize = 0;
    static mut LAST_SDIV_DIVIDEND: i32 = 0;
    static mut LAST_SDIV_DIVISOR: i32 = 0;

    unsafe extern "C" fn recording_sdiv(dividend: i32, divisor: i32) -> i32 {
        SDIV_CALLS += 1;
        LAST_SDIV_DIVIDEND = dividend;
        LAST_SDIV_DIVISOR = divisor;
        SDIV_RESULT
    }

    struct SdivInstall {
        previous: usize,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for SdivInstall {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(FIXED16_SDIV32).write_volatile(self.previous);
            }
        }
    }

    fn install_sdiv(
        implementation: unsafe extern "C" fn(i32, i32) -> i32,
        result: i32,
    ) -> SdivInstall {
        let lock = FIXED16_DIV_INDIRECT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let previous = core::ptr::addr_of!(FIXED16_SDIV32).read_volatile();
            core::ptr::addr_of_mut!(FIXED16_SDIV32).write_volatile(implementation as usize);
            SDIV_RESULT = result;
            SDIV_CALLS = 0;
            LAST_SDIV_DIVIDEND = 0;
            LAST_SDIV_DIVISOR = 0;
            SdivInstall {
                previous,
                _lock: lock,
            }
        }
    }

    #[test]
    fn fixed16_div_indirect_dereferences_dividend_and_returns_quotient() {
        let sentinel = -0x0d15_ea5e;
        let _sdiv = install_sdiv(recording_sdiv, sentinel);
        let dividend = 0x0012_d000; // 18.8125 in Q16.16
        let divisor = 0x0002_0000; // 2.0 in Q16.16

        assert_eq!(unsafe { fixed16_div_indirect(&dividend, divisor) }, sentinel);
        unsafe {
            assert_eq!(SDIV_CALLS, 1);
            assert_eq!(LAST_SDIV_DIVIDEND, dividend);
            assert_eq!(LAST_SDIV_DIVISOR, divisor);
        }
    }

    #[test]
    fn fixed16_div_indirect_loads_current_pointee_each_call() {
        let _sdiv = install_sdiv(recording_sdiv, 0);
        let mut slot = 1;
        for expected in [i32::MIN, -1, 0, 1, 0x7fff_ffff] {
            slot = expected;
            assert_eq!(unsafe { fixed16_div_indirect(&slot, 3) }, 0);
            unsafe {
                assert_eq!(LAST_SDIV_DIVIDEND, expected);
                assert_eq!(LAST_SDIV_DIVISOR, 3);
            }
        }
        unsafe {
            assert_eq!(SDIV_CALLS, 5);
        }
    }

    /// With the firmware core swapped for real truncating division the
    /// helper is exactly `*a / b` (wrapping on the INT_MIN / -1 corner,
    /// matching the ADS core's unsigned-magnitude loop).
    #[test]
    fn fixed16_div_indirect_delegates_truncating_division() {
        unsafe extern "C" fn truncating_sdiv(dividend: i32, divisor: i32) -> i32 {
            dividend.wrapping_div(divisor)
        }
        let _sdiv = install_sdiv(truncating_sdiv, 0);
        for (dividend, divisor, expected) in [
            (0x0012_d000, 0x0002_0000, 9), // ratio of two Q16.16 values: scales cancel
            (-0x0012_d000, 0x0002_0000, -9),
            (7, -2, -3),  // truncation toward zero, not floor
            (-7, 2, -3),
            (i32::MIN, -1, i32::MIN), // ADS magnitude loop wraps, no trap
            (0, 5, 0),
        ] {
            assert_eq!(unsafe { fixed16_div_indirect(&dividend, divisor) }, expected);
        }
    }

    // ---- fixed16_eq_indirect ----

    /// Call through real by-value copies so both pointer loads are
    /// exercised.
    fn eq_indirect(a: i32, b: i32) -> bool {
        unsafe { fixed16_eq_indirect(&a, &b) }
    }

    #[test]
    fn fixed16_eq_indirect_equal_values_match() {
        assert!(eq_indirect(0, 0));
        assert!(eq_indirect(FIX_ONE, FIX_ONE));
        assert!(eq_indirect(-FIX_ONE, -FIX_ONE));
        assert!(eq_indirect(i32::MAX, i32::MAX));
        assert!(eq_indirect(i32::MIN, i32::MIN));
        assert!(eq_indirect(0x1234_5678, 0x1234_5678));
    }

    #[test]
    fn fixed16_eq_indirect_differing_values_do_not_match() {
        assert!(!eq_indirect(FIX_ONE, 0));
        assert!(!eq_indirect(0, FIX_ONE));
        assert!(!eq_indirect(FIX_ONE, -FIX_ONE));
        // 1.0 != 0.5 and -1.0 != -1.5 in Q16.16.
        assert!(!eq_indirect(FIX_ONE, 0x0000_8000));
        assert!(!eq_indirect(-FIX_ONE, -0x0001_8000));
    }

    #[test]
    fn fixed16_eq_indirect_one_ulp_decides() {
        // A single ulp of difference (Q16.16 resolution) already makes
        // the values unequal, in both directions.
        assert!(!eq_indirect(1, 0));
        assert!(!eq_indirect(0, 1));
        assert!(!eq_indirect(FIX_ONE, FIX_ONE - 1));
        assert!(!eq_indirect(FIX_ONE - 1, FIX_ONE));
        assert!(!eq_indirect(-FIX_ONE + 1, -FIX_ONE));
        assert!(!eq_indirect(-FIX_ONE, -FIX_ONE + 1));
        // Equal again once the ulp gap is closed.
        assert!(eq_indirect(FIX_ONE - 1, FIX_ONE - 1));
    }

    #[test]
    fn fixed16_eq_indirect_signed_extremes() {
        // Raw bit-pattern equality: the EQ/NE conditions are
        // sign-agnostic, so 0 never equals -1 and the extremes only
        // match themselves.
        assert!(!eq_indirect(0, -1));
        assert!(!eq_indirect(-1, 0));
        assert!(!eq_indirect(i32::MAX, i32::MIN));
        assert!(!eq_indirect(i32::MIN, i32::MAX));
        assert!(!eq_indirect(i32::MAX, i32::MAX - 1));
        assert!(eq_indirect(-1, -1));
        // 32767.0 (i32::MAX & !0xffff) != -32768.0 (i32::MIN).
        assert!(!eq_indirect(i32::MAX & !0xffff, i32::MIN));
    }

    #[test]
    fn fixed16_eq_indirect_matches_reference() {
        let values = [
            0i32,
            1,
            -1,
            2,
            FIX_ONE,
            -FIX_ONE,
            0x8000,
            -0x8000,
            0x0001_0001,
            0x1234_5678,
            -0x1234_5678,
            0x7fff_ffff,
            i32::MIN,
        ];
        for &a in &values {
            for &b in &values {
                assert_eq!(eq_indirect(a, b), a == b, "a={a:#x} b={b:#x}");
            }
        }
        let mut rng = Rng(0x1ea5_1eaf_dead_beef);
        for _ in 0..100_000 {
            let a = rng.next() as i32;
            // Half the sweep compares two independent words, half forces
            // equality so the true branch is hit as often as the false.
            let b = if rng.next() & 1 == 0 { a } else { rng.next() as i32 };
            assert_eq!(eq_indirect(a, b), a == b, "a={a:#x} b={b:#x}");
        }
        // Dense sweep across the sign boundary, both directions.
        for a in -4096i32..4096 {
            for b in -4096i32..4096 {
                assert_eq!(eq_indirect(a, b), a == b, "a={a:#x} b={b:#x}");
            }
        }
    }

    // ---- fixed16_gt_indirect ----

    /// Call through real by-value copies so both pointer loads are
    /// exercised.
    fn gt_indirect(a: i32, b: i32) -> bool {
        unsafe { fixed16_gt_indirect(&a, &b) }
    }

    #[test]
    fn fixed16_gt_indirect_equal_values_are_not_greater() {
        assert!(!gt_indirect(0, 0));
        assert!(!gt_indirect(FIX_ONE, FIX_ONE));
        assert!(!gt_indirect(-FIX_ONE, -FIX_ONE));
        assert!(!gt_indirect(i32::MAX, i32::MAX));
        assert!(!gt_indirect(i32::MIN, i32::MIN));
        assert!(!gt_indirect(0x1234_5678, 0x1234_5678));
    }

    #[test]
    fn fixed16_gt_indirect_strict_ordering() {
        assert!(gt_indirect(FIX_ONE, 0));
        assert!(!gt_indirect(0, FIX_ONE));
        assert!(gt_indirect(FIX_ONE, -FIX_ONE));
        assert!(!gt_indirect(-FIX_ONE, FIX_ONE));
        // 1.0 > 0.5 and -1.0 > -1.5 in Q16.16.
        assert!(gt_indirect(FIX_ONE, 0x0000_8000));
        assert!(gt_indirect(-FIX_ONE, -0x0001_8000));
    }

    #[test]
    fn fixed16_gt_indirect_one_ulp_decides() {
        // A single ulp of difference (Q16.16 resolution) already flips
        // the result, in both directions.
        assert!(gt_indirect(1, 0));
        assert!(!gt_indirect(0, 1));
        assert!(gt_indirect(FIX_ONE, FIX_ONE - 1));
        assert!(!gt_indirect(FIX_ONE - 1, FIX_ONE));
        assert!(gt_indirect(-FIX_ONE + 1, -FIX_ONE));
        assert!(!gt_indirect(-FIX_ONE, -FIX_ONE + 1));
    }

    #[test]
    fn fixed16_gt_indirect_signed_extremes() {
        // Signed comparison: every non-negative is above every negative,
        // unlike an unsigned bit-pattern ordering.
        assert!(gt_indirect(0, -1));
        assert!(!gt_indirect(-1, 0));
        assert!(gt_indirect(i32::MAX, i32::MIN));
        assert!(!gt_indirect(i32::MIN, i32::MAX));
        assert!(gt_indirect(-1, i32::MIN));
        assert!(gt_indirect(i32::MAX, 0));
        assert!(gt_indirect(i32::MAX, i32::MAX - 1));
        // 32767.0 (i32::MAX & !0xffff) is above -32768.0 (i32::MIN).
        assert!(gt_indirect(i32::MAX & !0xffff, i32::MIN));
    }

    #[test]
    fn fixed16_gt_indirect_matches_reference() {
        let values = [
            0i32,
            1,
            -1,
            2,
            FIX_ONE,
            -FIX_ONE,
            0x8000,
            -0x8000,
            0x0001_0001,
            0x1234_5678,
            -0x1234_5678,
            0x7fff_ffff,
            i32::MIN,
        ];
        for &a in &values {
            for &b in &values {
                assert_eq!(gt_indirect(a, b), a > b, "a={a:#x} b={b:#x}");
            }
        }
        let mut rng = Rng(0x1ea5_1eaf_dead_beef);
        for _ in 0..100_000 {
            let a = rng.next() as i32;
            let b = rng.next() as i32;
            assert_eq!(gt_indirect(a, b), a > b, "a={a:#x} b={b:#x}");
        }
        // Dense sweep across the sign boundary, both directions.
        for a in -4096i32..4096 {
            for b in -4096i32..4096 {
                assert_eq!(gt_indirect(a, b), a > b, "a={a:#x} b={b:#x}");
            }
        }
    }

    // ---- fixed16_lt_indirect ----

    /// Call through real by-value copies so both pointer loads are
    /// exercised.
    fn lt_indirect(a: i32, b: i32) -> bool {
        unsafe { fixed16_lt_indirect(&a, &b) }
    }

    #[test]
    fn fixed16_lt_indirect_equal_values_are_not_less() {
        assert!(!lt_indirect(0, 0));
        assert!(!lt_indirect(FIX_ONE, FIX_ONE));
        assert!(!lt_indirect(-FIX_ONE, -FIX_ONE));
        assert!(!lt_indirect(i32::MAX, i32::MAX));
        assert!(!lt_indirect(i32::MIN, i32::MIN));
        assert!(!lt_indirect(0x1234_5678, 0x1234_5678));
    }

    #[test]
    fn fixed16_lt_indirect_strict_ordering() {
        assert!(lt_indirect(0, FIX_ONE));
        assert!(!lt_indirect(FIX_ONE, 0));
        assert!(lt_indirect(-FIX_ONE, FIX_ONE));
        assert!(!lt_indirect(FIX_ONE, -FIX_ONE));
        // 0.5 < 1.0 and -1.5 < -1.0 in Q16.16.
        assert!(lt_indirect(0x0000_8000, FIX_ONE));
        assert!(lt_indirect(-0x0001_8000, -FIX_ONE));
    }

    #[test]
    fn fixed16_lt_indirect_one_ulp_decides() {
        // A single ulp of difference (Q16.16 resolution) already flips
        // the result, in both directions.
        assert!(lt_indirect(0, 1));
        assert!(!lt_indirect(1, 0));
        assert!(lt_indirect(FIX_ONE - 1, FIX_ONE));
        assert!(!lt_indirect(FIX_ONE, FIX_ONE - 1));
        assert!(lt_indirect(-FIX_ONE, -FIX_ONE + 1));
        assert!(!lt_indirect(-FIX_ONE + 1, -FIX_ONE));
    }

    #[test]
    fn fixed16_lt_indirect_signed_extremes() {
        // Signed comparison: every negative is below every non-negative,
        // unlike an unsigned bit-pattern ordering.
        assert!(lt_indirect(-1, 0));
        assert!(!lt_indirect(0, -1));
        assert!(lt_indirect(i32::MIN, i32::MAX));
        assert!(!lt_indirect(i32::MAX, i32::MIN));
        assert!(lt_indirect(i32::MIN, -1));
        assert!(lt_indirect(0, i32::MAX));
        assert!(lt_indirect(i32::MAX - 1, i32::MAX));
        // -32768.0 (i32::MIN) is below 32767.0 (i32::MAX & !0xffff).
        assert!(lt_indirect(i32::MIN, i32::MAX & !0xffff));
    }

    #[test]
    fn fixed16_lt_indirect_matches_reference() {
        let values = [
            0i32,
            1,
            -1,
            2,
            FIX_ONE,
            -FIX_ONE,
            0x8000,
            -0x8000,
            0x0001_0001,
            0x1234_5678,
            -0x1234_5678,
            0x7fff_ffff,
            i32::MIN,
        ];
        for &a in &values {
            for &b in &values {
                assert_eq!(lt_indirect(a, b), a < b, "a={a:#x} b={b:#x}");
            }
        }
        let mut rng = Rng(0x1ea5_1eaf_dead_beef);
        for _ in 0..100_000 {
            let a = rng.next() as i32;
            let b = rng.next() as i32;
            assert_eq!(lt_indirect(a, b), a < b, "a={a:#x} b={b:#x}");
        }
        // Dense sweep across the sign boundary, both directions.
        for a in -4096i32..4096 {
            for b in -4096i32..4096 {
                assert_eq!(lt_indirect(a, b), a < b, "a={a:#x} b={b:#x}");
            }
        }
    }

    // ---- fixed16_sub_indirect ----

    /// Call through a real by-value copy so the pointer load is
    /// exercised.
    fn sub_indirect(a: i32, b: i32) -> i32 {
        unsafe { fixed16_sub_indirect(&a, &b) }
    }

    #[test]
    fn fixed16_sub_indirect_zero_and_identity() {
        assert_eq!(sub_indirect(0, 0), 0);
        assert_eq!(sub_indirect(FIX_ONE, 0), FIX_ONE);
        assert_eq!(sub_indirect(0, FIX_ONE), -FIX_ONE);
        assert_eq!(sub_indirect(FIX_ONE, FIX_ONE), 0);
        // 2.5 - 1.0 = 1.5 and 1.0 - 2.5 = -1.5, exact in Q16.16.
        assert_eq!(sub_indirect(0x0002_8000, FIX_ONE), 0x0001_8000);
        assert_eq!(sub_indirect(FIX_ONE, 0x0002_8000), -0x0001_8000);
    }

    #[test]
    fn fixed16_sub_indirect_one_ulp_is_exact() {
        // A single ulp of difference (Q16.16 resolution) survives the
        // subtraction exactly, in both directions.
        assert_eq!(sub_indirect(1, 0), 1);
        assert_eq!(sub_indirect(0, 1), -1);
        assert_eq!(sub_indirect(0x0001_0001, FIX_ONE), 1);
        assert_eq!(sub_indirect(FIX_ONE, 0x0001_0001), -1);
    }

    #[test]
    fn fixed16_sub_indirect_signed_extremes_wrap() {
        // Plain non-flag-setting `sub`: wraps modulo 2^32, no
        // saturation. -32768.0 - 1ulp wraps to just below 32768.0.
        assert_eq!(sub_indirect(i32::MIN, 1), i32::MAX);
        assert_eq!(sub_indirect(i32::MAX, -1), i32::MIN);
        assert_eq!(sub_indirect(i32::MIN, i32::MIN), 0);
        assert_eq!(sub_indirect(i32::MIN, i32::MAX), 1);
        // 32767.0 - (-32768.0) = 65535.0 wraps to -1.0.
        assert_eq!(sub_indirect(i32::MAX & !0xffff, i32::MIN), -FIX_ONE);
    }

    #[test]
    fn fixed16_sub_indirect_matches_reference() {
        let values = [
            0i32,
            1,
            -1,
            2,
            FIX_ONE,
            -FIX_ONE,
            0x8000,
            -0x8000,
            0x0001_0001,
            0x1234_5678,
            -0x1234_5678,
            0x7fff_ffff,
            i32::MIN,
        ];
        for &a in &values {
            for &b in &values {
                assert_eq!(sub_indirect(a, b), a.wrapping_sub(b), "a={a:#x} b={b:#x}");
            }
        }
        let mut rng = Rng(0x5eed_c0de_1bad_f00d);
        for _ in 0..100_000 {
            let a = rng.next() as i32;
            let b = rng.next() as i32;
            assert_eq!(sub_indirect(a, b), a.wrapping_sub(b), "a={a:#x} b={b:#x}");
        }
        // Dense sweep across the sign boundary, both directions.
        for a in -4096i32..4096 {
            for b in -4096i32..4096 {
                assert_eq!(sub_indirect(a, b), a.wrapping_sub(b), "a={a:#x} b={b:#x}");
            }
        }
    }

    // ---- fixed16_mul_indirect ----

    /// Q16.16 one (1.0), the multiplicative identity of this format.
    const FIX_ONE: i32 = 0x0001_0000;

    /// Call through a real by-value copy so the pointer load is exercised.
    fn mul_indirect(a: i32, b: i32) -> i32 {
        unsafe { fixed16_mul_indirect(&a, b) }
    }

    /// Reference: full signed 64-bit product, arithmetic >> 16, truncate
    /// to 32 bits — equal to the original's (hi << 16) | (lo >> 16) funnel
    /// for every input.
    fn ref_mul_indirect(a: i32, b: i32) -> i32 {
        (((a as i64) * (b as i64)) >> 16) as i32
    }

    #[test]
    fn fixed16_mul_indirect_zero_and_identity() {
        assert_eq!(mul_indirect(0, FIX_ONE), 0);
        assert_eq!(mul_indirect(FIX_ONE, 0), 0);
        assert_eq!(mul_indirect(0, 0), 0);
        // 1.0 * 1.0 = 1.0: 0x10000 * 0x10000 = 2^32, >> 16 = 0x10000.
        assert_eq!(mul_indirect(FIX_ONE, FIX_ONE), FIX_ONE);
        // 2.5 * 4.0 = 10.0, exact.
        assert_eq!(mul_indirect(0x0002_8000, 0x0004_0000), 0x000a_0000);
    }

    #[test]
    fn fixed16_mul_indirect_negative_operands() {
        assert_eq!(mul_indirect(-FIX_ONE, FIX_ONE), -FIX_ONE);
        assert_eq!(mul_indirect(FIX_ONE, -FIX_ONE), -FIX_ONE);
        assert_eq!(mul_indirect(-FIX_ONE, -FIX_ONE), FIX_ONE);
        // -1.5 * 2.0 = -3.0, exact.
        assert_eq!(mul_indirect(-0x0001_8000, 0x0002_0000), -0x0003_0000);
    }

    #[test]
    fn fixed16_mul_indirect_sign_extends_the_product_high_half() {
        // product = -1: smull high half is 0xffffffff. The funnel keeps
        // the sign extension: 0xffff_0000 | 0xffff = -1. Dropping it
        // (zero-extended high half) would give 0x0000_ffff.
        assert_eq!(mul_indirect(-1, 1), -1);
        assert_eq!(mul_indirect(1, -1), -1);
        // -2.0 * 1.0: product 0xfffffffe_00000000 -> 0xfffe_0000.
        assert_eq!(mul_indirect(-0x0002_0000, FIX_ONE), -0x0002_0000);
    }

    #[test]
    fn fixed16_mul_indirect_truncates_toward_negative_infinity() {
        // 1 ulp * 1 ulp = 2^-32, below resolution: truncates to 0.
        assert_eq!(mul_indirect(1, 1), 0);
        // Negative fraction floors, it does not truncate toward zero:
        // -1 ulp * 1 ulp = -2^-32 -> -1 (0xffffffff), NOT 0.
        assert_eq!(mul_indirect(-1, 1), -1);
        assert_eq!(mul_indirect(-3, 1), -1);
        // -0.5 ulp of the result still floors to -1.
        assert_eq!(mul_indirect(-1, 2), -1);
        // Exact negative products are unaffected by the shift direction.
        assert_eq!(mul_indirect(-0x0001_8000, FIX_ONE), -0x0001_8000);
    }

    #[test]
    fn fixed16_mul_indirect_wraps_the_low_32_bits() {
        // i32::MAX^2 = 0x3fffffff_00000001; bits [47:16] = 0xffff_0000.
        // The original wraps to -65536, no clamping or saturation.
        assert_eq!(mul_indirect(i32::MAX, i32::MAX), -FIX_ONE);
        // i32::MIN^2 = 0x40000000_00000000; bits [47:16] = 0.
        assert_eq!(mul_indirect(i32::MIN, i32::MIN), 0);
        // 1.0 * -32768.0 = -2^47; bits [47:16] = 0x8000_0000 (i32::MIN).
        assert_eq!(mul_indirect(FIX_ONE, i32::MIN), i32::MIN);
        // i32::MIN * i32::MAX = 0xc0000000_80000000; bits [47:16] =
        // 0x0000_8000 (positive despite the negative product).
        assert_eq!(mul_indirect(i32::MIN, i32::MAX), 0x0000_8000);
    }

    #[test]
    fn fixed16_mul_indirect_equals_the_original_register_assembly() {
        // Mirror the original instruction by instruction: smull, then
        // (hi << 16) | (lo >> 16) on the raw halves (the funnel_product
        // helper used by the fixed16_div tests).
        for &(a, b) in &[
            (0x1234_5678i32, 0x0000_1000i32),
            (-0x1234_5678, 0x0000_1000),
            (0x1234_5678, -0x0000_1000),
            (-0x1234_5678, -0x0000_1000),
            (i32::MAX, i32::MAX),
            (i32::MIN, i32::MIN),
            (i32::MIN, i32::MAX),
            (-1, -1),
        ] {
            assert_eq!(mul_indirect(a, b), funnel_product(a, b), "a={a:#x} b={b:#x}");
        }
    }

    #[test]
    fn fixed16_mul_indirect_matches_reference() {
        let values = [
            0i32,
            1,
            -1,
            2,
            FIX_ONE,
            -FIX_ONE,
            0x8000,
            -0x8000,
            0x0001_0001,
            -0x0001_0001,
            0x1234_5678,
            -0x1234_5678,
            0x7fff_ffff,
            i32::MIN,
        ];
        for &a in &values {
            for &b in &values {
                assert_eq!(mul_indirect(a, b), ref_mul_indirect(a, b), "a={a:#x} b={b:#x}");
            }
        }
        let mut rng = Rng(0xfeed_5eed_c0ff_ee11);
        for _ in 0..100_000 {
            let a = rng.next() as i32;
            let b = rng.next() as i32;
            assert_eq!(mul_indirect(a, b), ref_mul_indirect(a, b), "a={a:#x} b={b:#x}");
        }
    }

    // ---- fixed16_ne_indirect ----

    /// Call through real by-value copies so both pointer loads are
    /// exercised.
    fn ne_indirect(a: i32, b: i32) -> bool {
        unsafe { fixed16_ne_indirect(&a, &b) }
    }

    #[test]
    fn fixed16_ne_indirect_equal_values() {
        assert!(!ne_indirect(0, 0));
        assert!(!ne_indirect(FIX_ONE, FIX_ONE));
        assert!(!ne_indirect(-FIX_ONE, -FIX_ONE));
        assert!(!ne_indirect(i32::MAX, i32::MAX));
        assert!(!ne_indirect(i32::MIN, i32::MIN));
        // -0 does not exist in two's complement: 0 == 0 bit pattern only.
        assert!(!ne_indirect(0x1234_5678, 0x1234_5678));
    }

    #[test]
    fn fixed16_ne_indirect_one_ulp_differences() {
        // The comparator is a raw bit-pattern compare: a single ulp of
        // difference (Q16.16 resolution) already counts as "not equal".
        assert!(ne_indirect(0, 1));
        assert!(ne_indirect(1, 0));
        assert!(ne_indirect(-1, 0));
        assert!(ne_indirect(FIX_ONE, FIX_ONE + 1));
        assert!(ne_indirect(FIX_ONE, FIX_ONE - 1));
        assert!(ne_indirect(-FIX_ONE, -FIX_ONE + 1));
        // Signs: +0 vs the smallest negative step.
        assert!(ne_indirect(0, -1));
    }

    #[test]
    fn fixed16_ne_indirect_extremes_and_wrap_boundaries() {
        assert!(ne_indirect(i32::MAX, i32::MIN));
        assert!(ne_indirect(i32::MIN, i32::MAX));
        // Adjacent across the sign boundary.
        assert!(ne_indirect(i32::MAX, -1));
        assert!(ne_indirect(i32::MIN, 0));
        // 32767.0 vs -32768.0: the largest representable span.
        assert!(ne_indirect(i32::MAX & !0xffff, i32::MIN));
    }

    #[test]
    fn fixed16_ne_indirect_matches_reference() {
        let values = [
            0i32,
            1,
            -1,
            2,
            FIX_ONE,
            -FIX_ONE,
            0x8000,
            -0x8000,
            0x0001_0001,
            0x1234_5678,
            -0x1234_5678,
            0x7fff_ffff,
            i32::MIN,
        ];
        for &a in &values {
            for &b in &values {
                assert_eq!(ne_indirect(a, b), a != b, "a={a:#x} b={b:#x}");
            }
        }
        let mut rng = Rng(0xb01d_face_cafe_beef);
        for _ in 0..100_000 {
            let a = rng.next() as i32;
            let b = rng.next() as i32;
            assert_eq!(ne_indirect(a, b), a != b, "a={a:#x} b={b:#x}");
        }
        // Dense near-equality sweep: every small delta around zero both ways.
        for a in -4096i32..4096 {
            for b in -4096i32..4096 {
                assert_eq!(ne_indirect(a, b), a != b, "a={a:#x} b={b:#x}");
            }
        }
    }

    // ---- fixed16_add_indirect ----

    /// Call through a real by-value copy so the pointer load is
    /// exercised.
    fn add_indirect(a: i32, b: i32) -> i32 {
        unsafe { fixed16_add_indirect(&a, &b) }
    }

    #[test]
    fn fixed16_add_indirect_zero_and_identity() {
        assert_eq!(add_indirect(0, 0), 0);
        assert_eq!(add_indirect(FIX_ONE, 0), FIX_ONE);
        assert_eq!(add_indirect(0, FIX_ONE), FIX_ONE);
        assert_eq!(add_indirect(FIX_ONE, -FIX_ONE), 0);
        // 2.5 + 1.0 = 3.5 and 1.0 + -2.5 = -1.5, exact in Q16.16.
        assert_eq!(add_indirect(0x0002_8000, FIX_ONE), 0x0003_8000);
        assert_eq!(add_indirect(FIX_ONE, -0x0002_8000), -0x0001_8000);
    }

    #[test]
    fn fixed16_add_indirect_one_ulp_is_exact() {
        // A single ulp (Q16.16 resolution) survives the addition
        // exactly, in both directions.
        assert_eq!(add_indirect(1, 0), 1);
        assert_eq!(add_indirect(0, 1), 1);
        assert_eq!(add_indirect(1, -1), 0);
        assert_eq!(add_indirect(FIX_ONE, 1), 0x0001_0001);
        assert_eq!(add_indirect(0x0001_0001, -FIX_ONE), 1);
    }

    #[test]
    fn fixed16_add_indirect_signed_extremes_wrap() {
        // Plain non-flag-setting `add`: wraps modulo 2^32, no
        // saturation. 32768.0 + 1ulp wraps to just above -32768.0.
        assert_eq!(add_indirect(i32::MAX, 1), i32::MIN);
        assert_eq!(add_indirect(i32::MIN, -1), i32::MAX);
        assert_eq!(add_indirect(i32::MIN, i32::MIN), 0);
        assert_eq!(add_indirect(i32::MAX, i32::MAX), -2);
        // 32767.0 + 32768.0 = 65535.0 wraps to -1.0.
        assert_eq!(add_indirect(i32::MAX & !0xffff, i32::MIN), -FIX_ONE);
    }

    #[test]
    fn fixed16_add_indirect_matches_reference() {
        let values = [
            0i32,
            1,
            -1,
            2,
            FIX_ONE,
            -FIX_ONE,
            0x8000,
            -0x8000,
            0x0001_0001,
            0x1234_5678,
            -0x1234_5678,
            0x7fff_ffff,
            i32::MIN,
        ];
        for &a in &values {
            for &b in &values {
                assert_eq!(add_indirect(a, b), a.wrapping_add(b), "a={a:#x} b={b:#x}");
            }
        }
        let mut rng = Rng(0xadd1_c7ed_f16d_c0de);
        for _ in 0..100_000 {
            let a = rng.next() as i32;
            let b = rng.next() as i32;
            assert_eq!(add_indirect(a, b), a.wrapping_add(b), "a={a:#x} b={b:#x}");
        }
        // Dense sweep across the sign boundary, both directions.
        for a in -4096i32..4096 {
            for b in -4096i32..4096 {
                assert_eq!(add_indirect(a, b), a.wrapping_add(b), "a={a:#x} b={b:#x}");
            }
        }
    }

    // ---- message_kind_byte ----

    /// The 12-byte UI message envelope the original reads: vtable word
    /// at +0x0, kind byte at +0x4, union word at +0x8.
    fn envelope(kind: u8) -> [u8; 12] {
        let mut bytes = [0xaau8; 12];
        bytes[4] = kind;
        bytes
    }

    #[test]
    fn message_kind_byte_reads_the_tag_at_offset_4() {
        for kind in [0u8, 1, 2, 0x16, 0x7f, 0x80, 0xff] {
            let storage = envelope(kind);
            assert_eq!(unsafe { message_kind_byte(storage.as_ptr()) }, kind);
        }
    }

    #[test]
    fn message_kind_byte_reads_only_the_low_byte_of_the_kind_word() {
        // The +0x4 accessor is a byte load (ldrb): a kind word of
        // 0x20003 (seen at a message_kind_construct call site) reads
        // back as its little-endian low byte 0x03, and the upper
        // bytes of the word are invisible.
        let mut storage = [0u8; 12];
        storage[4..8].copy_from_slice(&0x20003u32.to_le_bytes());
        assert_eq!(unsafe { message_kind_byte(storage.as_ptr()) }, 0x03);
    }

    #[test]
    fn message_kind_byte_ignores_neighbouring_bytes() {
        // Only offset 4 is read: every other byte of the envelope is
        // irrelevant to the result.
        let mut storage = [0u8; 12];
        storage[4] = 1;
        assert_eq!(unsafe { message_kind_byte(storage.as_ptr()) }, 1);
        let mut rng = Rng(0x5eed_c0de_5eed_c0de);
        for _ in 0..1_000 {
            let mut storage = [0u8; 12];
            for byte in &mut storage {
                *byte = rng.next() as u8;
            }
            let kind = rng.next() as u8;
            storage[4] = kind;
            assert_eq!(unsafe { message_kind_byte(storage.as_ptr()) }, kind);
        }
    }

    // ---- message_payload_word ----

    #[test]
    fn message_payload_word_reads_the_word_at_offset_8() {
        for word in [
            0u32,
            1,
            0x20,
            0x500,
            0x501,
            0x0001_0000,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_ffff,
        ] {
            let mut storage = [0xaau8; 12];
            storage[8..12].copy_from_slice(&word.to_le_bytes());
            assert_eq!(
                unsafe { message_payload_word(storage.as_ptr() as *const u32) },
                word
            );
        }
    }

    #[test]
    fn message_payload_word_returns_all_32_bits() {
        // The +0x8 accessor is a word load (ldr): unlike the kind
        // byte's ldrb, the upper bytes are part of the result and the
        // byte order is little-endian.
        let mut storage = [0u8; 12];
        storage[8..12].copy_from_slice(&[0x44, 0x33, 0x22, 0x11]);
        assert_eq!(
            unsafe { message_payload_word(storage.as_ptr() as *const u32) },
            0x1122_3344
        );
    }

    #[test]
    fn message_payload_word_ignores_neighbouring_bytes() {
        // Only the +0x8 word is read: the vtable word at +0x0 and the
        // kind byte at +0x4 are irrelevant to the result.
        let mut storage = [0u8; 12];
        storage[8..12].copy_from_slice(&0x501u32.to_le_bytes());
        assert_eq!(
            unsafe { message_payload_word(storage.as_ptr() as *const u32) },
            0x501
        );
        let mut rng = Rng(0x5eed_8a10_5eed_8a10);
        for _ in 0..1_000 {
            let mut storage = [0u8; 12];
            for byte in &mut storage {
                *byte = rng.next() as u8;
            }
            let word = rng.next() as u32;
            storage[8..12].copy_from_slice(&word.to_le_bytes());
            assert_eq!(
                unsafe { message_payload_word(storage.as_ptr() as *const u32) },
                word
            );
        }
    }

    // ---- message_code_word ----

    #[test]
    fn message_code_word_reads_the_word_at_offset_4() {
        for word in [
            0u32,
            1,
            0x500,
            0x501,
            0x0001_0000,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_ffff,
        ] {
            let mut storage = [0xaau8; 12];
            storage[4..8].copy_from_slice(&word.to_le_bytes());
            assert_eq!(
                unsafe { message_code_word(storage.as_ptr() as *const u32) },
                word
            );
        }
    }

    #[test]
    fn message_code_word_returns_all_32_bits() {
        // The +0x4 accessor is a word load (ldr): unlike the kind
        // byte's ldrb on the envelope, the upper bytes are part of
        // the result and the byte order is little-endian.
        let mut storage = [0u8; 12];
        storage[4..8].copy_from_slice(&[0x44, 0x33, 0x22, 0x11]);
        assert_eq!(
            unsafe { message_code_word(storage.as_ptr() as *const u32) },
            0x1122_3344
        );
    }

    #[test]
    fn message_code_word_ignores_neighbouring_bytes() {
        // Only the +0x4 word is read: the vtable word at +0x0 and
        // the union word at +0x8 are irrelevant to the result.
        let mut storage = [0u8; 12];
        storage[4..8].copy_from_slice(&0x500u32.to_le_bytes());
        assert_eq!(
            unsafe { message_code_word(storage.as_ptr() as *const u32) },
            0x500
        );
        let mut rng = Rng(0x5eed_c04e_5eed_c04e);
        for _ in 0..1_000 {
            let mut storage = [0u8; 12];
            for byte in &mut storage {
                *byte = rng.next() as u8;
            }
            let word = rng.next() as u32;
            storage[4..8].copy_from_slice(&word.to_le_bytes());
            assert_eq!(
                unsafe { message_code_word(storage.as_ptr() as *const u32) },
                word
            );
        }
    }

    // ---- query_name_to_cxx_string ----

    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;

    /// Serializes the tests that swap the three QUERY_OBJECT_* seams
    /// (the FIXED16_DIV_LOCK precedent above).
    static QUERY_NAME_LOCK: Mutex<()> = Mutex::new(());

    /// Bump arena backing the heap-ops `alloc` slot for these tests
    /// (the cxx/string.rs precedent): the rep allocation must be
    /// writable, and the shared mock in heap/veneers hands out a fixed
    /// fake address.
    const QUERY_ARENA_SIZE: usize = 4096;

    #[repr(C, align(8))]
    struct QueryArena([u8; QUERY_ARENA_SIZE]);

    static mut QUERY_ARENA: QueryArena = QueryArena([0; QUERY_ARENA_SIZE]);
    static mut QUERY_ARENA_USED: usize = 0;
    /// Every (pointer, tag) the arena `free` slot recorded, in order.
    static mut QUERY_FREES: Vec<(*mut u8, usize)> = Vec::new();

    unsafe extern "C" fn query_arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = QUERY_ARENA_USED;
        let aligned = (size + 7) & !7;
        if used + aligned > QUERY_ARENA_SIZE {
            return core::ptr::null_mut();
        }
        QUERY_ARENA_USED = used + aligned;
        core::ptr::addr_of_mut!(QUERY_ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn query_arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(QUERY_FREES)).push((ptr, tag));
    }

    unsafe extern "C" fn query_arena_create(
        desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        desc as *mut HeapDescriptorDescriptor
    }

    /// Callee event log: the mocks push their names as they run.
    static mut QUERY_EVENTS: Vec<&'static str> = Vec::new();
    static mut CONSTRUCT_QUERY: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_ID: u32 = u32::MAX;
    static mut CONSTRUCT_MODE: u32 = u32::MAX;
    static mut NAME_OUT: *mut StringObject = core::ptr::null_mut();
    static mut NAME_QUERY: *const u8 = core::ptr::null();
    static mut DESTROY_QUERY: *mut u8 = core::ptr::null_mut();
    /// Payload the name mock installs into the StringObject; NULL makes
    /// `string_object_c_str` fall back to the shared empty C string.
    static mut NAME_PAYLOAD_TO_INSTALL: *mut u8 = core::ptr::null_mut();
    /// Backing text for the installed payload (a static: the arena
    /// `free` slot only records, it never actually releases).
    static mut NAME_TEXT: [u8; 96] = [0; 96];

    unsafe extern "C" fn recording_construct(query: *mut u8, id: u32, mode: u32) -> *mut u8 {
        (*core::ptr::addr_of_mut!(QUERY_EVENTS)).push("construct");
        CONSTRUCT_QUERY = query;
        CONSTRUCT_ID = id;
        CONSTRUCT_MODE = mode;
        query
    }

    unsafe extern "C" fn recording_name(out: *mut StringObject, query: *const u8) {
        (*core::ptr::addr_of_mut!(QUERY_EVENTS)).push("name");
        NAME_OUT = out;
        NAME_QUERY = query;
        (*out).vtable = &STRING_OBJECT_VTABLE;
        (*out).payload = NAME_PAYLOAD_TO_INSTALL;
    }

    unsafe extern "C" fn recording_destroy(query: *mut u8) {
        (*core::ptr::addr_of_mut!(QUERY_EVENTS)).push("destroy");
        DESTROY_QUERY = query;
    }

    struct QueryMockInstall {
        previous_construct: usize,
        previous_name: usize,
        previous_destroy: usize,
        _seam_lock: MutexGuard<'static, ()>,
        _heap_lock: MutexGuard<'static, ()>,
    }

    impl Drop for QueryMockInstall {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(QUERY_OBJECT_CONSTRUCT)
                    .write_volatile(self.previous_construct);
                core::ptr::addr_of_mut!(QUERY_OBJECT_NAME)
                    .write_volatile(self.previous_name);
                core::ptr::addr_of_mut!(QUERY_OBJECT_DESTROY)
                    .write_volatile(self.previous_destroy);
            }
        }
    }

    /// Installs the recording mocks on all three seams plus the arena
    /// over the shared heap-ops table, and resets every log.
    fn install_query_mocks() -> QueryMockInstall {
        let seam_lock = QUERY_NAME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_lock = crate::heap::veneers::tests::mock_heap();
        unsafe {
            QUERY_ARENA_USED = 0;
            (*core::ptr::addr_of_mut!(QUERY_FREES)).clear();
            (*core::ptr::addr_of_mut!(QUERY_EVENTS)).clear();
            CONSTRUCT_QUERY = core::ptr::null_mut();
            CONSTRUCT_ID = u32::MAX;
            CONSTRUCT_MODE = u32::MAX;
            NAME_OUT = core::ptr::null_mut();
            NAME_QUERY = core::ptr::null();
            DESTROY_QUERY = core::ptr::null_mut();
            NAME_PAYLOAD_TO_INSTALL = core::ptr::null_mut();
            let ops = core::ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = query_arena_alloc;
            (*ops).free = query_arena_free;
            (*ops).create = query_arena_create;
            let previous_construct =
                core::ptr::addr_of!(QUERY_OBJECT_CONSTRUCT).read_volatile();
            core::ptr::addr_of_mut!(QUERY_OBJECT_CONSTRUCT)
                .write_volatile(recording_construct as usize);
            let previous_name = core::ptr::addr_of!(QUERY_OBJECT_NAME).read_volatile();
            core::ptr::addr_of_mut!(QUERY_OBJECT_NAME)
                .write_volatile(recording_name as usize);
            let previous_destroy =
                core::ptr::addr_of!(QUERY_OBJECT_DESTROY).read_volatile();
            core::ptr::addr_of_mut!(QUERY_OBJECT_DESTROY)
                .write_volatile(recording_destroy as usize);
            QueryMockInstall {
                previous_construct,
                previous_name,
                previous_destroy,
                _seam_lock: seam_lock,
                _heap_lock: heap_lock,
            }
        }
    }

    /// Points the name mock's payload at `text` (a NUL-terminated C
    /// string, without the trailing NUL in the slice).
    fn install_name_text(text: &[u8]) {
        unsafe {
            let storage = core::ptr::addr_of_mut!(NAME_TEXT).cast::<u8>();
            core::ptr::copy_nonoverlapping(text.as_ptr(), storage, text.len());
            storage.add(text.len()).write(0);
            NAME_PAYLOAD_TO_INSTALL = storage;
        }
    }

    /// The rep header below a produced string's data pointer.
    unsafe fn produced_rep(data: *mut u8) -> (i32, u32, u32) {
        let rep = crate::cxx::string::data_rep(data);
        ((*rep).refcount, (*rep).capacity, (*rep).length)
    }

    #[test]
    fn query_name_constructs_names_copies_and_destroys_in_order() {
        let _mocks = install_query_mocks();
        install_name_text(b"settings");
        let mut slot: *mut u8 = core::ptr::null_mut();

        unsafe {
            query_name_to_cxx_string(&mut slot);

            assert_eq!(
                *core::ptr::addr_of!(QUERY_EVENTS),
                Vec::from(["construct", "name", "destroy"])
            );
            // The default query object: id byte 0, mode byte 0.
            assert_eq!(CONSTRUCT_ID, 0);
            assert_eq!(CONSTRUCT_MODE, 0);
            // One shared query buffer travels through all three calls.
            assert!(!CONSTRUCT_QUERY.is_null());
            assert_eq!(NAME_QUERY, CONSTRUCT_QUERY as *const u8);
            assert_eq!(DESTROY_QUERY, CONSTRUCT_QUERY);
            assert!(!NAME_OUT.is_null());

            // The produced string owns a fresh rep: refcount 0, the
            // 0x20 capacity floor (length 8 < 0x20), length stamped.
            assert!(!slot.is_null());
            assert_ne!(slot, crate::cxx::string::empty_rep_data());
            assert_eq!(produced_rep(slot), (0, 0x20, 8));
            assert_eq!(core::slice::from_raw_parts(slot, 9), b"settings\0");

            // The name holder's payload was released through the
            // tag-0x34 free path.
            let payload = core::ptr::addr_of_mut!(NAME_TEXT).cast::<u8>();
            assert_eq!(
                *core::ptr::addr_of!(QUERY_FREES),
                Vec::from([(payload, 0x34usize)])
            );
        }
    }

    #[test]
    fn query_name_applies_the_capacity_floor_at_0x20() {
        let _mocks = install_query_mocks();
        // (name length, expected capacity): the original picks
        // max(0x20, length) with its addhi/movls slot select.
        for (length, expected_capacity) in [
            (1usize, 0x20u32),
            (0x1f, 0x20),
            (0x20, 0x20),
            (0x21, 0x21),
            (0x40, 0x40),
        ] {
            unsafe {
                QUERY_ARENA_USED = 0;
                (*core::ptr::addr_of_mut!(QUERY_FREES)).clear();
                let text: Vec<u8> = (0..length).map(|i| b'a' + (i % 26) as u8).collect();
                install_name_text(&text);
                let mut slot: *mut u8 = core::ptr::null_mut();

                query_name_to_cxx_string(&mut slot);

                assert_eq!(
                    produced_rep(slot),
                    (0, expected_capacity, length as u32),
                    "length={length}"
                );
                assert_eq!(core::slice::from_raw_parts(slot, length), text.as_slice());
                assert_eq!(*slot.add(length), 0, "NUL at data[length]");
            }
        }
    }

    #[test]
    fn query_name_empty_name_parks_on_the_shared_empty_rep() {
        let _mocks = install_query_mocks();
        // A NULL payload makes string_object_c_str substitute the
        // shared empty C string, whose strlen is 0.
        let mut slot: *mut u8 = core::ptr::null_mut();

        unsafe {
            query_name_to_cxx_string(&mut slot);

            assert_eq!(
                *core::ptr::addr_of!(QUERY_EVENTS),
                Vec::from(["construct", "name", "destroy"])
            );
            assert_eq!(slot, crate::cxx::string::empty_rep_data());
            assert_eq!(*slot, 0);
            assert_eq!(
                QUERY_ARENA_USED, 0,
                "an empty name never allocates a rep"
            );
            assert!(
                (*core::ptr::addr_of!(QUERY_FREES)).is_empty(),
                "the NULL payload takes release_payload's early-out"
            );
        }
    }

    // ---- context_text_to_cxx_string ----

    /// Serializes the tests that swap the two counted-u16 marshaling
    /// seams (the QUERY_NAME_LOCK precedent above).
    static CONTEXT_TEXT_LOCK: Mutex<()> = Mutex::new(());

    /// Callee event log: the mocks push their names as they run.
    static mut CONTEXT_EVENTS: Vec<&'static str> = Vec::new();
    static mut SERIALIZE_BUFFER: *mut u16 = core::ptr::null_mut();
    static mut DESERIALIZE_BUFFER: *const u16 = core::ptr::null();
    static mut DESERIALIZE_STRING: *mut *mut u8 = core::ptr::null_mut();
    /// Count the serialize mock stamps into the buffer.
    static mut SERIALIZE_COUNT: u16 = 0;
    /// What the deserialize mock observed: the count word and the
    /// first few code units.
    static mut OBSERVED_COUNT: u16 = 0;
    static mut OBSERVED_UNITS: [u16; 8] = [0; 8];

    unsafe extern "C" fn recording_serialize(counted: *mut u16) {
        (*core::ptr::addr_of_mut!(CONTEXT_EVENTS)).push("serialize");
        SERIALIZE_BUFFER = counted;
        let count = SERIALIZE_COUNT;
        *counted = count;
        for i in 0..count as usize {
            *counted.add(1 + i) = 0x40 + i as u16;
        }
    }

    unsafe extern "C" fn recording_deserialize(counted: *const u16, string: *mut *mut u8) {
        (*core::ptr::addr_of_mut!(CONTEXT_EVENTS)).push("deserialize");
        DESERIALIZE_BUFFER = counted;
        DESERIALIZE_STRING = string;
        let count = *counted;
        OBSERVED_COUNT = count;
        let kept = (count as usize).min(OBSERVED_UNITS.len());
        for i in 0..kept {
            OBSERVED_UNITS[i] = *counted.add(1 + i);
        }
    }

    struct ContextMockInstall {
        previous_serialize: usize,
        previous_deserialize: usize,
        _seam_lock: MutexGuard<'static, ()>,
    }

    impl Drop for ContextMockInstall {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CONTEXT_TEXT_TO_COUNTED_U16)
                    .write_volatile(self.previous_serialize);
                core::ptr::addr_of_mut!(COUNTED_U16_TO_CXX_STRING)
                    .write_volatile(self.previous_deserialize);
            }
        }
    }

    /// Installs the recording mocks on both seams and resets every log.
    fn install_context_mocks() -> ContextMockInstall {
        let seam_lock = CONTEXT_TEXT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CONTEXT_EVENTS)).clear();
            SERIALIZE_BUFFER = core::ptr::null_mut();
            DESERIALIZE_BUFFER = core::ptr::null();
            DESERIALIZE_STRING = core::ptr::null_mut();
            SERIALIZE_COUNT = 0;
            OBSERVED_COUNT = u16::MAX;
            OBSERVED_UNITS = [0; 8];
            let previous_serialize =
                core::ptr::addr_of!(CONTEXT_TEXT_TO_COUNTED_U16).read_volatile();
            core::ptr::addr_of_mut!(CONTEXT_TEXT_TO_COUNTED_U16)
                .write_volatile(recording_serialize as usize);
            let previous_deserialize =
                core::ptr::addr_of!(COUNTED_U16_TO_CXX_STRING).read_volatile();
            core::ptr::addr_of_mut!(COUNTED_U16_TO_CXX_STRING)
                .write_volatile(recording_deserialize as usize);
            ContextMockInstall {
                previous_serialize,
                previous_deserialize,
                _seam_lock: seam_lock,
            }
        }
    }

    #[test]
    fn context_text_marshals_in_order_and_threads_the_ctor_result() {
        let _mocks = install_context_mocks();
        let mut slot: *mut u8 = core::ptr::null_mut();

        unsafe {
            SERIALIZE_COUNT = 3;
            context_text_to_cxx_string(&mut slot);

            assert_eq!(
                *core::ptr::addr_of!(CONTEXT_EVENTS),
                Vec::from(["serialize", "deserialize"])
            );
            // The real default constructor parked the caller's slot on
            // the shared empty rep before the buffer work; the mocks
            // never reassign it.
            assert_eq!(slot, crate::cxx::string::empty_rep_data());
            // One staging buffer travels through both marshaling calls.
            assert!(!SERIALIZE_BUFFER.is_null());
            assert_eq!(DESERIALIZE_BUFFER, SERIALIZE_BUFFER as *const u16);
            // The deserializer receives the constructor's r0 return
            // (the original's mov r4,r0 / mov r1,r4 thread), which is
            // the caller's slot.
            assert_eq!(DESERIALIZE_STRING, &mut slot as *mut *mut u8);
            // The counted payload round-trips byte-exactly.
            assert_eq!(OBSERVED_COUNT, 3);
            assert_eq!(OBSERVED_UNITS[..3], [0x40, 0x41, 0x42]);
        }
    }

    #[test]
    fn context_text_deserializes_unconditionally_from_empty_to_full() {
        let _mocks = install_context_mocks();
        // The original's bl 0x082596f4 is unconditional: count 0 (the
        // serializer's unset-field path) is deserialized too, and 0xff
        // is the serializer's truncation ceiling.
        for count in [0u16, 1, 0xff] {
            unsafe {
                (*core::ptr::addr_of_mut!(CONTEXT_EVENTS)).clear();
                OBSERVED_COUNT = u16::MAX;
                SERIALIZE_COUNT = count;
                let mut slot: *mut u8 = core::ptr::null_mut();

                context_text_to_cxx_string(&mut slot);

                assert_eq!(
                    *core::ptr::addr_of!(CONTEXT_EVENTS),
                    Vec::from(["serialize", "deserialize"]),
                    "count={count:#x}"
                );
                assert_eq!(OBSERVED_COUNT, count, "count={count:#x}");
                assert_eq!(slot, crate::cxx::string::empty_rep_data());
            }
        }
    }

    // ---- pmu_reg87_bit1_clear ----

    /// Serializes access to the PMU_REG87_BIT1_QUERY seam cell (the
    /// QUERY_NAME_LOCK precedent above).
    static PMU_FLAG_LOCK: Mutex<()> = Mutex::new(());
    static mut PMU_FLAG_RESULT: i32 = 0;
    static mut PMU_FLAG_CALLS: usize = 0;

    unsafe extern "C" fn recording_pmu_flag_query() -> i32 {
        PMU_FLAG_CALLS += 1;
        PMU_FLAG_RESULT
    }

    struct PmuFlagInstall {
        previous: usize,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for PmuFlagInstall {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PMU_REG87_BIT1_QUERY).write_volatile(self.previous);
            }
        }
    }

    fn install_pmu_flag(result: i32) -> PmuFlagInstall {
        let lock = PMU_FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let previous = core::ptr::addr_of!(PMU_REG87_BIT1_QUERY).read_volatile();
            core::ptr::addr_of_mut!(PMU_REG87_BIT1_QUERY)
                .write_volatile(recording_pmu_flag_query as usize);
            PMU_FLAG_RESULT = result;
            PMU_FLAG_CALLS = 0;
            PmuFlagInstall {
                previous,
                _lock: lock,
            }
        }
    }

    #[test]
    fn pmu_reg87_bit1_clear_calls_the_query_once_and_passes_zero_through() {
        let _mock = install_pmu_flag(0);

        assert!(!unsafe { pmu_reg87_bit1_clear() });
        unsafe {
            assert_eq!(PMU_FLAG_CALLS, 1);
        }
    }

    #[test]
    fn pmu_reg87_bit1_clear_maps_every_nonzero_to_true() {
        let _mock = install_pmu_flag(0);

        // The query's own contract only yields 0/1, but the original's
        // cmp r0,#0 / movne r0,#1 maps EVERY nonzero value to true -
        // pin the whole i32 range behavior, not just the 0/1 corner.
        for value in [1, 2, -1, i32::MAX, i32::MIN] {
            unsafe {
                PMU_FLAG_RESULT = value;
                PMU_FLAG_CALLS = 0;
            }
            assert!(unsafe { pmu_reg87_bit1_clear() }, "value={value:#x}");
            unsafe {
                assert_eq!(PMU_FLAG_CALLS, 1, "value={value:#x}");
            }
        }
    }

    #[test]
    fn pmu_reg87_bit1_clear_reads_the_live_result_each_call() {
        let _mock = install_pmu_flag(0);

        for (value, expected) in [(0, false), (1, true), (0, false), (-1, true)] {
            unsafe {
                PMU_FLAG_RESULT = value;
            }
            assert_eq!(unsafe { pmu_reg87_bit1_clear() }, expected, "value={value:#x}");
        }
    }
}
