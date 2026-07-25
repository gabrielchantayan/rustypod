//! Floating -> decimal engine (the dtoa back-end the `%e/%f/%g` formatter
//! calls) plus the whole 12-byte extended-float soft-fp stack it stands on,
//! and four small block-cipher helpers that share this batch (see the note
//! at the bottom of this header — they are NOT dtoa related despite the
//! batch description).
//!
//! retailOS is soft-float: doubles travel as u64 bit patterns and every
//! arithmetic step below is integer bit manipulation (no f32/f64 ops, so no
//! unported helper calls).
//!
//! # The 12-byte extended-float format
//!
//! `[exp_word, mant_hi, mant_lo]`. Value = (mant_hi:mant_lo) *
//! 2^(exp_word - 0x3fff - 63) — a normalized 64-bit mantissa (top bit set)
//! and a biased binary exponent. exp_word bit 31 = sign, bit 30
//! (0x40000000) = inf/nan marker, bits 23..0 = biased exponent. Zero is
//! `{sign, 0, 0}`. This is the same format scanf_float's converter uses.
//!
//! # Ports
//!
//! - `printf_float_dtoa` — original: `FUN_08032514` @ 0x08032514 (724
//!   bytes). The engine. ABI (recovered from the call sites @ 0x08032970 /
//!   0x08032b74 / 0x08032d20): `(out, digits, bits, ndigits, style)` with
//!   `style` as a fifth, stack-passed argument — identical to the committed
//!   `printf_float::DtoaFn` hook signature. `bits` points at the 8 value
//!   bytes (lo word first). On return `out` holds `{dec_exp, len, style}`
//!   and `digits` holds `len` ASCII digits plus a NUL. style 0 (`%e/%g`):
//!   exactly `ndigits` significant digits, `dec_exp` = decimal exponent.
//!   style 1 (`%f`): all digits of round(value * 10^ndigits) (max 17),
//!   `dec_exp` = decimal exponent of the value. Algorithm: estimate
//!   dec_exp as `(19728 * (exp - 1023)) >> 16` (19728 ~= log10(2)*2^16,
//!   DAT_08032ba8), scale the value by 10^-delta in the extended format so
//!   the significand becomes an integer (the exponent bias shift 0x201f on
//!   both operands makes the round routine's underflow path deliver the
//!   integer with the discarded fraction as sticky), then peel decimal
//!   digits with `_ll_udiv10`. If the scaled integer does not fit in 64
//!   bits (result exponent word low 16 bits nonzero) it saturates to
//!   0x7fffffffffffffff. style 0 retries with est +/- 1 when the estimate
//!   was off (leftover digits / leading zero); style 1 with more than 17
//!   digits retries once as style 0 with ndigits = 17 (the original's
//!   "give up" branch at 0x080327d4 is dead — the flag at [sp,#40] is
//!   always 0 — so the retry is unconditional).
//! - `dtoa_pow10` — original: `FUN_08034228` @ 0x08034228 (316 bytes).
//!   Writes 10^exp (exp >= 0) to `out` as a 12-byte extended float.
//!   Decomposes exp = 55*q + r with q = (exp+7067)/55 - 128 >= 0 and
//!   r = (exp+7067)%55 - 27 in [-27,27], then multiplies table powers
//!   10^(2^k) (r, 5 entries) and 10^(55*2^k) (q, 4 entries) with
//!   `ext_mul_ext`, finishing with one divide when r < 0. The originals
//!   per-entry rounding-adjust hack (4th table word vs `adj`) is dead in
//!   this firmware (adj is always 0) and is not ported.
//! - `ext_mul_ext` — original: `FUN_08037504` @ 0x08037504 (48 bytes) and
//!   `ext_div_ext` — original: `FUN_080374a4` @ 0x080374a4 (48 bytes).
//!   Extended multiply/divide producing a 12-byte extended result (via
//!   [`ext_fp_mul_core`]/[`ext_fp_div_core`] + [`ext_fp_round`]). The C ABI
//!   cannot return three registers, so the result goes to an out pointer
//!   (the originals returned exp/mant-hi/mant-lo in r0/r1/r2).
//! - `ext_mul_dbl` — original: `FUN_08037534` @ 0x08037534 (48 bytes) and
//!   `ext_div_dbl` — original: `FUN_080374d4` @ 0x080374d4 (48 bytes).
//!   Same cores rounded to a double by [`ext_fp_round_to_double`],
//!   returned as its u64 bit pattern (hi word in bits 63..32; the
//!   originals returned hi in r0, lo in r1). Signatures match scanf_float's
//!   `SoftfloatOps::{ext_mul, ext_div}` slots.
//! - `ext_fp_mul_core` — original: `FUN_08037564` @ 0x08037564 (612
//!   bytes). 64x64 -> 128 mantissa multiply. SIMPLIFICATION: the original
//!   has four paths (either/both low words zero) that are all algebraically
//!   the exact product (the general path is signed Karatsuba for the middle
//!   term); the port computes the exact 128-bit product once, plus the
//!   original's sticky fold `mid | ((lo | lo<<2) >> 2)` and the
//!   normalize/exponent decrement.
//! - `ext_fp_div_core` — original: `FUN_08037024` @ 0x08037024 (712
//!   bytes). 64/64 mantissa divide: Newton-Raphson reciprocal seeded from a
//!   128-entry table (embedded below, original data @ 0x080372ec), five
//!   estimated quotient digits, then three exact long-division bits and a
//!   sticky. The port is a faithful transliteration of the instruction
//!   sequence (the sticky word r6 embeds the last quotient bits — a clean
//!   fraction would NOT round identically). A Python transliteration of
//!   this sequence was checked against exact arithmetic: quotient = exact
//!   floor (300k random + adversarial cases) and the round classification
//!   (guard bit / exact-half / exact-zero) matches on 500k cases.
//! - `ext_fp_round` — original: `FUN_080373c8` @ 0x080373c8 (220 bytes).
//!   Shared round/sticky routine: with `adj` = 0 (always in this firmware —
//!   the rounding-mode query FUN_083ece54 is the stub `mov r0,#0; bx lr`)
//!   rounds to nearest, ties to even; adj = -1 truncates; other adj rounds
//!   up. The negative-exponent path un-normalizes into a plain integer
//!   (this is how the engine extracts the digit integer).
//! - `ext_fp_round_to_double` — original: `FUN_0803736c` @ 0x0803736c (100
//!   bytes). Rounds the extended value to a double (guard/sticky folded
//!   from the 11 low mantissa bits), packing via the implicit-bit-carry
//!   trick; overflow yields unsigned infinity. NOTE: the original drops the
//!   sign (`bic r0, r0, #0x80000000` before packing) — callers apply the
//!   sign themselves (scanf_float does); this is preserved.
//! - `double_to_ext` — original: `FUN_08036f30` @ 0x08036f30 (244 bytes).
//!   Splits a double (hi, lo words) into the extended format, normalizing
//!   denormals with the original's 16/8/4/2/1 count-leading-zeros chains
//!   (expressed with `leading_zeros` — identical for all reachable inputs)
//!   and tagging inf/nan with the 0x40000000 marker.
//!
//! # Rounding mode
//!
//! Round to nearest, ties to even, at every stage (see `ext_fp_round`).
//! Host-test oracles therefore use Rust's own `{:e}`/`{:.prec$}` formatting
//! (also round-to-nearest-even). The engine's digits are the RNE of the
//! value *as computed in 64-bit extended arithmetic*, so a value sitting
//! exactly on a decimal tie in infinite precision can land one ulp off a
//! correctly-rounded dtoa — same as the original.
//!
//! # Simplifications (all documented above where relevant)
//!
//! - FUN_080359d4 @ 0x080359d4 (the engine's double splitter) is folded
//!   into the engine: with its flag argument 0 it reduces to "biased
//!   exponent field, or -64 for denormal/zero" (its denormal path through
//!   FUN_083ed0dc returns {0, sign-or-0} whose exponent term collapses to
//!   -64 in all cases). FUN_083ed0dc itself is not ported.
//! - FUN_083ece54 (rounding-mode query) is a stub returning 0; the whole
//!   `*5>>1 & 0xc00000` adjustment in the engine folds to adj = 0.
//! - The mul core's four paths collapse to one exact 128-bit product.
//! - The divide core's dead `ldr r7, [sp, #12]` (a scheduling artifact)
//!   is omitted.
//!
//! # The four block helpers — NOT dtoa
//!
//! The batch sheet called 0x0802e118/0x0802e154/0x0802e190/0x0802e1f4
//! "dtoa nibble-shift helpers". They are nothing of the sort: their only
//! callers are the 16-byte block functions @ 0x0802e5a0/0x0802e674 (4x4
//! byte-matrix transpose in/out, round key steps of 16 bytes), i.e. they
//! are the SubBytes / InvSubBytes / ShiftRows / InvShiftRows of an AES-like
//! proprietary block cipher. 0x0802e118/0x0802e154 translate every byte of
//! a 16-byte state through a 256-byte table; the tables live in the image
//! @ 0x0891ee4c / 0x0891ef4c and are embedded verbatim below (their content
//! looks like obfuscated ASCII, not the standard AES S-box — the exact
//! cipher is out of scope). 0x0802e190/0x0802e1f4 rotate the three row
//! quartets of the column-major state. They are ported here because the
//! batch assigned them.

use crate::ll_udiv10::ll_udiv10_full;

/// 12-byte extended float: `[exp_word, mant_hi, mant_lo]`.
type Ext = [u32; 3];

/// Extended 1.0 (exp bias 0x3fff, mantissa 2^63).
const EXT_ONE: Ext = [0x3fff, 0x8000_0000, 0];

/// `10^(2^k)`, k = 0..5 — original table @ 0x089861a0 (5 x 12 bytes).
const POW10_UNITS: [Ext; 5] = [
    [0x4002, 0xa000_0000, 0x0000_0000], // 10^1
    [0x4005, 0xc800_0000, 0x0000_0000], // 10^2
    [0x400c, 0x9c40_0000, 0x0000_0000], // 10^4
    [0x4019, 0xbebc_2000, 0x0000_0000], // 10^8
    [0x4034, 0x8e1b_c9bf, 0x0400_0000], // 10^16
];

/// `10^(55*2^k)`, k = 0..4 — original table @ 0x089861dc (4 x 16 bytes;
/// the 4th word of each entry is the dead rounding-adjust, not ported).
const POW10_GROUPS: [Ext; 4] = [
    [0x40b5, 0xd0cf_4b50, 0xcfe2_0766], // 10^55
    [0x416c, 0xaa51_823e, 0x34a7_eedf], // 10^110
    [0x42d9, 0xe2a0_b5dc, 0x971f_303a], // 10^220
    [0x45b4, 0xc8a0_25fd, 0x4fc1_a3e9], // 10^440
];

/// Reciprocal seed table for the divide core — original data @ 0x080372ec,
/// indexed by the divisor's top 8 bits minus 0x80 (128 entries).
#[rustfmt::skip]
const RECIP_SEED: [u8; 128] = [
    0x80, 0x80, 0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x76, 0x75, 0x74, 0x73,
    0x72, 0x71, 0x71, 0x70, 0x6f, 0x6e, 0x6e, 0x6d, 0x6c, 0x6c, 0x6b, 0x6a, 0x6a, 0x69, 0x68, 0x68,
    0x67, 0x66, 0x66, 0x65, 0x64, 0x64, 0x63, 0x63, 0x62, 0x61, 0x61, 0x60, 0x60, 0x5f, 0x5f, 0x5e,
    0x5e, 0x5d, 0x5d, 0x5c, 0x5c, 0x5b, 0x5b, 0x5a, 0x5a, 0x59, 0x59, 0x58, 0x58, 0x57, 0x57, 0x56,
    0x56, 0x55, 0x55, 0x55, 0x54, 0x54, 0x53, 0x53, 0x52, 0x52, 0x52, 0x51, 0x51, 0x50, 0x50, 0x50,
    0x4f, 0x4f, 0x4f, 0x4e, 0x4e, 0x4d, 0x4d, 0x4d, 0x4c, 0x4c, 0x4c, 0x4b, 0x4b, 0x4b, 0x4a, 0x4a,
    0x4a, 0x49, 0x49, 0x49, 0x48, 0x48, 0x48, 0x47, 0x47, 0x47, 0x47, 0x46, 0x46, 0x46, 0x45, 0x45,
    0x45, 0x44, 0x44, 0x44, 0x44, 0x43, 0x43, 0x43, 0x43, 0x42, 0x42, 0x42, 0x42, 0x41, 0x41, 0x41,
];

/// 32-bit add with carry-in, ARM style: returns (result, carry-out).
#[inline(always)]
fn adds(a: u32, b: u32, carry: u32) -> (u32, u32) {
    let r = a as u64 + b as u64 + carry as u64;
    (r as u32, (r >> 32) as u32)
}

/// 32-bit subtract, ARM style: returns (result, NOT-borrow).
#[inline(always)]
fn subs(a: u32, b: u32) -> (u32, u32) {
    (a.wrapping_sub(b), if a >= b { 1 } else { 0 })
}

/// 32-bit subtract with carry, ARM style: `a - b - (1 - carry)`,
/// returns (result, NOT-borrow).
#[inline(always)]
fn sbcs(a: u32, b: u32, carry: u32) -> (u32, u32) {
    let r = a as i64 - b as i64 - (1 - carry) as i64;
    (r as u32, if r >= 0 { 1 } else { 0 })
}

/// The ADS `subcc`/`subscs` pair idiom from the divide core: always
/// subtract, but only update the carry when it was set — a borrow-in of 1
/// is forwarded into the next word's `sbc` instead of this one.
#[inline(always)]
fn subs_forward_borrow(a: u32, b: u32, carry: u32) -> (u32, u32) {
    if carry == 0 {
        (a.wrapping_sub(b), 0)
    } else {
        subs(a, b)
    }
}

/// Split a double (as its hi/lo words) into the 12-byte extended format.
/// Original: `FUN_08036f30` @ 0x08036f30.
#[cfg_attr(target_os = "none", no_mangle)]
pub fn double_to_ext(hi: u32, lo: u32) -> Ext {
    let twice = hi << 1; // sign shifts into the ARM carry
    let sign = hi & 0x8000_0000;
    let nonzero = twice != 0 || lo != 0;
    let mut exp = twice >> 20;
    if nonzero {
        exp = exp.wrapping_add(0x7800);
    }
    let mut mant_lo = lo << 11;
    let mut mant_hi = (twice << 10) | (lo >> 21);
    if nonzero {
        mant_hi |= 0x8000_0000; // implicit bit
    }
    // rrx: sign back into bit 31, exponent halved into the 0x3c00 bias.
    exp = sign | (exp >> 1);
    let exp_field = (twice as i32) >> 21; // asrs: negative when all-ones
    if exp_field != 0 {
        if exp_field == -1 {
            exp |= 0x4000_0000; // inf/nan marker
        }
        return [exp, mant_hi, mant_lo];
    }
    // Denormal or zero: the forced implicit bit is the normalization flag.
    if mant_hi & 0x8000_0000 == 0 {
        return [exp, mant_hi, mant_lo]; // exact zero: {sign, 0, 0}
    }
    mant_hi &= 0x7fff_ffff;
    if mant_hi == 0 {
        // Whole mantissa lives in the low word (cannot be zero here).
        let shift = mant_lo.leading_zeros();
        return [exp.wrapping_sub(31).wrapping_sub(shift), mant_lo << shift, 0];
    }
    let shift = mant_hi.leading_zeros();
    mant_hi = (mant_hi << shift) | (mant_lo >> (32 - shift));
    mant_lo <<= shift;
    [exp.wrapping_sub(shift).wrapping_add(1), mant_hi, mant_lo]
}

/// Multiply core, exact model (see the module header for the equivalence
/// argument with the original's four paths). Original: `FUN_08037564` @
/// 0x08037564. Returns (sign, exp, mant_hi, mant_lo, sticky).
#[cfg_attr(target_os = "none", no_mangle)]
pub fn ext_fp_mul_core(a: Ext, b: Ext) -> (u32, u32, u32, u32, u32) {
    let sign = (a[0] ^ b[0]) & 0x8000_0000;
    let mut exp = (a[0] & 0x00ff_ffff)
        .wrapping_add(b[0] & 0x00ff_ffff)
        .wrapping_sub(0x3ffe);
    // Exact 128-bit product of the two 64-bit mantissas, in 32-bit limbs
    // (each partial is a 32x32 -> 64 multiply: umull, no libcalls).
    let (ah, al) = (a[1] as u64, a[2] as u64);
    let (bh, bl) = (b[1] as u64, b[2] as u64);
    let hh = ah * bh;
    let (mid, mid_carry) = (ah * bl).overflowing_add(al * bh);
    let lo64 = (al * bl).wrapping_add(mid << 32);
    let lo_carry = (lo64 < al * bl) as u64;
    let hi64 = hh + (mid >> 32) + lo_carry + ((mid_carry as u64) << 32);
    // Sticky fold: the low 64 bits collapse into one word, preserving
    // zero / exactly-half / other and the guard bit.
    let (lo32, mid32) = (lo64 as u32, (lo64 >> 32) as u32);
    let mut sticky = mid32 | ((lo32 | lo32.wrapping_shl(2)) >> 2);
    let (mut mant_hi, mut mant_lo) = ((hi64 >> 32) as u32, hi64 as u32);
    if mant_hi & 0x8000_0000 == 0 {
        // Product below 2^127: normalize one bit left, exponent down.
        let (s, c) = adds(sticky, sticky, 0);
        sticky = s;
        let (l, c) = adds(mant_lo, mant_lo, c);
        mant_lo = l;
        let (h, _) = adds(mant_hi, mant_hi, c);
        mant_hi = h;
        exp = exp.wrapping_sub(1);
    }
    (sign, exp, mant_hi, mant_lo, sticky)
}

/// Divide core: faithful transliteration of the original instruction
/// sequence (Newton-Raphson seed + five estimated digits + three exact
/// bits + sticky). Original: `FUN_08037024` @ 0x08037024. Returns
/// (sign, exp, mant_hi, mant_lo, sticky); the sticky word embeds the last
/// quotient bits exactly like the original (see module header).
#[cfg_attr(target_os = "none", no_mangle)]
pub fn ext_fp_div_core(a: Ext, b: Ext) -> (u32, u32, u32, u32, u32) {
    let sign = (a[0] ^ b[0]) & 0x8000_0000;
    let mut exp = (a[0] & 0x00ff_ffff)
        .wrapping_sub(b[0] & 0x00ff_ffff)
        .wrapping_add(0x3f00)
        .wrapping_add(0xff);

    // Divisor split into 16-bit limbs.
    let b_hi_hi = b[1] >> 16;
    let b_lo_hi = b[2] >> 16;
    let b_hi_lo = b[1] & 0xffff;
    let b_lo_lo = b[2] & 0xffff;

    // Dividend shifted right one into a 97-bit r1:r2:r0 (r0 top bit only).
    let hi_carry = a[1] & 1;
    let lo_carry = a[2] & 1;
    let mut r1 = a[1] >> 1;
    let mut r2 = (a[2] >> 1) | (hi_carry << 31);
    let mut r0 = if lo_carry != 0 { 0x8000_0000 } else { 0 };

    // Newton-Raphson reciprocal of the divisor's top bits.
    let mut r6 = RECIP_SEED[((b_hi_hi >> 8) - 0x80) as usize] as u32;
    let mut r7 = b_hi_hi.wrapping_mul(r6).wrapping_add(r6);
    r7 = 0x0080_0000u32.wrapping_sub(r7);
    r6 = r7.wrapping_mul(r6);
    r7 = b[1] >> 13;
    r6 = (r6 >> 19).wrapping_add(2);
    let mut ip = r7.wrapping_mul(r6).wrapping_add(r6);
    ip = 0x2000_0000u32.wrapping_sub(ip);
    r7 = ip >> 16;
    ip &= 0xffff;
    let recip = (r7.wrapping_mul(r6).wrapping_add(ip.wrapping_mul(r6) >> 16)) >> 6;

    // Estimated quotient digit: q = ((recip * num) as u32) >> 16, exactly
    // the original's 32-bit `mul` + `lsr #16`.
    let r = recip;
    let mut acc_hi = 0u32; // r4
    let mut acc_mid = 0u32; // r5
    let mut sticky; // r6

    // --- digit 1 (subtract q*b at scale 2^16) ---
    let mut q = (r.wrapping_mul(r1 >> 15)) >> 16;
    acc_hi = q << 16;
    let mut c;
    let mut t = q.wrapping_mul(b_lo_hi);
    (r2, c) = subs(r2, t);
    t = q.wrapping_mul(b_hi_hi);
    (r1, c) = sbcs(r1, t, c);
    t = q.wrapping_mul(b_lo_lo);
    (r0, c) = subs(r0, t << 16);
    (r2, c) = sbcs(r2, t >> 16, c);
    t = q.wrapping_mul(b_hi_lo);
    (r2, c) = subs_forward_borrow(r2, t << 16, c);
    (r1, c) = sbcs(r1, t >> 16, c);

    // --- digit 2 (scale 2^3) ---
    q = (r.wrapping_mul(r1 >> 2)) >> 16;
    t = q.wrapping_mul(b_lo_hi);
    (r0, c) = subs(r0, t << 19);
    (r2, c) = sbcs(r2, t >> 13, c);
    t = q.wrapping_mul(b_hi_hi);
    (r2, c) = subs_forward_borrow(r2, t << 19, c);
    (r1, c) = sbcs(r1, t >> 13, c);
    t = q.wrapping_mul(b_lo_lo);
    acc_hi = acc_hi.wrapping_add(q << 3);
    (r0, c) = subs(r0, t << 3);
    (r2, c) = sbcs(r2, t >> 29, c);
    t = q.wrapping_mul(b_hi_lo);
    (r2, c) = subs_forward_borrow(r2, t << 3, c);
    (r1, c) = sbcs(r1, t >> 29, c);

    let _ = c; // final borrow of the estimate chain feeds nothing
    // Remainder left 26.
    r1 = (r1 << 26) | (r2 >> 6);
    r2 = (r2 << 26) | (r0 >> 6);
    r0 <<= 26;

    // --- digit 3 (scale 2^16 again, into the mid accumulator) ---
    q = (r.wrapping_mul(r1 >> 15)) >> 16;
    acc_mid = q << 22;
    acc_hi = acc_hi.wrapping_add(q >> 10);
    t = q.wrapping_mul(b_lo_hi);
    (r2, c) = subs(r2, t);
    t = q.wrapping_mul(b_hi_hi);
    (r1, c) = sbcs(r1, t, c);
    t = q.wrapping_mul(b_lo_lo);
    (r0, c) = subs(r0, t << 16);
    (r2, c) = sbcs(r2, t >> 16, c);
    t = q.wrapping_mul(b_hi_lo);
    (r2, c) = subs_forward_borrow(r2, t << 16, c);
    (r1, c) = sbcs(r1, t >> 16, c);

    let _ = c; // final borrow of the estimate chain feeds nothing
    // --- digit 4 (scale 2^3) ---
    q = (r.wrapping_mul(r1 >> 2)) >> 16;
    t = q.wrapping_mul(b_lo_hi);
    (r0, c) = subs(r0, t << 19);
    (r2, c) = sbcs(r2, t >> 13, c);
    t = q.wrapping_mul(b_hi_hi);
    (r2, c) = subs_forward_borrow(r2, t << 19, c);
    (r1, c) = sbcs(r1, t >> 13, c);
    t = q.wrapping_mul(b_lo_lo);
    (r0, c) = subs(r0, t << 3);
    (r2, c) = sbcs(r2, t >> 29, c);
    t = q.wrapping_mul(b_hi_lo);
    (r2, c) = subs_forward_borrow(r2, t << 3, c);
    (r1, c) = sbcs(r1, t >> 29, c);

    let _ = c; // final borrow of the estimate chain feeds nothing
    // Remainder left 26; digit 4 joins the mid accumulator (<<9).
    r1 = (r1 << 26) | (r2 >> 6);
    let (m, c5) = adds(acc_mid, q << 9, 0);
    acc_mid = m;
    let q5_num = r1 >> 15;
    r2 = (r2 << 26) | (r0 >> 6);
    q = (r.wrapping_mul(q5_num)) >> 16;
    acc_hi = acc_hi.wrapping_add(c5);
    r0 <<= 26;

    // --- digit 5 (top bits of the sticky word) ---
    sticky = q << 28;
    t = q.wrapping_mul(b_lo_hi);
    (r2, c) = subs(r2, t);
    t = q.wrapping_mul(b_hi_hi);
    (r1, c) = sbcs(r1, t, c);
    t = q.wrapping_mul(b_lo_lo);
    (r0, c) = subs(r0, t << 16);
    (r2, c) = sbcs(r2, t >> 16, c);
    t = q.wrapping_mul(b_hi_lo);
    (r2, c) = subs_forward_borrow(r2, t << 16, c);
    (r1, c) = sbcs(r1, t >> 16, c);
    let _ = c; // the final borrow feeds nothing, as in the original
    let (m, c5) = adds(acc_mid, q >> 4, 0);
    acc_mid = m;
    // Remainder left 14; digit 5's carry joins the high accumulator.
    r1 = (r1 << 14) | (r2 >> 18);
    r2 = (r2 << 14) | (r0 >> 18);
    r0 <<= 14;
    acc_hi = acc_hi.wrapping_add(c5);

    // Three exact long-division bits against the recombined 64-bit divisor.
    let b_hi = b[1];
    let b_lo = b[2];
    let mut bits = 0u32;
    let mut top = 0u32; // 97th remainder bit
    for step in 0..3 {
        let (d_lo, mut c) = subs(r2, b_lo);
        let (d_hi, c2) = sbcs(r1, b_hi, c);
        c = c2;
        if step > 0 {
            let (_, c3) = sbcs(top, 0, c);
            c = c3;
        }
        if c == 1 {
            r2 = d_lo;
            r1 = d_hi;
        }
        bits = bits * 2 + c;
        if step < 2 {
            let (n0, c0) = adds(r0, r0, 0);
            let (n2, c2) = adds(r2, r2, c0);
            let (n1, c1) = adds(r1, r1, c2);
            r0 = n0;
            r2 = n2;
            r1 = n1;
            top = c1;
        }
    }
    if (r1 | r2) != 0 {
        sticky |= 1;
    }
    // Fold the last bits in; the carry climbs into the quotient.
    let (s, c) = adds(sticky, bits << 28, 0);
    sticky = s;
    let (l, c) = adds(acc_mid, 0, c);
    let (h, _) = adds(acc_hi, 0, c);
    let (mut mant_hi, mut mant_lo) = (h, l);
    if mant_hi & 0x8000_0000 == 0 {
        // Quotient below 2^63: normalize one bit left, exponent down.
        let (s, c) = adds(sticky, sticky, 0);
        sticky = s;
        let (l, c) = adds(mant_lo, mant_lo, c);
        mant_lo = l;
        let (h, _) = adds(mant_hi, mant_hi, c);
        mant_hi = h;
        exp = exp.wrapping_sub(1);
    }
    (sign, exp, mant_hi, mant_lo, sticky)
}

/// Shared round/sticky routine. Original: `FUN_080373c8` @ 0x080373c8.
/// With `adj` = 0 rounds to nearest, ties to even; `adj` = -1 truncates;
/// any other `adj` rounds up on inexact. The negative-exponent path
/// un-normalizes the mantissa (the engine's integer extraction).
#[cfg_attr(target_os = "none", no_mangle)]
pub fn ext_fp_round(
    sign: u32,
    mut exp: u32,
    mut mant_hi: u32,
    mut mant_lo: u32,
    mut sticky: u32,
    adj: i32,
) -> Ext {
    if (exp as i32) < 0 {
        // Underflow: shift right, folding the discarded bits into sticky.
        sticky = (sticky | sticky << 16) >> 16;
        if (exp as i32) <= -64 {
            sticky |= mant_lo;
            sticky = (sticky | sticky << 16) >> 16;
            mant_lo = 0;
            sticky |= mant_hi;
            if (exp as i32) < -64 {
                sticky = (sticky | sticky << 16) >> 16;
            }
            mant_hi = 0;
            exp = 0;
        } else {
            if (exp as i32) <= -32 {
                sticky |= mant_lo;
                mant_lo = mant_hi;
                mant_hi = 0;
                exp = exp.wrapping_add(32);
            }
            exp = exp.wrapping_neg();
            if exp != 0 {
                sticky = (sticky | sticky << 16) >> 16;
                let back = 32 - exp;
                sticky |= mant_lo << back;
                mant_lo = (mant_lo >> exp) | (mant_hi << back);
                mant_hi >>= exp;
                exp = 0;
            }
        }
    }
    // Round decision. adj == 0 keeps the computed carry (guard bit, or the
    // mantissa parity on an exact tie): round to nearest, ties to even.
    let twice = sticky << 1;
    let mut round_up = sticky >> 31;
    if twice == 0 {
        if round_up == 0 {
            // Exact: no rounding.
            return [sign | exp, mant_hi, mant_lo];
        }
        // Exactly half: tie — round up iff the mantissa is odd.
        round_up = mant_lo & 1;
    }
    let adj1 = adj.wrapping_add(1) as u32;
    if adj1 != 1 {
        round_up = if adj1 >= 1 { 1 } else { 0 };
    }
    if round_up == 1 {
        let (l, c) = adds(mant_lo, 1, 0);
        mant_lo = l;
        let mut carry = 0;
        if c == 1 {
            let (h, c2) = adds(mant_hi, 1, 0);
            mant_hi = h;
            carry = c2;
            if c2 == 1 {
                mant_hi = 0x8000_0000;
            }
        }
        exp = exp.wrapping_add(carry);
    }
    [sign | exp, mant_hi, mant_lo]
}

/// Round the extended value to a double, returned as its u64 bit pattern
/// (hi word in bits 63..32). Original: `FUN_0803736c` @ 0x0803736c. The
/// original drops the sign before packing (callers apply it themselves);
/// overflow packs unsigned infinity.
#[cfg_attr(target_os = "none", no_mangle)]
pub fn ext_fp_round_to_double(
    sign: u32,
    exp: u32,
    mant_hi: u32,
    mant_lo: u32,
    sticky: u32,
    adj: i32,
) -> u64 {
    // Fold the sticky word, then bring the 11 sub-double bits into guard
    // position and shrink the mantissa to 53 bits.
    let sticky = ((sticky | sticky << 16) >> 16) | (mant_lo << 21);
    let mant_lo = (mant_lo >> 11) | (mant_hi << 21);
    let mant_hi = mant_hi >> 11;
    let exp = exp.wrapping_sub(0x3c00).wrapping_sub(1);
    let [exp, mant_hi, mant_lo] = ext_fp_round(sign, exp, mant_hi, mant_lo, sticky, adj);
    let exp = exp & 0x7fff_ffff; // the original drops the sign here
    let top = exp & 0x8000_0000; // always 0; kept for faithfulness
    let hi = mant_hi.wrapping_add(exp << 20) | top;
    if exp.wrapping_add(1) < 0x800 {
        return ((hi as u64) << 32) | mant_lo as u64;
    }
    (0x7ff0_0000u64 | top as u64) << 32 // overflow: unsigned infinity
}

/// Extended multiply, extended result. Original: `FUN_08037504` @
/// 0x08037504. No-op (returns `a`) when either operand carries the
/// inf/nan marker.
fn ext_mul_ext_val(a: &Ext, b: &Ext, adj: i32) -> Ext {
    if a[0] & 0x4000_0000 == 0 && b[0] & 0x4000_0000 == 0 {
        let (sign, exp, mh, ml, sticky) = ext_fp_mul_core(*a, *b);
        ext_fp_round(sign, exp, mh, ml, sticky, adj)
    } else {
        *a
    }
}

/// Extended divide, extended result. Original: `FUN_080374a4` @
/// 0x080374a4. No-op unless both operands are normalized finite values.
fn ext_div_ext_val(a: &Ext, b: &Ext, adj: i32) -> Ext {
    let a_ok = (a[1] & !a[0].wrapping_shl(1)) & 0x8000_0000 != 0;
    let b_ok = (b[1] & !b[0].wrapping_shl(1)) & 0x8000_0000 != 0;
    if a_ok && b_ok {
        let (sign, exp, mh, ml, sticky) = ext_fp_div_core(*a, *b);
        ext_fp_round(sign, exp, mh, ml, sticky, adj)
    } else {
        *a
    }
}

/// `ext_mul_ext` entry — original: `FUN_08037504` @ 0x08037504. Result to
/// `out` (the original returned it in r0/r1/r2).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ext_mul_ext(a: *const u32, b: *const u32, adj: i32, out: *mut u32) {
    let a = [a.read(), a.add(1).read(), a.add(2).read()];
    let b = [b.read(), b.add(1).read(), b.add(2).read()];
    let r = ext_mul_ext_val(&a, &b, adj);
    out.write(r[0]);
    out.add(1).write(r[1]);
    out.add(2).write(r[2]);
}

/// `ext_div_ext` entry — original: `FUN_080374a4` @ 0x080374a4.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ext_div_ext(a: *const u32, b: *const u32, adj: i32, out: *mut u32) {
    let a = [a.read(), a.add(1).read(), a.add(2).read()];
    let b = [b.read(), b.add(1).read(), b.add(2).read()];
    let r = ext_div_ext_val(&a, &b, adj);
    out.write(r[0]);
    out.add(1).write(r[1]);
    out.add(2).write(r[2]);
}

/// `ext_mul_dbl` — original: `FUN_08037534` @ 0x08037534. Extended
/// multiply rounded to a double, returned as its u64 bit pattern (hi word
/// in bits 63..32). Matches scanf_float's `SoftfloatOps::ext_mul`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ext_mul_dbl(a: *const u32, b: *const u32, adj: i32) -> u64 {
    let a = [a.read(), a.add(1).read(), a.add(2).read()];
    let b = [b.read(), b.add(1).read(), b.add(2).read()];
    if a[0] & 0x4000_0000 != 0 || b[0] & 0x4000_0000 != 0 {
        // Guard skipped the op: the original returns operand a unpacked.
        // (Not reachable from the dtoa/scanf paths, which stay finite.)
        return ((a[0] as u64) << 32) | a[1] as u64;
    }
    let (sign, exp, mh, ml, sticky) = ext_fp_mul_core(a, b);
    ext_fp_round_to_double(sign, exp, mh, ml, sticky, adj)
}

/// `ext_div_dbl` — original: `FUN_080374d4` @ 0x080374d4. Extended divide
/// rounded to a double; same contract as [`ext_mul_dbl`]. Matches
/// scanf_float's `SoftfloatOps::ext_div`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ext_div_dbl(a: *const u32, b: *const u32, adj: i32) -> u64 {
    let a = [a.read(), a.add(1).read(), a.add(2).read()];
    let b = [b.read(), b.add(1).read(), b.add(2).read()];
    let a_ok = (a[1] & !a[0].wrapping_shl(1)) & 0x8000_0000 != 0;
    let b_ok = (b[1] & !b[0].wrapping_shl(1)) & 0x8000_0000 != 0;
    if !(a_ok && b_ok) {
        return ((a[0] as u64) << 32) | a[1] as u64;
    }
    let (sign, exp, mh, ml, sticky) = ext_fp_div_core(a, b);
    ext_fp_round_to_double(sign, exp, mh, ml, sticky, adj)
}

/// 10^exp (exp >= 0) as a 12-byte extended float at `out`. Original:
/// `FUN_08034228` @ 0x08034228. Matches scanf_float's `SoftfloatOps::pow10`.
/// Table coverage: exp <= 500 (beyond that the original reads past its
/// tables; no caller reaches it).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dtoa_pow10(out: *mut u32, exp: u32, adj: i32) {
    let mut rem_part = EXT_ONE; // 10^|r| accumulator
    let mut grp_part = EXT_ONE; // 10^(55*q) accumulator
    // Decompose exp = 55*q + r with q >= 0 and r in [-27, 27]: the original
    // uses its signed-division runtime on (exp + 7067) / 55.
    let t = exp.wrapping_add(7067) as i32;
    let mut r = t % 55 - 27;
    let negative = r < 0;
    if negative {
        r = -r;
    }
    let mut q = t / 55 - 128;
    let mut k = 0;
    while r != 0 {
        if r & 1 != 0 {
            rem_part = ext_mul_ext_val(&rem_part, &POW10_UNITS[k], adj);
        }
        r >>= 1;
        k += 1;
    }
    let mut k = 0;
    while q != 0 {
        if q & 1 != 0 {
            grp_part = ext_mul_ext_val(&grp_part, &POW10_GROUPS[k], adj);
        }
        q >>= 1;
        k += 1;
    }
    let result = if negative {
        ext_div_ext_val(&grp_part, &rem_part, adj)
    } else {
        ext_mul_ext_val(&grp_part, &rem_part, adj)
    };
    out.write(result[0]);
    out.add(1).write(result[1]);
    out.add(2).write(result[2]);
}

/// log10(2) * 2^16 rounded (the engine's decimal-exponent estimate factor,
/// DAT_08032ba8).
const LOG10_2_FIXED: i32 = 0x4d10;

/// The dtoa back-end. Original: `FUN_08032514` @ 0x08032514; see the
/// module header for the ABI and algorithm. Signature matches the
/// committed `printf_float::DtoaFn` hook.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn printf_float_dtoa(
    out: *mut i32,
    digits: *mut u8,
    bits: *const u64,
    ndigits: i32,
    style: i32,
) {
    let words = bits as *const u32;
    let mant_hi = words.add(1).read();
    let mant_lo = words.read();
    // FUN_080359d4 folded (see module header): biased exponent, or -64 for
    // denormal/zero. The rounding adjust is 0 (stubbed query).
    let exp_field = (mant_hi << 1) >> 21;
    let raw_exp = if exp_field != 0 { exp_field as i32 } else { -64 };
    const ADJ: i32 = 0;

    if (mant_hi & 0x7fff_ffff) | mant_lo == 0 {
        // Signed zero: no scaling, fabricate the zero digit string.
        let (exp10, len) = if style == 1 {
            (-(ndigits + 1), 0)
        } else {
            for i in 0..ndigits {
                *digits.add(i as usize) = b'0';
            }
            (0, ndigits)
        };
        *digits.add(len as usize) = 0;
        *out = exp10;
        *out.add(1) = len;
        *out.add(2) = style;
        return;
    }

    let mut est = LOG10_2_FIXED.wrapping_mul(raw_exp - 0x3ff) >> 16;
    let mut ndigits = ndigits;
    let mut style = style;
    let (exp10, len);
    'scale: loop {
        let delta = if style == 0 { est - ndigits + 1 } else { -ndigits };
        let mut pow10: Ext = [0; 3];
        dtoa_pow10(pow10.as_mut_ptr(), delta.unsigned_abs(), ADJ);
        let mut value = double_to_ext(mant_hi, mant_lo);
        value[0] = value[0].wrapping_sub(0x201f);
        if delta > 0 {
            pow10[0] = pow10[0].wrapping_add(0x201f);
            value = ext_div_ext_val(&value, &pow10, ADJ);
        } else {
            pow10[0] = pow10[0].wrapping_sub(0x201f);
            value = ext_mul_ext_val(&value, &pow10, ADJ);
        }
        // The round routine's underflow path delivers the digit integer iff
        // the result exponent reached 0; anything else means the scaled
        // value escaped 64 bits.
        let mut digits64: u64 = if (value[0] << 16) != 0 {
            0x7fff_ffff_ffff_ffff
        } else {
            ((value[1] as u64) << 32) | value[2] as u64
        };
        if style != 0 {
            // %f: every digit of the scaled integer, least significant
            // first, capped at 17.
            let mut count = 0i32;
            while digits64 != 0 && count <= 16 {
                let (quot, digit) = ll_udiv10_full(digits64);
                *digits.add(count as usize) = b'0' + digit;
                digits64 = quot;
                count += 1;
            }
            if digits64 != 0 {
                // More than 17 digits: the original's give-up branch is
                // dead (its flag is always 0) — retry as 17 significant
                // digits, unconditionally.
                ndigits = 17;
                style = 0;
                continue 'scale;
            }
            let (mut lo, mut hi) = (0i32, count - 1);
            while lo < hi {
                let a = digits.add(lo as usize);
                let b = digits.add(hi as usize);
                let tmp = a.read();
                a.write(b.read());
                b.write(tmp);
                lo += 1;
                hi -= 1;
            }
            exp10 = count - ndigits - 1;
            len = count;
            break;
        }
        // %e/%g: exactly ndigits digits, most significant first.
        let mut pos = ndigits - 1;
        while pos >= 0 {
            let (quot, digit) = ll_udiv10_full(digits64);
            *digits.add(pos as usize) = b'0' + digit;
            digits64 = quot;
            pos -= 1;
        }
        if digits64 != 0 {
            // Estimate one low: leftover digits remain.
            est += 1;
            continue 'scale;
        }
        if *digits == b'0' {
            // Estimate one high: leading zero.
            est -= 1;
            continue 'scale;
        }
        exp10 = est;
        len = ndigits;
        break;
    }
    *digits.add(len as usize) = 0;
    *out = exp10;
    *out.add(1) = len;
    *out.add(2) = style;
}

// ---------------------------------------------------------------------------
// Block-cipher round helpers (see the module header — assigned to this batch
// as "dtoa nibble-shift helpers", actually AES-like SubBytes/ShiftRows).

/// SubBytes table — original data @ 0x0891ee4c (256 bytes, embedded
/// verbatim; content is not the standard AES S-box).
#[rustfmt::skip]
static BLOCK_SUB_TABLE: [u8; 256] = [
    0x27, 0x53, 0x82, 0x61, 0x02, 0x4b, 0xef, 0x4b, 0xf6, 0xe3, 0xf5, 0xf4, 0x65, 0x80, 0x00, 0xe9,
    0xf2, 0xf4, 0x68, 0x80, 0x26, 0x41, 0x62, 0x03, 0x4c, 0x04, 0x4c, 0x0d, 0x4c, 0x17, 0xe5, 0xee,
    0xe7, 0xe1, 0xec, 0x69, 0x80, 0x09, 0x8f, 0xef, 0xf0, 0xef, 0xed, 0xef, 0xe6, 0x6f, 0x80, 0x31,
    0x1c, 0xf2, 0xe5, 0xf6, 0x65, 0x80, 0x01, 0x15, 0x63, 0x05, 0x4c, 0x2a, 0x4c, 0x73, 0x4c, 0x81,
    0x4c, 0xa1, 0x4c, 0xfa, 0x61, 0x02, 0x4c, 0x30, 0x4c, 0x6d, 0xee, 0xe4, 0xf2, 0x61, 0x03, 0x4c,
    0x3b, 0x4c, 0x42, 0x4c, 0x4d, 0xe4, 0xe5, 0xf6, 0x61, 0x80, 0x09, 0x0d, 0xe7, 0xf5, 0xea, 0xe1,
    0xf2, 0xe1, 0xf4, 0x69, 0x80, 0x0a, 0x8d, 0xf6, 0xef, 0xf7, 0xe5, 0xec, 0xf3, 0xe9, 0xe7, 0x6e,
    0x02, 0x4c, 0x5b, 0x4c, 0x62, 0xe4, 0xe5, 0xf6, 0x61, 0x80, 0x09, 0x45, 0xe7, 0xf5, 0xea, 0xe1,
    0xf2, 0xe1, 0xf4, 0x69, 0x80, 0x0a, 0xc5, 0xf2, 0xef, 0x6e, 0x80, 0x01, 0x1b, 0xe5, 0xe4, 0xe9,
    0xec, 0xec, 0xe1, 0xe2, 0xf2, 0xe5, 0xf6, 0x65, 0x80, 0x1e, 0x1d, 0x68, 0x02, 0x4c, 0x87, 0x4c,
    0x92, 0xe1, 0xf2, 0xed, 0xe5, 0xee, 0xe9, 0xe1, 0x6e, 0x80, 0x05, 0x65, 0xf9, 0xe9, 0xf7, 0xee,
    0xe1, 0xf2, 0xed, 0xe5, 0xee, 0xe9, 0xe1, 0x6e, 0x80, 0x05, 0x87, 0xe9, 0xf2, 0x63, 0x02, 0x4c,
    0xa9, 0x4c, 0xae, 0xec, 0x65, 0x80, 0x24, 0xd4, 0xf5, 0xed, 0xe6, 0xec, 0xe5, 0x78, 0x86, 0x00,
    0xea, 0x4c, 0xc3, 0x4c, 0xcb, 0x4c, 0xd3, 0x4c, 0xde, 0x4c, 0xe6, 0x4c, 0xf2, 0xe1, 0xe3, 0xf5,
    0xf4, 0x65, 0x80, 0x1e, 0xbf, 0xe2, 0xe5, 0xec, 0xef, 0x77, 0x80, 0x1e, 0x19, 0xe4, 0xef, 0xf4,
    0xe2, 0xe5, 0xec, 0xef, 0x77, 0x80, 0x1e, 0xc7, 0xe7, 0xf2, 0xe1, 0xf6, 0x65, 0x80, 0x1e, 0xc1,
];

/// InvSubBytes table — original data @ 0x0891ef4c (256 bytes).
#[rustfmt::skip]
static BLOCK_INV_SUB_TABLE: [u8; 256] = [
    0xe8, 0xef, 0xef, 0xeb, 0xe1, 0xe2, 0xef, 0xf6, 0x65, 0x80, 0x1e, 0xc3, 0xf4, 0xe9, 0xec, 0xe4,
    0x65, 0x80, 0x1e, 0xc5, 0xf9, 0xf2, 0xe9, 0xec, 0xec, 0xe9, 0x63, 0x80, 0x04, 0x54, 0x64, 0x04,
    0x4d, 0x0e, 0x4d, 0x18, 0x4d, 0x1e, 0x4d, 0x28, 0xe2, 0xec, 0xe7, 0xf2, 0xe1, 0xf6, 0x65, 0x80,
    0x02, 0x05, 0xe5, 0xf6, 0x61, 0x80, 0x09, 0x0f, 0xe9, 0xe5, 0xf2, 0xe5, 0xf3, 0xe9, 0x73, 0x80,
    0x00, 0xeb, 0xef, 0x74, 0x82, 0x01, 0x17, 0x4d, 0x31, 0x4d, 0x3a, 0xe1, 0xe3, 0xe3, 0xe5, 0xee,
    0x74, 0x80, 0x01, 0x17, 0xe2, 0xe5, 0xec, 0xef, 0x77, 0x80, 0x1e, 0xb9, 0x65, 0x02, 0x4d, 0x48,
    0x4d, 0x53, 0xe7, 0xf5, 0xf2, 0xed, 0xf5, 0xeb, 0xe8, 0x69, 0x80, 0x0a, 0x0f, 0xed, 0xe1, 0xf4,
    0xf2, 0xe1, 0xe7, 0xf5, 0xf2, 0xed, 0xf5, 0xeb, 0xe8, 0x69, 0x80, 0x0a, 0x47, 0xe6, 0xe3, 0xf9,
    0xf2, 0xe9, 0xec, 0xec, 0xe9, 0x63, 0x80, 0x04, 0x44, 0x67, 0x02, 0x4d, 0x75, 0x4d, 0x7c, 0xf2,
    0xe1, 0xf6, 0x65, 0x80, 0x00, 0xe8, 0xf5, 0xea, 0xe1, 0xf2, 0xe1, 0xf4, 0x69, 0x80, 0x0a, 0x8f,
    0x68, 0x04, 0x4d, 0x90, 0x4d, 0x9b, 0x4d, 0xa6, 0x4d, 0xb0, 0xe1, 0xf2, 0xed, 0xe5, 0xee, 0xe9,
    0xe1, 0x6e, 0x80, 0x05, 0x67, 0xe2, 0xef, 0xf0, 0xef, 0xed, 0xef, 0xe6, 0x6f, 0x80, 0x31, 0x1d,
    0xe9, 0xf2, 0xe1, 0xe7, 0xe1, 0xee, 0x61, 0x80, 0x30, 0x48, 0xef, 0xef, 0xeb, 0xe1, 0xe2, 0xef,
    0xf6, 0x65, 0x80, 0x1e, 0xbb, 0x69, 0x04, 0x4d, 0xc5, 0x4d, 0xd0, 0x4f, 0x0a, 0x4f, 0x19, 0xe2,
    0xef, 0xf0, 0xef, 0xed, 0xef, 0xe6, 0x6f, 0x80, 0x31, 0x1f, 0xe7, 0xe8, 0x74, 0x8e, 0x00, 0x38,
    0x4d, 0xf2, 0x4d, 0xfb, 0x4e, 0x05, 0x4e, 0x23, 0x4e, 0x2a, 0x4e, 0x50, 0x4e, 0x69, 0x4e, 0x96,
];

/// SubBytes: translate every byte of a 16-byte state through
/// [`BLOCK_SUB_TABLE`]. Original: `FUN_0802e118` @ 0x0802e118 (60 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_sub_bytes(state: *mut u8) {
    for word in 0..4 {
        for byte in 0..4 {
            let p = state.add(word * 4 + byte);
            *p = BLOCK_SUB_TABLE[*p as usize];
        }
    }
}

/// InvSubBytes: translate every byte of a 16-byte state through
/// [`BLOCK_INV_SUB_TABLE`]. Original: `FUN_0802e154` @ 0x0802e154 (60
/// bytes).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_inv_sub_bytes(state: *mut u8) {
    for word in 0..4 {
        for byte in 0..4 {
            let p = state.add(word * 4 + byte);
            *p = BLOCK_INV_SUB_TABLE[*p as usize];
        }
    }
}

/// ShiftRows on the column-major 16-byte state: row 1 (bytes 4..8) left by
/// one, row 2 (bytes 8..12) by two, row 3 (bytes 12..16) by three.
/// Original: `FUN_0802e190` @ 0x0802e190 (100 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_shift_rows(state: *mut u8) {
    let s = |i: usize| state.add(i);
    // Row 1: [4] <- [5] <- [6] <- [7] <- [4].
    let b4 = s(4).read();
    s(4).write(s(5).read());
    s(5).write(s(6).read());
    s(6).write(s(7).read());
    s(7).write(b4);
    // Row 2: swap [8]<->[10], [9]<->[11].
    let b8 = s(8).read();
    s(8).write(s(10).read());
    s(10).write(b8);
    let b9 = s(9).read();
    s(9).write(s(11).read());
    s(11).write(b9);
    // Row 3: [15] -> [12] -> [13] -> [14] -> [15] (left by three).
    let b12 = s(12).read();
    s(12).write(s(15).read());
    let b14 = s(14).read();
    s(15).write(b14);
    s(14).write(s(13).read());
    s(13).write(b12);
}

/// InvShiftRows: the inverse row rotations. Original: `FUN_0802e1f4` @
/// 0x0802e1f4 (100 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_inv_shift_rows(state: *mut u8) {
    let s = |i: usize| state.add(i);
    // Row 1 right by one: [4] <- [7], [7] <- [6], [6] <- [5], [5] <- [4].
    let b4 = s(4).read();
    s(4).write(s(7).read());
    let b6 = s(6).read();
    s(7).write(b6);
    s(6).write(s(5).read());
    s(5).write(b4);
    // Row 2 (self-inverse): swap [8]<->[10], [9]<->[11].
    let b8 = s(8).read();
    s(8).write(s(10).read());
    s(10).write(b8);
    let b9 = s(9).read();
    s(9).write(s(11).read());
    s(11).write(b9);
    // Row 3 right by three: [12] <- [13] <- [14] <- [15] <- [12].
    let b12 = s(12).read();
    s(12).write(s(13).read());
    s(13).write(s(14).read());
    s(14).write(s(15).read());
    s(15).write(b12);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;
    use std::string::{String, ToString};
    use std::vec::Vec;

    /// Run the engine on a host double.
    fn dtoa(x: f64, ndigits: i32, style: i32) -> (i32, i32, i32, Vec<u8>) {
        let bits = x.to_bits();
        let mut out = [0i32; 3];
        let mut buf = [0u8; 32];
        unsafe {
            printf_float_dtoa(out.as_mut_ptr(), buf.as_mut_ptr(), &bits as *const u64, ndigits, style);
        }
        let n = out[1] as usize;
        assert_eq!(buf[n], 0, "digits not NUL-terminated");
        (out[0], out[1], out[2], buf[..n].to_vec())
    }

    /// Host oracle for style 0 (significant digits): digits + decimal
    /// exponent from Rust's own round-to-nearest-even formatter.
    fn expected_sig(x: f64, prec: usize) -> (String, i32) {
        let s = format!("{:.*e}", prec, x);
        let epos = s.find('e').unwrap();
        let exp: i32 = s[epos + 1..].parse().unwrap();
        let digits: String = s[..epos].chars().filter(|c| c.is_ascii_digit()).collect();
        (digits, exp)
    }

    /// Host oracle for style 1 (%f with `prec` fraction digits): digit
    /// string of round(x * 10^prec) and the value's decimal exponent,
    /// derived from Rust's fixed-point formatting.
    fn expected_fixed(x: f64, prec: usize) -> (String, i32) {
        let s = format!("{:.prec$}", x);
        let s = s.strip_prefix('-').unwrap_or(&s);
        let (int_part, frac_part) = match s.find('.') {
            Some(p) => (&s[..p], &s[p + 1..]),
            None => (s, ""),
        };
        let all: String = int_part.chars().chain(frac_part.chars()).collect();
        let zeros = all.len() - all.trim_start_matches('0').len();
        let digits = all.trim_start_matches('0').to_string();
        // Position of the first surviving digit relative to the point.
        let exp10 = int_part.len() as i32 - zeros as i32 - 1;
        (digits, exp10)
    }

    fn check_sig(x: f64, prec: usize) {
        let (want_digits, want_exp) = expected_sig(x, prec);
        let (exp10, len, style, digits) = dtoa(x, prec as i32 + 1, 0);
        assert_eq!(style, 0);
        assert_eq!(len as usize, want_digits.len(), "len for {x:e} prec {prec}");
        assert_eq!(
            core::str::from_utf8(&digits).unwrap(),
            want_digits,
            "digits for {x:e} prec {prec}"
        );
        assert_eq!(exp10, want_exp, "exp for {x:e} prec {prec}");
    }

    fn check_fixed(x: f64, prec: usize) {
        let (want_digits, want_exp) = expected_fixed(x, prec);
        let (exp10, len, style, digits) = dtoa(x, prec as i32, 1);
        assert_eq!(style, 1);
        let got = core::str::from_utf8(&digits).unwrap();
        // The engine emits every digit of the scaled integer; the oracle
        // drops leading zeros, which the engine never produces either.
        assert_eq!(got, want_digits, "digits for {x} prec {prec}");
        assert_eq!(len as usize, want_digits.len());
        assert_eq!(exp10, want_exp, "exp for {x} prec {prec}");
    }

    #[test]
    fn zero_and_negative_zero() {
        for &x in &[0.0f64, -0.0] {
            let (exp10, len, style, digits) = dtoa(x, 6, 0);
            assert_eq!((exp10, len, style), (0, 6, 0));
            assert_eq!(&digits, b"000000");
            let (exp10, len, style, digits) = dtoa(x, 2, 1);
            assert_eq!((exp10, len, style), (-3, 0, 1));
            assert_eq!(digits.len(), 0);
        }
    }

    #[test]
    fn one_point_zero() {
        check_sig(1.0, 0);
        check_sig(1.0, 6);
        check_sig(1.0, 16);
        check_fixed(1.0, 0);
        check_fixed(1.0, 6);
    }

    #[test]
    fn pi() {
        check_sig(core::f64::consts::PI, 0);
        check_sig(core::f64::consts::PI, 1);
        check_sig(core::f64::consts::PI, 6);
        check_sig(core::f64::consts::PI, 15);
        check_sig(core::f64::consts::PI, 16);
        check_fixed(core::f64::consts::PI, 0);
        check_fixed(core::f64::consts::PI, 2);
        check_fixed(core::f64::consts::PI, 14);
    }

    #[test]
    fn small_and_large() {
        check_sig(1e-3, 6);
        check_sig(1e-3, 16);
        check_fixed(1e-3, 6);
        check_sig(1e300, 6);
        check_sig(1e300, 16);
        check_sig(1e-300, 6);
        check_sig(-2.5e18, 6);
    }

    #[test]
    fn inexact_tenth() {
        // 0.1 is not exactly representable; the 17th digit shows it.
        check_sig(0.1, 0);
        check_sig(0.1, 5);
        check_sig(0.1, 15);
        check_sig(0.1, 16);
        check_fixed(0.1, 1);
        check_fixed(0.1, 6);
    }

    #[test]
    fn u64_max_as_double() {
        let x = u64::MAX as f64; // 18446744073709551616.0
        check_sig(x, 0);
        check_sig(x, 6);
        check_sig(x, 16);
    }

    #[test]
    fn denormals() {
        check_sig(5e-324, 6); // smallest denormal
        check_sig(5e-324, 16);
        check_sig(f64::from_bits(0x000f_ffff_ffff_ffff), 6); // largest denormal
        check_sig(f64::from_bits(0x0010_0000_0000_0000), 6); // smallest normal
        check_sig(f64::from_bits(0x0008_2345_6789_abcd), 9); // mid denormal
        check_fixed(5e-324, 6);
    }

    #[test]
    fn estimate_retry_paths() {
        // Values whose first decimal-exponent estimate is off in each
        // direction (leftover digits / leading zero in the style-0 loop).
        check_sig(9.999999, 6);
        check_sig(9.9999999e10, 6);
        check_sig(0.09999, 4);
        check_sig(99.5, 3);
        check_sig(999.5, 4);
        check_sig(1.000001, 6);
        check_fixed(261.0, 2);
        check_fixed(0.5, 0);
        check_fixed(2.5, 0); // ties to even -> "2"
        check_fixed(3.5, 0); // ties to even -> "4"
        check_fixed(1.2, 0); // rounds down even though stored above 1.2
    }

    #[test]
    fn fixed_large_value_retries_as_17_significant() {
        // %f of a value whose scaled integer needs more than 17 digits:
        // the engine falls back to 17 significant digits.
        let x = 1.2345678901234567e20;
        let (want_digits, want_exp) = expected_sig(x, 16);
        let (exp10, _len, style, digits) = dtoa(x, 6, 1);
        // style echoed is the RETRIED style (0), matching the original's
        // `str sl, [r2]` after sl was zeroed.
        assert_eq!(style, 0);
        assert_eq!(core::str::from_utf8(&digits).unwrap(), want_digits);
        assert_eq!(exp10, want_exp);
    }

    #[test]
    fn fuzz_against_host_formatting() {
        // Random finite doubles x precisions x both styles, strict equality
        // against the host RNE oracles. Divergence is only possible through
        // double rounding at a decimal tie (see module header); none should
        // appear in this sample.
        let mut seed = 0xdead_beef_cafe_f00du64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed
        };
        for i in 0..4000 {
            let bits = rnd();
            let x = f64::from_bits(bits);
            if !x.is_finite() {
                continue;
            }
            match i % 4 {
                // style 0: 1..=17 significant digits
                0 | 1 => {
                    let prec = (rnd() % 17) as usize;
                    let (want_digits, want_exp) = expected_sig(x, prec);
                    let (exp10, len, style, digits) = dtoa(x, prec as i32 + 1, 0);
                    assert_eq!(style, 0, "x={x:e} prec={prec}");
                    assert_eq!(exp10, want_exp, "exp x={x:e} prec={prec}");
                    assert_eq!(len as usize, want_digits.len(), "len x={x:e} prec={prec}");
                    assert_eq!(
                        core::str::from_utf8(&digits).unwrap(),
                        want_digits,
                        "digits x={x:e} prec={prec}"
                    );
                }
                // style 1: 0..=16 fraction digits (only values whose
                // scaled integer fits the 17-digit cap — larger ones take
                // the documented style-0 retry and are covered elsewhere)
                _ => {
                    let prec = (rnd() % 17) as usize;
                    let ax = x.abs();
                    let cap = 10f64.powi(17 - prec as i32);
                    if !(1e-300..cap).contains(&ax) && ax != 0.0 {
                        continue;
                    }
                    let (want_digits, want_exp) = expected_fixed(x, prec);
                    let (exp10, _len, style, digits) = dtoa(x, prec as i32, 1);
                    assert_eq!(style, 1, "x={x} prec={prec}");
                    assert_eq!(exp10, want_exp, "exp x={x} prec={prec}");
                    assert_eq!(
                        core::str::from_utf8(&digits).unwrap(),
                        want_digits,
                        "digits x={x} prec={prec}"
                    );
                }
            }
        }
    }

    // ---- pow10 / ext arithmetic ----

    /// Exact 10^e in the extended format, via a simple bignum: returns
    /// (biased exp word, mant64) with round-to-nearest-even at 64 bits.
    fn exact_pow10_ext(e: u32) -> (u32, u64) {
        // Big unsigned integer, little-endian u32 limbs.
        let mut limbs: Vec<u32> = std::vec![1];
        for _ in 0..e {
            let mut carry = 0u64;
            for l in limbs.iter_mut() {
                let v = *l as u64 * 10 + carry;
                *l = v as u32;
                carry = v >> 32;
            }
            if carry != 0 {
                limbs.push(carry as u32);
            }
        }
        let bits = 32 * limbs.len() - limbs.last().unwrap().leading_zeros() as usize;
        let e10 = bits as i64 - 1; // value in [2^e10, 2^(e10+1))
        // Extract the top 64 bits with RNE.
        let shift = bits as i64 - 64;
        let get_bit = |i: i64| -> u64 {
            if i < 0 {
                return 0;
            }
            (limbs[(i / 32) as usize] >> (i % 32)) as u64 & 1
        };
        let mut mant: u64 = 0;
        for i in 0..64 {
            mant |= get_bit(shift + i) << i;
        }
        if shift > 0 {
            let guard = get_bit(shift - 1);
            let mut any = 0;
            for i in 0..shift - 1 {
                any |= get_bit(i);
            }
            if guard == 1 && (any == 1 || mant & 1 == 1) {
                mant += 1; // cannot overflow: 10^e is never all ones
            }
        }
        ((0x3fff + e10) as u32, mant)
    }

    #[test]
    fn pow10_values() {
        for e in 0u32..=340 {
            let mut ext = [0u32; 3];
            unsafe { dtoa_pow10(ext.as_mut_ptr(), e, 0) };
            let (want_exp, want_mant) = exact_pow10_ext(e);
            assert_eq!(ext[0], want_exp, "exp word for 10^{e}");
            let got = ((ext[1] as u64) << 32) | ext[2] as u64;
            // The original builds 10^e by repeated 64-bit-rounded extended
            // multiplies, so allow one ulp of accumulated rounding.
            let diff = got.abs_diff(want_mant);
            assert!(diff <= 1, "10^{e}: got {got:#x}, want {want_mant:#x}");
        }
    }

    #[test]
    fn mul_core_matches_exact_product() {
        let mut seed = 0x12345678u64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 11) | (1 << 63)
        };
        for _ in 0..2000 {
            let a = rnd();
            let b = rnd();
            let (ea, eb) = (0x3fffu32 + (a % 100) as u32, 0x3fffu32 + (b % 200) as u32);
            let (_, exp, mh, ml, sticky) =
                ext_fp_mul_core([ea, (a >> 32) as u32, a as u32], [eb, (b >> 32) as u32, b as u32]);
            // Exact model with u128.
            let p = (a as u128) * (b as u128);
            let mut hi = (p >> 64) as u64;
            let lo = p as u64;
            let lo32 = lo as u32;
            let mid32 = (lo >> 32) as u32;
            let mut want_sticky = mid32 | ((lo32 | lo32.wrapping_shl(2)) >> 2);
            let mut want_exp = ea.wrapping_add(eb).wrapping_sub(0x3ffe);
            if hi >> 63 == 0 {
                // Normalize: 96-bit sticky:mant shift left by one.
                let carry = want_sticky >> 31;
                want_sticky <<= 1;
                hi = (hi << 1) | carry as u64;
                want_exp = want_exp.wrapping_sub(1);
            }
            assert_eq!(((mh as u64) << 32) | ml as u64, hi);
            assert_eq!(exp, want_exp);
            assert_eq!(sticky, want_sticky);
        }
    }

    /// Round-to-nearest-even of the value num/den (positive integers) at
    /// 64 mantissa bits; returns (exp adjust relative to inputs, mant64).
    fn rne_div_model(a: u64, b: u64) -> (i32, u64, u32) {
        // quotient a/b normalized to [2^63, 2^64)
        let (num, exp_adj) = if a >= b { ((a as u128) << 63, 0) } else { ((a as u128) << 64, -1) };
        let q = (num / b as u128) as u64;
        let rem = num % b as u128;
        let sticky = if rem == 0 {
            0
        } else if rem * 2 == b as u128 {
            0x8000_0000
        } else if rem * 2 > b as u128 {
            0xc000_0000
        } else {
            0x4000_0000
        };
        (exp_adj, q, sticky)
    }

    #[test]
    fn div_core_quotient_and_round_class() {
        let mut seed = 0x87654321u64;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 11) | (1 << 63)
        };
        for _ in 0..4000 {
            let a = rnd();
            let b = rnd();
            let (_, exp, mh, ml, sticky) = ext_fp_div_core(
                [0x3fff, (a >> 32) as u32, a as u32],
                [0x3fff, (b >> 32) as u32, b as u32],
            );
            let (want_adj, want_q, _) = rne_div_model(a, b);
            assert_eq!(((mh as u64) << 32) | ml as u64, want_q, "a={a:#x} b={b:#x}");
            assert_eq!(exp, (0x3fff + want_adj) as u32, "exp a={a:#x} b={b:#x}");
            // Rounding classification.
            let num = if a >= b { (a as u128) << 63 } else { (a as u128) << 64 };
            let rem = num % b as u128;
            let exact = rem == 0;
            let half = rem * 2 == b as u128;
            let guard = rem * 2 > b as u128;
            assert_eq!(sticky == 0, exact, "zero class a={a:#x} b={b:#x}");
            assert_eq!(sticky == 0x8000_0000, half, "half class a={a:#x} b={b:#x}");
            assert_eq!(sticky >> 31 == 1, guard, "guard a={a:#x} b={b:#x}");
        }
    }

    #[test]
    fn round_nearest_ties_even() {
        // exact: no round
        assert_eq!(ext_fp_round(0, 100, 0x8000_0000, 5, 0, 0), [100, 0x8000_0000, 5]);
        // guard set, sticky clear, mantissa even: no round
        assert_eq!(
            ext_fp_round(0, 100, 0x8000_0000, 4, 0x8000_0000, 0),
            [100, 0x8000_0000, 4]
        );
        // same but odd: round up
        assert_eq!(
            ext_fp_round(0, 100, 0x8000_0000, 5, 0x8000_0000, 0),
            [100, 0x8000_0000, 6]
        );
        // guard + sticky: round up
        assert_eq!(
            ext_fp_round(0, 100, 0x8000_0000, 4, 0x8000_0001, 0),
            [100, 0x8000_0000, 5]
        );
        // below guard: no round
        assert_eq!(
            ext_fp_round(0, 100, 0x8000_0000, 4, 0x7fff_ffff, 0),
            [100, 0x8000_0000, 4]
        );
        // carry ripples into the exponent
        assert_eq!(
            ext_fp_round(0, 100, 0xffff_ffff, 0xffff_ffff, 0xc000_0000, 0),
            [101, 0x8000_0000, 0]
        );
        // adj = -1 truncates; adj = 1 rounds up on inexact
        assert_eq!(
            ext_fp_round(0, 100, 0x8000_0000, 4, 0xc000_0000, -1),
            [100, 0x8000_0000, 4]
        );
        assert_eq!(
            ext_fp_round(0, 100, 0x8000_0000, 4, 0x4000_0000, 1),
            [100, 0x8000_0000, 5]
        );
        // sign preserved
        assert_eq!(
            ext_fp_round(0x8000_0000, 100, 0x8000_0000, 0, 0, 0)[0],
            0x8000_0000 | 100
        );
    }

    #[test]
    fn round_underflow_integerizes() {
        // The engine's digit extraction: exp < 0 un-normalizes with a plain
        // right shift, discarded bits folded into the sticky word.
        // 1.5 * 2^63 at exp -1 -> 0x6000000000000000, still exact.
        let r = ext_fp_round(0, (-1i32) as u32, 0xc000_0000, 0, 0, 0);
        assert_eq!(r, [0, 0x6000_0000, 0]);
        // 1.5 * 2^63 at exp -63 -> 1 with an exact-half tie, odd -> 2.
        let r = ext_fp_round(0, (-63i32) as u32, 0xc000_0000, 0, 0, 0);
        assert_eq!(r, [0, 0, 2]);
        // 1.2 (the double 0x3FF3333333333333 as ext: 0x9999999999999800)
        // at exp -63 -> 1, fraction below half.
        let r = ext_fp_round(0, (-63i32) as u32, 0x9999_9999, 0x9999_9800, 0, 0);
        assert_eq!(r, [0, 0, 1]);
        // 2.5 at exp -62 -> 2 (tie, even)
        let r = ext_fp_round(0, (-62i32) as u32, 0xa000_0000, 0, 0, 0);
        assert_eq!(r, [0, 0, 2]);
        // 3.5 at exp -62 -> 4 (tie, odd)
        let r = ext_fp_round(0, (-62i32) as u32, 0xe000_0000, 0, 0, 0);
        assert_eq!(r, [0, 0, 4]);
    }

    #[test]
    fn round_to_double_basic() {
        // ext 1.2 (biased 0x3fff) -> double 0x3FF3333333333333
        let d = ext_fp_round_to_double(0, 0x3fff, 0x9999_9999, 0x9999_9800, 0, 0);
        assert_eq!(d, 0x3FF3_3333_3333_3333);
        // 1.5 -> 0x3FF8000000000000
        let d = ext_fp_round_to_double(0, 0x3fff, 0xc000_0000, 0, 0, 0);
        assert_eq!(d, 0x3FF8_0000_0000_0000);
        // overflow (double exponent 0x7ff reached) -> unsigned infinity
        let d = ext_fp_round_to_double(0, 0x4400, 0x8000_0000, 0, 0, 0);
        assert_eq!(d, 0x7FF0_0000_0000_0000);
        // sign is dropped by the original
        let d = ext_fp_round_to_double(0x8000_0000, 0x3fff, 0x8000_0000, 0, 0, 0);
        assert_eq!(d, 0x3FF0_0000_0000_0000);
    }

    #[test]
    fn double_to_ext_cases() {
        // 1.0
        assert_eq!(double_to_ext(0x3ff0_0000, 0), [0x3fff, 0x8000_0000, 0]);
        // -2.0
        assert_eq!(double_to_ext(0xc000_0000, 0), [0x8000_4000, 0x8000_0000, 0]);
        // 0.1
        assert_eq!(
            double_to_ext(0x3fb9_9999, 0x9999_999a),
            [0x3ffb, 0xcccc_cccc, 0xcccc_d000]
        );
        // zero / negative zero
        assert_eq!(double_to_ext(0, 0), [0, 0, 0]);
        assert_eq!(double_to_ext(0x8000_0000, 0), [0x8000_0000, 0, 0]);
        // smallest denormal: 2^-1074 -> mantissa 2^63, exp = -1074 + 0x3fff
        assert_eq!(
            double_to_ext(0, 1),
            [(0x3fff - 1074) as u32, 0x8000_0000, 0]
        );
        // largest denormal
        let e = double_to_ext(0x000f_ffff, 0xffff_ffff);
        assert_eq!(e[0], 0x3fff - 1023);
        assert_eq!(e[1] >> 31, 1);
        // inf gets the marker
        let e = double_to_ext(0x7ff0_0000, 0);
        assert_eq!(e[0] & 0x4000_0000, 0x4000_0000);
    }

    #[test]
    fn ext_mul_div_double_entries() {
        // 3.0 * 0.1 and 3.0 / 0.1 via the extended ops == host IEEE mul/div
        // (both round to nearest, ties to even).
        let a = double_to_ext(0x4008_0000, 0); // 3.0
        let b = double_to_ext(0x3fb9_9999, 0x9999_999a); // 0.1
        let m = unsafe { ext_mul_dbl(a.as_ptr(), b.as_ptr(), 0) };
        assert_eq!(m, (3.0f64 * 0.1f64).to_bits());
        let d = unsafe { ext_div_dbl(a.as_ptr(), b.as_ptr(), 0) };
        assert_eq!(d, (3.0f64 / 0.1f64).to_bits());
        // The extended-result entry normalizes and stays in range.
        let mut r = [0u32; 3];
        unsafe { ext_mul_ext(a.as_ptr(), b.as_ptr(), 0, r.as_mut_ptr()) };
        assert_eq!(r[1] >> 31, 1);
        assert_eq!(r[0] & 0x4000_0000, 0);
    }

    // ---- block cipher helpers ----

    #[test]
    fn block_sub_bytes_translate() {
        let mut state: [u8; 16] = core::array::from_fn(|i| (i * 17 + 3) as u8);
        let orig = state;
        unsafe { block_sub_bytes(state.as_mut_ptr()) };
        for i in 0..16 {
            assert_eq!(state[i], BLOCK_SUB_TABLE[orig[i] as usize]);
        }
        let mut state2 = orig;
        unsafe { block_inv_sub_bytes(state2.as_mut_ptr()) };
        for i in 0..16 {
            assert_eq!(state2[i], BLOCK_INV_SUB_TABLE[orig[i] as usize]);
        }
    }

    #[test]
    fn block_shift_rows_pattern() {
        let state: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut s = state;
        unsafe { block_shift_rows(s.as_mut_ptr()) };
        assert_eq!(
            s,
            [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14]
        );
        // inv(forward) must be the identity
        unsafe { block_inv_shift_rows(s.as_mut_ptr()) };
        assert_eq!(s, state);
        // and forward(inverse) too
        let mut t = state;
        unsafe {
            block_inv_shift_rows(t.as_mut_ptr());
            block_shift_rows(t.as_mut_ptr());
        }
        assert_eq!(t, state);
    }
}
