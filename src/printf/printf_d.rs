//! `convert_d` / `convert_u` — original: `FUN_0802f4b4` @ 0x0802f4b4
//! (176 bytes), the retailOS printf converter for the 32-bit integer
//! conversions `%d` / `%i` / `%u`.
//!
//! The original is a single function dispatched on the conversion character
//! (`'u'` = unsigned, anything else signed); here the two public entry
//! points wrap a shared body keyed on a `signed` flag. Algorithm:
//!
//! 1. Widen the argument per the length flags (`widen_signed` /
//!    `widen_unsigned` from `printf_helpers`: `hh` re-extends from 8 bits,
//!    `h` from 16, else pass through).
//! 2. Signed only: pick the sign/prefix character — `'-'` for negative
//!    values (negating with wraparound, so `i32::MIN` prints as
//!    `-2147483648`), else `'+'` when flag 0x2 (`+`) is set, else `' '`
//!    when flag 0x4 (space) is set, else none. The original keeps these as
//!    the one-byte string literals `"-"` / `"+"` / `" "` / `""` in the
//!    literal pool at 0x0802f564 and passes a (pointer, length) pair.
//! 3. Peel decimal digits least-significant-first into a stack buffer via
//!    repeated division by 10 (see [`div10`]).
//! 4. Emit: the original tails into the shared numeric emitter
//!    `FUN_080322cc` @ 0x080322cc (assigned to `printf_out`, ported
//!    separately); it is inlined here as [`emit_number`] so this module
//!    stays self-contained and host-testable. Its logic, mirrored exactly:
//!    - Minimum digit count is 1, or `precision` when FLAG_PRECISION_GIVEN
//!      (0x20) is set — and in that case FLAG_ZERO_PAD (0x10) is *cleared
//!      in the state*, i.e. the `0` flag is ignored once a precision is
//!      given (verified in the original: `flags &= 0xffffffef`).
//!    - `pad_remaining -= zero_fill + num_digits + prefix_len`, then:
//!      leading space pad (unless zero-padding), prefix char, leading zero
//!      pad (so the sign lands before the zeros: `%05d` of -42 is
//!      `-0042`), precision zero-fill, digits most-significant-first, and
//!      finally trailing spaces for left-justified fields.
//!
//! Simplifications vs. the original:
//! - The digit buffer is `[u8; 10]` (max digits of a u32); the original
//!   reserves 32 bytes on the stack. The prefix is a single `u8`
//!   (`0` = none) instead of a pointer into the literal pool.
//! - `div10` inlines the shift-add divide-by-10 of the shared helper
//!   `FUN_08033694` @ 0x08033694 (quotient + remainder via a
//!   `num * 0.8` approximation and a single fix-up step, the 32-bit twin
//!   of `_ll_udiv10`). Keeping the sequence verbatim lowers to plain
//!   shifts/adds on armv5te — no `__aeabi_uidiv` libcall.
//! - The shared emitter is inlined (see step 4); semantics, including the
//!   per-character `count` bumps and the in-place clearing of
//!   FLAG_ZERO_PAD, are identical.

use crate::printf_helpers::{
    pad_emit, pad_emit_zero, widen_signed, widen_unsigned, PrintfState, FLAG_PRECISION_GIVEN,
    FLAG_ZERO_PAD,
};

/// Format flag: `+` — always show a sign for signed conversions.
/// Not part of `printf_helpers` (no helper there consumes it).
const FLAG_SHOW_SIGN: u32 = 0x002;
/// Format flag: ` ` (space) — prefix positive signed values with a space.
const FLAG_SPACE_SIGN: u32 = 0x004;

/// `convert_d` — port of the signed (`%d` / `%i`) path of the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn convert_d(state: *mut PrintfState, value: i32) {
    convert_int(state, value as u32, true);
}

/// `convert_u` — port of the unsigned (`%u`) path of the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn convert_u(state: *mut PrintfState, value: u32) {
    convert_int(state, value, false);
}

/// Shared body of the original `FUN_0802f4b4`: widen, pick the prefix,
/// peel digits, emit.
unsafe fn convert_int(state: *mut PrintfState, value: u32, signed: bool) {
    let mut prefix = 0u8; // 0 = no prefix
    let magnitude;
    if signed {
        let wide = widen_signed(value as i32, state);
        if wide < 0 {
            // Wrapping negate: i32::MIN stays 0x80000000 as a magnitude.
            magnitude = (wide as u32).wrapping_neg();
            prefix = b'-';
        } else {
            magnitude = wide as u32;
            let flags = (*state).flags;
            if flags & FLAG_SHOW_SIGN != 0 {
                prefix = b'+';
            } else if flags & FLAG_SPACE_SIGN != 0 {
                prefix = b' ';
            }
        }
    } else {
        magnitude = widen_unsigned(value, state);
    }

    // Digits, least-significant first; empty when magnitude == 0 (the
    // emitter's minimum digit count of 1 turns that into "0"). A u32 has
    // at most 10 decimal digits, so `num_digits` stays in bounds (the
    // original reserves 32 stack bytes and has no bounds check either).
    let mut digits = [0u8; 10];
    let mut num_digits = 0usize;
    let mut remaining = magnitude;
    while remaining != 0 {
        let (quot, rem) = div10(remaining);
        *digits.get_unchecked_mut(num_digits) = rem + b'0';
        num_digits += 1;
        remaining = quot;
    }

    emit_number(state, digits.get_unchecked(..num_digits), prefix);
}

/// Inlined port of the shared numeric emitter `FUN_080322cc` @ 0x080322cc
/// (see module doc). `digits` are least-significant first; `prefix` is the
/// sign/prefix character or 0 for none.
unsafe fn emit_number(state: *mut PrintfState, digits: &[u8], prefix: u8) {
    let min_digits = if (*state).flags & FLAG_PRECISION_GIVEN != 0 {
        // A given precision turns off zero-padding (original clears the
        // flag in the state, so the zero_pad() tests below see it too).
        (*state).flags &= !FLAG_ZERO_PAD;
        (*state).precision
    } else {
        1
    };
    let zero_fill = (min_digits - digits.len() as i32).max(0);
    let prefix_len = if prefix != 0 { 1 } else { 0 };
    (*state).pad_remaining -= zero_fill + digits.len() as i32 + prefix_len;

    if !(*state).zero_pad() {
        pad_emit(state);
    }
    if prefix != 0 {
        ((*state).putc)(prefix, (*state).putc_ctx);
        (*state).count += 1;
    }
    if (*state).zero_pad() {
        pad_emit(state);
    }
    for _ in 0..zero_fill {
        ((*state).putc)(b'0', (*state).putc_ctx);
        (*state).count += 1;
    }
    for &digit in digits.iter().rev() {
        ((*state).putc)(digit, (*state).putc_ctx);
        (*state).count += 1;
    }
    pad_emit_zero(state);
}

/// Port of the shift-add divide-by-10 helper `FUN_08033694` @ 0x08033694:
/// returns `(num / 10, num % 10)` without a divider. `x` approximates
/// `num * 0.8` (the factors telescope to `0x33333333 / 2^30`), so
/// `quot = x >> 3` is `num / 10` rounded down, at most one too small;
/// the fix-up on `rem = (num - 10) - quot * 10` decides both whether to
/// bump the quotient and the final remainder. Never overflows: the
/// running total stays below `0.8 * num`.
fn div10(num: u32) -> (u32, u8) {
    let mut x = num - (num >> 2);
    x = x.wrapping_add(x >> 4);
    x = x.wrapping_add(x >> 8);
    x = x.wrapping_add(x >> 16);
    let mut quot = x >> 3;
    let mut rem = num.wrapping_sub(10).wrapping_sub(quot.wrapping_mul(10));
    if (rem as i32) < 0 {
        rem = rem.wrapping_add(10);
    } else {
        quot += 1;
    }
    (quot, rem as u8)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::printf_helpers::{
        FLAG_LEFT_JUSTIFY, FLAG_LEN_H, FLAG_LEN_HH,
    };
    use core::ffi::c_void;
    use std::string::String;
    use std::vec::Vec;

    struct Sink {
        buf: Vec<u8>,
    }

    unsafe extern "C" fn sink_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Sink)).buf.push(c);
    }

    /// Run a conversion and return the emitted text. `width` is loaded
    /// into `pad_remaining` the way the printf core does before calling
    /// the converter; `precision` is only meaningful with
    /// FLAG_PRECISION_GIVEN. Also asserts the state's `count` matches the
    /// emitted length.
    fn render_d(flags: u32, width: i32, precision: i32, value: i32) -> String {
        render(flags, width, precision, value as u32, true)
    }

    fn render_u(flags: u32, width: i32, precision: i32, value: u32) -> String {
        render(flags, width, precision, value, false)
    }

    fn render(flags: u32, width: i32, precision: i32, value: u32, signed: bool) -> String {
        let mut sink = Sink { buf: Vec::new() };
        let mut state = PrintfState {
            reserved_00: [0; 2],
            prefix: core::ptr::null(),
            reserved_0c: [0; 3],
            flags,
            putc: sink_putc,
            emit_str: None,
            putc_ctx: &mut sink as *mut Sink as *mut c_void,
            reserved_28: [0; 3],
            pad_remaining: width,
            precision,
            count: 0,
        };
        unsafe {
            if signed {
                convert_d(&mut state, value as i32);
            } else {
                convert_u(&mut state, value);
            }
        }
        assert_eq!(
            state.count as usize,
            sink.buf.len(),
            "count mismatch: flags={flags:#x} width={width} prec={precision} value={value:#x}"
        );
        String::from_utf8(sink.buf).unwrap()
    }

    #[test]
    fn plain_values() {
        assert_eq!(render_d(0, 0, 0, 0), "0");
        assert_eq!(render_d(0, 0, 0, 1), "1");
        assert_eq!(render_d(0, 0, 0, -1), "-1");
        assert_eq!(render_d(0, 0, 0, 42), "42");
        assert_eq!(render_d(0, 0, 0, -42), "-42");
        assert_eq!(render_d(0, 0, 0, i32::MAX), "2147483647");
        assert_eq!(render_d(0, 0, 0, i32::MIN), "-2147483648");
        assert_eq!(render_u(0, 0, 0, 0), "0");
        assert_eq!(render_u(0, 0, 0, 1), "1");
        assert_eq!(render_u(0, 0, 0, u32::MAX), "4294967295");
    }

    #[test]
    fn field_width_space_pad() {
        assert_eq!(render_d(0, 5, 0, 42), "   42");
        assert_eq!(render_d(0, 5, 0, -42), "  -42");
        assert_eq!(render_d(0, 2, 0, 42), "42"); // width < content: no pad
        assert_eq!(render_d(0, 0, 0, 42), "42");
        assert_eq!(render_u(0, 12, 0, u32::MAX), "  4294967295");
    }

    #[test]
    fn left_justify() {
        assert_eq!(render_d(FLAG_LEFT_JUSTIFY, 5, 0, 42), "42   ");
        assert_eq!(render_d(FLAG_LEFT_JUSTIFY, 5, 0, -42), "-42  ");
        // Zero flag is meaningless with left justify (pads are spaces).
        assert_eq!(
            render_d(FLAG_LEFT_JUSTIFY | FLAG_ZERO_PAD, 5, 0, 42),
            "42   "
        );
    }

    #[test]
    fn zero_pad_sign_comes_first() {
        assert_eq!(render_d(FLAG_ZERO_PAD, 5, 0, 42), "00042");
        assert_eq!(render_d(FLAG_ZERO_PAD, 5, 0, -42), "-0042");
        assert_eq!(render_d(FLAG_ZERO_PAD, 12, 0, i32::MIN), "-02147483648");
    }

    #[test]
    fn precision_zero_fills() {
        const P: u32 = FLAG_PRECISION_GIVEN;
        assert_eq!(render_d(P, 0, 5, 42), "00042");
        assert_eq!(render_d(P, 0, 5, -42), "-00042");
        assert_eq!(render_d(P, 8, 5, 42), "   00042");
        assert_eq!(render_d(P, 0, 2, 42), "42"); // precision < digits
        // Zero flag is ignored once a precision is given.
        assert_eq!(render_d(P | FLAG_ZERO_PAD, 8, 5, 42), "   00042");
        assert_eq!(render_d(P | FLAG_ZERO_PAD, 8, 5, -42), "  -00042");
    }

    #[test]
    fn precision_zero_of_zero_is_empty() {
        const P: u32 = FLAG_PRECISION_GIVEN;
        assert_eq!(render_d(P, 0, 0, 0), "");
        assert_eq!(render_d(P, 4, 0, 0), "    ");
        assert_eq!(render_u(P, 0, 0, 0), "");
        // ... but a nonzero value still prints.
        assert_eq!(render_d(P, 0, 0, 5), "5");
    }

    #[test]
    fn show_sign_and_space_flags() {
        assert_eq!(render_d(FLAG_SHOW_SIGN, 0, 0, 42), "+42");
        assert_eq!(render_d(FLAG_SHOW_SIGN, 0, 0, 0), "+0");
        assert_eq!(render_d(FLAG_SPACE_SIGN, 0, 0, 42), " 42");
        // '+' wins over space; neither affects negatives.
        assert_eq!(render_d(FLAG_SHOW_SIGN | FLAG_SPACE_SIGN, 0, 0, 42), "+42");
        assert_eq!(render_d(FLAG_SHOW_SIGN, 0, 0, -42), "-42");
        assert_eq!(render_d(FLAG_SPACE_SIGN, 0, 0, -42), "-42");
        // Prefix participates in width: sign before zeros.
        assert_eq!(render_d(FLAG_SHOW_SIGN | FLAG_ZERO_PAD, 5, 0, 42), "+0042");
        assert_eq!(render_d(FLAG_SHOW_SIGN, 5, 0, 42), "  +42");
        // Unsigned conversions never get a sign prefix.
        assert_eq!(render_u(FLAG_SHOW_SIGN, 0, 0, 42), "42");
        assert_eq!(render_u(FLAG_SPACE_SIGN, 0, 0, 42), "42");
    }

    #[test]
    fn length_modifiers_signed() {
        // h: re-extend from 16 bits.
        assert_eq!(render_d(FLAG_LEN_H, 0, 0, 0x8000), "-32768");
        assert_eq!(render_d(FLAG_LEN_H, 0, 0, 0x7fff), "32767");
        assert_eq!(render_d(FLAG_LEN_H, 0, 0, 0x1234_8000), "-32768");
        // hh: re-extend from 8 bits.
        assert_eq!(render_d(FLAG_LEN_HH, 0, 0, 0xff), "-1");
        assert_eq!(render_d(FLAG_LEN_HH, 0, 0, 0x80), "-128");
        assert_eq!(render_d(FLAG_LEN_HH, 0, 0, 0x7f), "127");
        // hh wins when both are set.
        assert_eq!(render_d(FLAG_LEN_H | FLAG_LEN_HH, 0, 0, 0x8080), "-128");
    }

    #[test]
    fn length_modifiers_unsigned() {
        assert_eq!(render_u(FLAG_LEN_H, 0, 0, 0xdeadbeef), "48879"); // 0xbeef
        assert_eq!(render_u(FLAG_LEN_HH, 0, 0, 0xdeadbeef), "239"); // 0xef
        assert_eq!(render_u(FLAG_LEN_H | FLAG_LEN_HH, 0, 0, 0xdeadbeef), "239");
        assert_eq!(render_u(FLAG_LEN_H, 0, 0, 0xffff), "65535");
    }

    #[test]
    fn precision_counts_into_width() {
        const P: u32 = FLAG_PRECISION_GIVEN;
        // "%10.5d" of -42: sign + 5 digits = 6, so 4 leading spaces.
        assert_eq!(render_d(P, 10, 5, -42), "    -00042");
        // Left-justified variant.
        assert_eq!(render_d(P | FLAG_LEFT_JUSTIFY, 10, 5, -42), "-00042    ");
    }

    #[test]
    fn div10_matches_hardware_divide() {
        let mut check = |num: u32| {
            assert_eq!(div10(num), (num / 10, (num % 10) as u8), "div10({num})");
        };
        for num in 0..100_000u32 {
            check(num);
        }
        for k in 0..=9u32 {
            let p = 10u32.pow(k);
            for num in [p.wrapping_sub(1), p, p + 1] {
                check(num);
            }
        }
        for num in [u32::MAX, u32::MAX - 1, u32::MAX - 9, u32::MAX - 10, 1 << 31] {
            check(num);
        }
        // Pseudo-random sweep (xorshift32).
        let mut state = 0x9E3779B9u32;
        for _ in 0..100_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            check(state);
        }
    }
}
