//! Port of the printf `%x`/`%X`/`%p` hex converter.
//!
//! Original: `FUN_0802f384` @ 0x0802f384 (280 bytes), ARM ADS 1.0.1.
//!
//! Algorithm (recovered from the machine code): the original is a single
//! entry taking `(state, spec_char, value_lo, value_hi)`. It picks the
//! lowercase ("0123456789abcdef" @ 0x80985be4) or uppercase
//! ("0123456789ABCDEF" @ 0x80985bf5) digit table by `spec_char == 'X'`,
//! re-widens the argument per the h/hh length flags unless `ll` is given,
//! works out the `#` alternate-form prefix ("0x"/"0X" for nonzero values;
//! the odd 1-byte "@" prefix @ 0x802f4a8 for `%#p`), forces
//! precision-given + precision 8 for `%p`, extracts nibbles least
//! significant first into a stack buffer, and hands digits + prefix to the
//! shared integer emitter `FUN_080322cc` (leading pad, prefix, zero pad,
//! precision zeros, digits most significant first, trailing pad).
//!
//! Simplifications vs. the original:
//! - The spec-char dispatch is split into three entries: [`convert_x`],
//!   [`convert_X`] and [`convert_p`], matching the fixed signature
//!   `convert_x(state, value)` the printf core uses.
//! - The value is `u32`, not a 64-bit lo/hi pair (`ll` hex goes through
//!   printf_ll). FLAG_LEN_LL therefore only suppresses the h/hh
//!   re-widening, as in the original's `tst flags,#0x80` branch.
//! - The shared emitter `FUN_080322cc` is inlined here as `emit_integer`
//!   (it is ported separately in printf_out, which this module may not
//!   import); semantics — precision clears FLAG_ZERO_PAD in the state,
//!   `pad_remaining -= zeros + ndigits + prefix_len`, zeros emitted
//!   between prefix and digits — are identical.
//! - The digit buffer is 8 bytes (max for a u32) instead of the
//!   original's 32-byte stack frame.

use crate::printf_helpers::{
    pad_emit, pad_emit_zero, widen_unsigned, PrintfState, FLAG_PRECISION_GIVEN, FLAG_ZERO_PAD,
};

/// Format flag: `#` — alternate form. For hex, prefixes nonzero values
/// with "0x"/"0X". (Not in printf_helpers: no helper there consumes it.)
pub const FLAG_ALTERNATE: u32 = 0x008;
/// Length modifier `ll`: argument is 64-bit. In this u32-only port it
/// only suppresses the h/hh re-widening (see module docs).
pub const FLAG_LEN_LL: u32 = 0x080;

/// Lowercase hex digits (original table @ 0x80985be4).
pub const HEX_DIGITS_LOWER: [u8; 16] = *b"0123456789abcdef";
/// Uppercase hex digits (original table @ 0x80985bf5).
pub const HEX_DIGITS_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Shared body of the three entries, mirroring `FUN_0802f384` with the
/// spec char folded into `upper`/`pointer`.
unsafe fn convert_hex(state: *mut PrintfState, mut value: u32, upper: bool, pointer: bool) {
    let table = if upper {
        &HEX_DIGITS_UPPER
    } else {
        &HEX_DIGITS_LOWER
    };

    // ll args arrive pre-widened; anything else is masked per h/hh.
    if (*state).flags & FLAG_LEN_LL == 0 {
        value = widen_unsigned(value, state);
    }

    let mut prefix: &[u8] = b"";
    if pointer {
        // `%p`: `#` adds the original's 1-byte "@" prefix (@ 0x802f4a8);
        // either way the value prints with an implied precision of 8.
        if (*state).flags & FLAG_ALTERNATE != 0 {
            prefix = b"@";
        }
        (*state).flags |= FLAG_PRECISION_GIVEN;
        (*state).precision = 8;
    } else if (*state).flags & FLAG_ALTERNATE != 0 && value != 0 {
        prefix = if upper { b"0X" } else { b"0x" };
    }

    // Nibbles, least significant first (original: 32-byte stack buffer,
    // 64-bit funnel shift; here a u32 shifted down by 4 per digit).
    let mut digits = [0u8; 8];
    let mut ndigits = 0usize;
    while value != 0 {
        digits[ndigits] = table[(value & 0xf) as usize];
        value >>= 4;
        ndigits += 1;
    }

    emit_integer(state, &digits[..ndigits], prefix);
}

/// Inlined `FUN_080322cc` @ 0x080322cc: emit an unsigned integer given as
/// least-significant-first `digits_rev`, with `prefix` ("0x", ...) in
/// front. Honors precision (minimum digit count; clearing FLAG_ZERO_PAD
/// in the state), field width via `pad_remaining`, and left-justify.
unsafe fn emit_integer(state: *mut PrintfState, digits_rev: &[u8], prefix: &[u8]) {
    let st = &mut *state;

    // Minimum digit count: the precision when given (which also kills
    // zero-padding — the original clears the flag in the state), else 1
    // so that a zero value still prints as "0".
    let min_digits = if st.flags & FLAG_PRECISION_GIVEN != 0 {
        st.flags &= !FLAG_ZERO_PAD;
        st.precision
    } else {
        1
    };
    let zeros = (min_digits - digits_rev.len() as i32).max(0);

    st.pad_remaining -= zeros + digits_rev.len() as i32 + prefix.len() as i32;

    // Right-justified space padding comes before the prefix; zero
    // padding between prefix and digits (pad_emit resolves both).
    if !st.zero_pad() {
        pad_emit(state);
    }
    for &c in prefix {
        (st.putc)(c, st.putc_ctx);
        st.count += 1;
    }
    if st.zero_pad() {
        pad_emit(state);
    }
    for _ in 0..zeros {
        (st.putc)(b'0', st.putc_ctx);
        st.count += 1;
    }
    for &c in digits_rev.iter().rev() {
        (st.putc)(c, st.putc_ctx);
        st.count += 1;
    }
    pad_emit_zero(state);
}

/// `convert_x` — `%x` converter. Original: `FUN_0802f384` @ 0x0802f384
/// with spec char 'x' (lowercase digits, "0x" alternate prefix).
#[no_mangle]
pub unsafe extern "C" fn convert_x(state: *mut PrintfState, value: u32) {
    convert_hex(state, value, false, false)
}

/// `convert_X` — `%X` converter: same path with the uppercase digit
/// table and "0X" alternate prefix (original: spec char 'X').
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn convert_X(state: *mut PrintfState, value: u32) {
    convert_hex(state, value, true, false)
}

/// `convert_p` — `%p` converter: lowercase digits, implied precision 8
/// (original: spec char 'p').
#[no_mangle]
pub unsafe extern "C" fn convert_p(state: *mut PrintfState, value: u32) {
    convert_hex(state, value, false, true)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::printf_helpers::{FLAG_LEFT_JUSTIFY, FLAG_LEN_H, FLAG_LEN_HH};
    use core::ffi::c_void;
    use std::string::String;
    use std::vec::Vec;

    /// Recording sink, same shape as the printf_helpers tests.
    struct Sink {
        buf: Vec<u8>,
    }

    unsafe extern "C" fn sink_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Sink)).buf.push(c);
    }

    /// Run a converter against a mock state: `width` is preloaded into
    /// `pad_remaining` (the core presets it to the field width; the
    /// emitter subtracts the content length). Returns the emitted text
    /// and the final state (for flag/count assertions).
    fn run(
        conv: unsafe extern "C" fn(*mut PrintfState, u32),
        flags: u32,
        width: i32,
        precision: i32,
        value: u32,
    ) -> (String, PrintfState) {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = PrintfState {
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
        unsafe { conv(&mut st, value) };
        (String::from_utf8(sink.buf).unwrap(), st)
    }

    fn x(flags: u32, width: i32, precision: i32, value: u32) -> String {
        run(convert_x, flags, width, precision, value).0
    }

    #[test]
    fn plain_values_lowercase() {
        assert_eq!(x(0, 0, 0, 0), "0");
        assert_eq!(x(0, 0, 0, 1), "1");
        assert_eq!(x(0, 0, 0, 0xdeadbeef), "deadbeef");
        assert_eq!(x(0, 0, 0, u32::MAX), "ffffffff");
    }

    #[test]
    fn plain_values_uppercase() {
        let up = |value| run(convert_X, 0, 0, 0, value).0;
        assert_eq!(up(0), "0");
        assert_eq!(up(1), "1");
        assert_eq!(up(0xdeadbeef), "DEADBEEF");
        assert_eq!(up(u32::MAX), "FFFFFFFF");
    }

    #[test]
    fn field_width_padding() {
        // Right-justified spaces.
        assert_eq!(x(0, 10, 0, 0xabc), "       abc");
        // Zero padding.
        assert_eq!(x(FLAG_ZERO_PAD, 10, 0, 0xabc), "0000000abc");
        // Left-justified trailing spaces (never zeros).
        assert_eq!(x(FLAG_LEFT_JUSTIFY, 10, 0, 0xabc), "abc       ");
        assert_eq!(x(FLAG_LEFT_JUSTIFY | FLAG_ZERO_PAD, 10, 0, 0xabc), "abc       ");
        // Width smaller than the content emits nothing extra.
        assert_eq!(x(0, 2, 0, 0xabc), "abc");
    }

    #[test]
    fn precision_zero_fills_and_clears_zero_pad() {
        assert_eq!(x(FLAG_PRECISION_GIVEN, 0, 8, 0xabc), "00000abc");
        // Precision shorter than the value is ignored.
        assert_eq!(x(FLAG_PRECISION_GIVEN, 0, 2, 0xabc), "abc");
        // Precision given: '0' flag ignored, spaces used for the width.
        let (text, st) = run(
            convert_x,
            FLAG_ZERO_PAD | FLAG_PRECISION_GIVEN,
            10,
            5,
            0xabc,
        );
        assert_eq!(text, "     00abc");
        // The original clears FLAG_ZERO_PAD in the state itself.
        assert_eq!(st.flags & FLAG_ZERO_PAD, 0);
        // "%.0x" of zero prints nothing at all.
        assert_eq!(x(FLAG_PRECISION_GIVEN, 0, 0, 0), "");
    }

    #[test]
    fn alternate_form_prefixes_nonzero() {
        assert_eq!(x(FLAG_ALTERNATE, 0, 0, 0xabc), "0xabc");
        assert_eq!(run(convert_X, FLAG_ALTERNATE, 0, 0, 0xabc).0, "0XABC");
        // Zero gets no prefix (C standard).
        assert_eq!(x(FLAG_ALTERNATE, 0, 0, 0), "0");
        // Zero padding goes between the prefix and the digits.
        assert_eq!(x(FLAG_ALTERNATE | FLAG_ZERO_PAD, 10, 0, 0xabc), "0x00000abc");
        // The prefix counts against the field width.
        assert_eq!(x(FLAG_ALTERNATE, 10, 0, 0xabc), "     0xabc");
        assert_eq!(x(FLAG_ALTERNATE | FLAG_LEFT_JUSTIFY, 10, 0, 0xabc), "0xabc     ");
    }

    #[test]
    fn length_flags_widen_unless_ll() {
        assert_eq!(x(FLAG_LEN_HH, 0, 0, 0xdeadbeef), "ef");
        assert_eq!(x(FLAG_LEN_H, 0, 0, 0xdeadbeef), "beef");
        // hh wins over h (widen_unsigned order).
        assert_eq!(x(FLAG_LEN_H | FLAG_LEN_HH, 0, 0, 0xdeadbeef), "ef");
        // ll suppresses the masking.
        assert_eq!(x(FLAG_LEN_LL | FLAG_LEN_HH, 0, 0, 0xdeadbeef), "deadbeef");
        assert_eq!(x(FLAG_LEN_LL | FLAG_LEN_H, 0, 0, u32::MAX), "ffffffff");
        // Widening happens before the `#` nonzero test: 0x100 with hh is
        // zero, so no prefix.
        assert_eq!(x(FLAG_ALTERNATE | FLAG_LEN_HH, 0, 0, 0x100), "0");
    }

    #[test]
    fn pointer_implies_precision_eight() {
        assert_eq!(run(convert_p, 0, 0, 0, 0xabc).0, "00000abc");
        assert_eq!(run(convert_p, 0, 0, 0, 0).0, "00000000");
        assert_eq!(run(convert_p, 0, 0, 0, u32::MAX).0, "ffffffff");
        // `%#p`: the original's odd 1-byte "@" prefix, even for zero.
        assert_eq!(run(convert_p, FLAG_ALTERNATE, 0, 0, 0xabc).0, "@00000abc");
        // Precision is forced into the state, like the original.
        let (_, st) = run(convert_p, 0, 0, 0, 0xabc);
        assert_eq!(st.flags & FLAG_PRECISION_GIVEN, FLAG_PRECISION_GIVEN);
        assert_eq!(st.precision, 8);
    }

    #[test]
    fn count_tracks_emitted_chars() {
        for (flags, width, precision, value) in [
            (0, 0, 0, 0xdeadbeef),
            (FLAG_ZERO_PAD, 12, 0, 0xabc),
            (FLAG_ALTERNATE | FLAG_LEFT_JUSTIFY, 12, 0, 0xabc),
            (FLAG_PRECISION_GIVEN, 0, 8, 1),
        ] {
            let (text, st) = run(convert_x, flags, width, precision, value);
            assert_eq!(st.count as usize, text.len(), "flags={flags:#x} width={width} value={value:#x}");
        }
    }
}
