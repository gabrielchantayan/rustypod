//! printf numeric output engine: the pad/prefix/digits ordering core and
//! the `%n` store (ARM ADS 1.0.1).
//!
//! Ports:
//! - `out_padded` @ 0x080322cc (288 bytes) — shared tail of every numeric
//!   converter (%d/%i/%u/%o/%x/%X, 32- and 64-bit). Emits, in order:
//!   leading space padding (right-justified, no `0` flag), the prefix
//!   string ("-", "+", " ", "0x", ...), zero padding (after the prefix so
//!   negatives come out as "-00042"), precision zeros, the digit buffer
//!   (stored least-significant digit first, emitted in reverse), and
//!   trailing spaces for `-`. Padding itself is delegated to
//!   [`pad_emit`]/[`pad_emit_zero`]; this function only orders the pieces.
//! - `store_n`    @ 0x080324d4 (60 bytes) — `%n`: stores `state.count`
//!   through the argument pointer, narrowed per the length flags
//!   (`hh` → byte, `h` → halfword, `ll` → 64-bit sign-extended, else word).
//!
//! ABI notes (recovered from the machine code, not the obvious guess):
//! - `out_padded` takes FIVE arguments — `(state, digits, num_digits,
//!   prefix, prefix_len)` — with `prefix_len` passed on the stack. All four
//!   original callers (0x0802f384, 0x0802f574, 0x0802f4b4, 0x080323ec) use
//!   this convention. The prefix is NOT read from `state.prefix`; that
//!   field is only consulted by the float converter.
//! - On entry `pad_remaining` holds the raw field width; `out_padded`
//!   subtracts the total content length (prefix + zeros + digits) itself.
//!
//! Simplifications vs. the original:
//! - `store_n`'s trailing `and r2, r2, #64` (flag 0x40 = `l`) is dead —
//!   its result is never used (plain `l` falls through to the word store,
//!   same as no modifier). Omitted.
//! - Ghidra shows putc calls through `fn_ptr & 0xfffffffc` (Thumb-bit
//!   clear); the firmware is pure ARM, so the mask is omitted.
//! - The original assumes natural alignment of the `%n` destination
//!   (strh/str/stm); so does this port.

use crate::printf_helpers::{
    pad_emit, pad_emit_zero, PrintfState, FLAG_LEN_H, FLAG_LEN_HH, FLAG_PRECISION_GIVEN,
    FLAG_ZERO_PAD,
};

/// Length modifier `ll`: argument is 64-bit. (Not shared with the
/// halfword/byte flags in `printf_helpers`, so defined here.)
pub const FLAG_LEN_LL: u32 = 0x080;

/// `out_padded` — original: `FUN_080322cc` @ 0x080322cc (288 bytes).
///
/// `digits` is the converter's digit buffer, LEAST-significant digit
/// first; it is emitted in reverse. `prefix`/`prefix_len` describe the
/// sign/base prefix string (may be empty). With FLAG_PRECISION_GIVEN the
/// `0` flag is cleared from `state.flags` (C rule: precision wins for
/// numeric conversions) and `precision` becomes the minimum digit count;
/// otherwise the minimum is 1, which is what prints "0" for a zero value
/// (empty digit buffer).
#[no_mangle]
pub unsafe extern "C" fn out_padded(
    state: *mut PrintfState,
    digits: *const u8,
    num_digits: i32,
    prefix: *const u8,
    prefix_len: i32,
) {
    // Original: tst flags,#32; ldrne precision; bicne flags,#16; moveq #1.
    let min_digits = if (*state).flags & FLAG_PRECISION_GIVEN != 0 {
        (*state).flags &= !FLAG_ZERO_PAD;
        (*state).precision
    } else {
        1
    };
    // subgt/movle: signed clamp to zero.
    let zero_fill = (min_digits - num_digits).max(0);
    (*state).pad_remaining -= zero_fill + num_digits + prefix_len;

    // Right-justified without `0`: spaces come first.
    if (*state).flags & FLAG_ZERO_PAD == 0 {
        pad_emit(state);
    }
    // Prefix always precedes zero padding, so the sign sticks to the
    // number: "-00042", never "000-42".
    let mut i = 0;
    while i < prefix_len {
        ((*state).putc)(*prefix.add(i as usize), (*state).putc_ctx);
        (*state).count += 1;
        i += 1;
    }
    // With `0` (and right-justified): zero fill between prefix and digits.
    if (*state).flags & FLAG_ZERO_PAD != 0 {
        pad_emit(state);
    }
    // Precision zeros; also the lone '0' of a zero value (min_digits == 1,
    // num_digits == 0).
    let mut zeros = zero_fill;
    while zeros > 0 {
        ((*state).putc)(b'0', (*state).putc_ctx);
        (*state).count += 1;
        zeros -= 1;
    }
    // Digit buffer is least-significant first; walk it backwards.
    let mut n = num_digits;
    while n > 0 {
        n -= 1;
        ((*state).putc)(*digits.add(n as usize), (*state).putc_ctx);
        (*state).count += 1;
    }
    // Left-justified: trailing spaces (no-op otherwise).
    pad_emit_zero(state);
}

/// `store_n` — original: `FUN_080324d4` @ 0x080324d4 (60 bytes).
///
/// `%n`: writes the number of characters emitted so far (`state.count`)
/// to `dest`, narrowed per the length flags. Test order matches the
/// original: `hh` (0x400) first, then `h` (0x100), then `ll` (0x80,
/// stored as count plus its sign extension — the original's
/// `asr r2, r0, #31; stm dest, {r0, r2}`), else a plain word.
#[no_mangle]
pub unsafe extern "C" fn store_n(state: *const PrintfState, dest: *mut u8) {
    let flags = (*state).flags;
    let count = (*state).count;
    if flags & FLAG_LEN_HH != 0 {
        *dest = count as u8;
    } else if flags & FLAG_LEN_H != 0 {
        *(dest as *mut u16) = count as u16;
    } else if flags & FLAG_LEN_LL != 0 {
        let d = dest as *mut i32;
        *d = count;
        *d.add(1) = count >> 31;
    } else {
        *(dest as *mut i32) = count;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::printf_helpers::{PutcFn, FLAG_LEFT_JUSTIFY, FLAG_ZERO_PAD};
    use core::ffi::c_void;
    use std::vec::Vec;

    struct Sink {
        buf: Vec<u8>,
    }

    unsafe extern "C" fn sink_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Sink)).buf.push(c);
    }

    fn make_state(flags: u32, width: i32, precision: i32, sink: &mut Sink) -> PrintfState {
        PrintfState {
            reserved_00: [0; 2],
            prefix: core::ptr::null(),
            reserved_0c: [0; 3],
            flags,
            putc: sink_putc as PutcFn,
            emit_str: None,
            putc_ctx: sink as *mut Sink as *mut c_void,
            reserved_28: [0; 3],
            pad_remaining: width, // raw field width, as the core leaves it
            precision,
            count: 0,
        }
    }

    /// Run out_padded; `digits_rev` is the converter buffer (LSD first),
    /// so b"24" prints as "42". Returns (output, final count, final flags).
    fn run(flags: u32, width: i32, precision: i32, digits_rev: &[u8], prefix: &[u8]) -> (Vec<u8>, i32, u32) {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = make_state(flags, width, precision, &mut sink);
        unsafe {
            out_padded(
                &mut st,
                digits_rev.as_ptr(),
                digits_rev.len() as i32,
                prefix.as_ptr(),
                prefix.len() as i32,
            );
        }
        (sink.buf, st.count, st.flags)
    }

    #[test]
    fn no_width_no_flags() {
        let (out, count, _) = run(0, 0, 0, b"24", b"");
        assert_eq!(out, b"42");
        assert_eq!(count, 2);
    }

    #[test]
    fn right_justified_spaces() {
        let (out, count, _) = run(0, 5, 0, b"24", b"");
        assert_eq!(out, b"   42");
        assert_eq!(count, 5);
    }

    #[test]
    fn left_justified_trailing_spaces() {
        let (out, count, _) = run(FLAG_LEFT_JUSTIFY, 5, 0, b"24", b"");
        assert_eq!(out, b"42   ");
        assert_eq!(count, 5);
    }

    #[test]
    fn zero_pad_positive() {
        let (out, count, _) = run(FLAG_ZERO_PAD, 5, 0, b"24", b"");
        assert_eq!(out, b"00042");
        assert_eq!(count, 5);
    }

    #[test]
    fn zero_pad_negative_signs_to_number() {
        // The assignment's headline case: -00042.
        let (out, count, _) = run(FLAG_ZERO_PAD, 6, 0, b"24", b"-");
        assert_eq!(out, b"-00042");
        assert_eq!(count, 6);
    }

    #[test]
    fn all_orderings_with_minus_prefix() {
        // Same content ("-" + "42"), width 6, one per justification mode.
        let (out, _, _) = run(0, 6, 0, b"24", b"-");
        assert_eq!(out, b"   -42"); // spaces, prefix, digits
        let (out, _, _) = run(FLAG_ZERO_PAD, 6, 0, b"24", b"-");
        assert_eq!(out, b"-00042"); // prefix, zeros, digits
        let (out, _, _) = run(FLAG_LEFT_JUSTIFY, 6, 0, b"24", b"-");
        assert_eq!(out, b"-42   "); // prefix, digits, spaces
        // `-` beats `0` for padding purposes (trailing pad is spaces).
        let (out, _, _) = run(FLAG_LEFT_JUSTIFY | FLAG_ZERO_PAD, 6, 0, b"24", b"-");
        assert_eq!(out, b"-42   ");
    }

    #[test]
    fn all_orderings_with_hex_prefix() {
        let (out, _, _) = run(0, 6, 0, b"24", b"0x");
        assert_eq!(out, b"  0x42");
        let (out, _, _) = run(FLAG_ZERO_PAD, 6, 0, b"24", b"0x");
        assert_eq!(out, b"0x0042"); // zeros after the 0x
        let (out, _, _) = run(FLAG_LEFT_JUSTIFY, 6, 0, b"24", b"0x");
        assert_eq!(out, b"0x42  ");
    }

    #[test]
    fn width_shorter_than_content_pads_nothing() {
        let (out, count, _) = run(FLAG_ZERO_PAD, 2, 0, b"24", b"-");
        assert_eq!(out, b"-42");
        assert_eq!(count, 3);
    }

    #[test]
    fn precision_adds_leading_zeros() {
        // "%8.5d" of 42: three precision zeros, three spaces.
        let (out, count, _) = run(FLAG_PRECISION_GIVEN, 8, 5, b"24", b"");
        assert_eq!(out, b"   00042");
        assert_eq!(count, 8);
    }

    #[test]
    fn precision_ignores_zero_pad_flag() {
        // C rule: '0' is ignored when a precision is given; the original
        // literally clears the bit from state.flags.
        let (out, _, flags) = run(FLAG_PRECISION_GIVEN | FLAG_ZERO_PAD, 8, 5, b"24", b"");
        assert_eq!(out, b"   00042");
        assert_eq!(flags & FLAG_ZERO_PAD, 0);
    }

    #[test]
    fn precision_with_negative() {
        // "%8.5d" of -42: pad = 8 - (1 + 3 + 2) = 2.
        let (out, count, _) = run(FLAG_PRECISION_GIVEN, 8, 5, b"24", b"-");
        assert_eq!(out, b"  -00042");
        assert_eq!(count, 8);
    }

    #[test]
    fn zero_value_prints_zero_without_precision() {
        // Empty digit buffer + no precision: min_digits = 1 emits one '0'.
        let (out, count, _) = run(0, 0, 0, b"", b"");
        assert_eq!(out, b"0");
        assert_eq!(count, 1);
        let (out, _, _) = run(0, 3, 0, b"", b"");
        assert_eq!(out, b"  0");
        let (out, _, _) = run(FLAG_ZERO_PAD, 3, 0, b"", b"");
        assert_eq!(out, b"000");
    }

    #[test]
    fn zero_value_with_zero_precision_prints_nothing() {
        // "%.0d" of 0 is the empty string.
        let (out, count, _) = run(FLAG_PRECISION_GIVEN, 0, 0, b"", b"");
        assert!(out.is_empty());
        assert_eq!(count, 0);
        // Only the width remains: "   ".
        let (out, _, _) = run(FLAG_PRECISION_GIVEN, 3, 0, b"", b"");
        assert_eq!(out, b"   ");
    }

    #[test]
    fn multi_digit_reverse_buffer() {
        // 12345 stored LSD-first.
        let (out, count, _) = run(0, 0, 0, b"54321", b"");
        assert_eq!(out, b"12345");
        assert_eq!(count, 5);
    }

    #[test]
    fn empty_prefix_zero_len_never_dereferences() {
        // prefix_len == 0 with a dangling-ish pointer must emit nothing.
        let (out, _, _) = run(0, 0, 0, b"24", b"");
        assert_eq!(out, b"42");
    }

    fn n_state(flags: u32, count: i32) -> PrintfState {
        PrintfState {
            reserved_00: [0; 2],
            prefix: core::ptr::null(),
            reserved_0c: [0; 3],
            flags,
            putc: sink_putc as PutcFn,
            emit_str: None,
            putc_ctx: core::ptr::null_mut(),
            reserved_28: [0; 3],
            pad_remaining: 0,
            precision: 0,
            count,
        }
    }

    #[test]
    fn store_n_default_word() {
        let st = n_state(0, 0x12345678);
        let mut dest: i32 = 0;
        unsafe { store_n(&st, &mut dest as *mut i32 as *mut u8) };
        assert_eq!(dest, 0x12345678);
    }

    #[test]
    fn store_n_hh_byte() {
        let st = n_state(FLAG_LEN_HH, 300);
        let mut dest: u8 = 0;
        unsafe { store_n(&st, &mut dest) };
        assert_eq!(dest, 44); // 300 truncated to 8 bits
        let st = n_state(FLAG_LEN_HH, -1);
        unsafe { store_n(&st, &mut dest) };
        assert_eq!(dest, 0xff);
    }

    #[test]
    fn store_n_h_halfword() {
        let st = n_state(FLAG_LEN_H, 0xdeadbeefu32 as i32);
        let mut dest: u16 = 0;
        unsafe { store_n(&st, &mut dest as *mut u16 as *mut u8) };
        assert_eq!(dest, 0xbeef);
    }

    #[test]
    fn store_n_ll_sign_extended_pair() {
        // Positive count: high word is 0.
        let st = n_state(FLAG_LEN_LL, 0x12345678);
        let mut dest: [i32; 2] = [0x55; 2];
        unsafe { store_n(&st, dest.as_mut_ptr() as *mut u8) };
        assert_eq!(dest, [0x12345678, 0]);
        // Negative count: high word is the sign extension.
        let st = n_state(FLAG_LEN_LL, -5);
        unsafe { store_n(&st, dest.as_mut_ptr() as *mut u8) };
        assert_eq!(dest, [-5, -1]);
    }

    #[test]
    fn store_n_hh_wins_over_h() {
        // Original tests 0x400 before 0x100.
        let st = n_state(FLAG_LEN_HH | FLAG_LEN_H, 0x1ff);
        let mut dest: u8 = 0;
        unsafe { store_n(&st, &mut dest) };
        assert_eq!(dest, 0xff);
    }
}
