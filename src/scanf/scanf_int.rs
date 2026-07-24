//! scanf integer converter for the stock firmware's scanf core
//! (ARM ADS 1.0.1): the shared `%d`/`%i`/`%u`/`%x`/`%o` worker.
//!
//! Port:
//! - `scanf_convert_int` — original: `FUN_0802f9c4` @ 0x0802f9c4
//!   (472 bytes). NOTE: the batch assignment cited 0x08035d50; that
//!   function is a CORDIC-style float helper (tables @ 0x08036008/0x0c,
//!   calls into the float mult @ 0x083eca20), not a scanf converter.
//!   The real converter was located by disassembling the `_scanf` format
//!   engine body @ 0x0803484c: every integer directive (`%d`/`%i`/`%o`/
//!   `%u`/`%x`) tail-dispatches to `bl 0x0802f9c4` with the base in r2.
//!
//! Algorithm (recovered from the machine code, cross-checked against the
//! Ghidra decompile):
//! 1. Skip leading whitespace via `ctype`, reading through `conv.getc`;
//!    `consumed` counts every net character read (starts at -1, bumped
//!    before each getc). EOF (-1) before any non-space char returns -1.
//! 2. If `width > 0` and [`SCANF_FLAG_SIGN_OK`] is set, an optional
//!    `+`/`-` is consumed (`-` sets the internal NEGATIVE bit).
//! 3. A leading `0` counts as a digit (DIGITS_SEEN) and, when followed
//!    by `x`/`X` with base 0 or 16, switches to base 16 and CLEARS
//!    DIGITS_SEEN (a bare `"0x"` is a matching failure, not the value 0).
//!    Base 0 (`%i`) otherwise resolves to 8 after a leading `0`, else 10.
//! 4. Digit loop: while `width > 0` and `digit_value(c, base) >= 0`,
//!    accumulate `value = base*value + digit` (the original's
//!    `mla r8, r9, r8, r0` — plain mod-2^32 wraparound, NO saturation).
//! 5. One `ungetc` pushes back the terminating character (harmless when
//!    it fails on the sticky-EOF path). No digits seen returns **-2**
//!    (the engine distinguishes it from the -1 EOF return); `*`
//!    suppression returns the consumed count without storing; otherwise
//!    the value is negated when SIGN_OK+NEGATIVE, stored through the
//!    next `ap` slot (`ap` advances by 4 bytes) narrowed per the length
//!    flags, and the consumed count is returned.
//!
//! Register usage of the original: r0 = unused (the engine passes -2;
//!    never read), r1 = `input` (full [`ScanfState`], the getc/ungetc
//!    argument), r2 = base (0 = `%i` auto-detect), r3 = `conv`
//!    ([`ScanfConvState`]: flags @ 4, width @ 8, getc @ 0x18, ungetc @
//!    0x1c, ctype @ 0x20, ap @ 0). Result in r0: consumed count >= 0,
//!    -1 on EOF before the field, -2 on a matching failure (no digits).
//!
//! Simplifications / deviations vs. the original:
//! - NO 64-bit (`ll`) path exists in this build, so none is ported: the
//!   engine's `%ll` call sites are literal `nop`s (0x08034bb0 etc.) and
//!   this converter neither accumulates 64-bit nor tests the `ll` flag
//!   in its store (byte/halfword/word only). Consequently there is no
//!   64-bit arithmetic at all — no `__aeabi_*` helper exposure.
//! - The digit-value helper is a private copy mirroring `_chval`
//!   @ 0x08032fec (publicly ported in `chval.rs`, not imported here to
//!   stay within the batch's import rules). It takes the full 32-bit
//!   character word like the original call (EOF's -1 folds to -1 the
//!   same way the raw register did).
//! - `store_n` (printf_out.rs @ 0x080324d4) is NOT reused: it stores a
//!   `PrintfState.count` under the PRINTF flag layout (hh=0x400, h=0x100,
//!   ll=0x80), while scanf uses hh=0x800, h=0x008 and stores the parsed
//!   value with sign applied. The store is inlined instead.
//! - Ghidra shows getc/ungetc/ctype calls through `fn_ptr & 0xfffffffc`
//!   (Thumb-bit clear); the firmware is pure ARM, so the mask is omitted.
//! - The original keeps the updated flags in a register and never writes
//!   `conv.flags` back; neither does this port (only `conv.ap` changes).
//! - `conv.getc/ungetc/ctype` are `Option`s in the shared struct; the
//!   original blindly calls them, so this port uses `unwrap_unchecked`.

use crate::scanf_helpers::{ScanfConvState, ScanfState};
use core::ffi::c_void;

/// `*` — assignment suppression: consume and convert, but do not store
/// and do not count the conversion (the engine tests this too).
pub const SCANF_FLAG_SUPPRESS: u32 = 0x001;
/// `ll` length modifier. Present in the flag word, but this build has no
/// 64-bit scanf path (see module docs) — carried for completeness only.
pub const SCANF_FLAG_LL: u32 = 0x002;
/// `h` length modifier: store a halfword.
pub const SCANF_FLAG_H: u32 = 0x008;
/// Set by the engine for every integer directive: a sign may be consumed
/// and the stored value is negated when [`SCANF_FLAG_NEGATIVE`] is set.
pub const SCANF_FLAG_SIGN_OK: u32 = 0x040;
/// Internal (converter-local): at least one digit was consumed. Cleared
/// on entry (with NEGATIVE, `bic r4, r4, #0x600`) and NOT written back.
pub const SCANF_FLAG_DIGITS_SEEN: u32 = 0x200;
/// Internal (converter-local): a `-` sign was consumed.
pub const SCANF_FLAG_NEGATIVE: u32 = 0x400;
/// `hh` length modifier: store a byte.
pub const SCANF_FLAG_HH: u32 = 0x800;

/// `scanf_convert_int` — original: `FUN_0802f9c4` @ 0x0802f9c4 (472 bytes).
///
/// See the module docs for the full algorithm and ABI. `base` is 10 for
/// `%d`/`%u`, 8 for `%o`, 16 for `%x`, 0 for `%i` (auto-detect from the
/// `0`/`0x` prefixes). Returns the number of input characters consumed
/// (>= 0), -1 when EOF hit before the field started, or -2 when no valid
/// digits were present (matching failure).
#[no_mangle]
pub unsafe extern "C" fn scanf_convert_int(
    unused_r0: i32,
    input: *mut ScanfState,
    base: i32,
    conv: *mut ScanfConvState,
) -> i32 {
    let _ = unused_r0; // never read by the original (engine passes -2)
    let conv = &mut *conv;
    let getc = conv.getc.unwrap_unchecked();
    let ungetc = conv.ungetc.unwrap_unchecked();
    let ctype = conv.ctype.unwrap_unchecked();

    // Original keeps flags in r4 for the whole function and clears the
    // two internal bits up front; conv.flags is never written back.
    let mut flags = conv.flags & !(SCANF_FLAG_DIGITS_SEEN | SCANF_FLAG_NEGATIVE);
    let mut width = conv.width;
    let mut base = base;
    let mut consumed: i32 = -1;
    let mut value: u32 = 0;

    // Skip leading whitespace (ctype(c) != 0), counting every char read.
    let mut c: i32;
    loop {
        consumed = consumed.wrapping_add(1);
        c = getc(input);
        if ctype(c) == 0 {
            break;
        }
    }
    if c == -1 {
        return -1; // EOF before the field even started
    }

    if width > 0 {
        // Optional sign, only when the engine marked it acceptable.
        if flags & SCANF_FLAG_SIGN_OK != 0 && (c == b'+' as i32 || c == b'-' as i32) {
            if c == b'-' as i32 {
                flags |= SCANF_FLAG_NEGATIVE;
            }
            consumed = consumed.wrapping_add(1);
            c = getc(input);
            width -= 1;
        }
        if width > 0 {
            if c == b'0' as i32 {
                // A leading '0' is itself a valid digit...
                flags |= SCANF_FLAG_DIGITS_SEEN;
                consumed = consumed.wrapping_add(1);
                width -= 1;
                c = getc(input);
                if width > 0 && (c == b'x' as i32 || c == b'X' as i32) && (base == 0 || base == 16)
                {
                    // ...unless it introduces a hex prefix: bare "0x"
                    // is a matching failure, not the value 0.
                    flags &= !SCANF_FLAG_DIGITS_SEEN;
                    consumed = consumed.wrapping_add(1);
                    width -= 1;
                    c = getc(input);
                    base = 16;
                } else if base == 0 {
                    base = 8;
                }
            } else if base == 0 {
                base = 10;
            }
        } else if base == 0 {
            base = 10;
        }
    } else if base == 0 {
        base = 10;
    }

    // Digit accumulation: mla r8, r9, r8, r0 — wraps mod 2^32, the
    // original performs NO overflow saturation.
    while width > 0 {
        let digit = digit_value(c, base as u32);
        if digit < 0 {
            break;
        }
        value = (base as u32).wrapping_mul(value).wrapping_add(digit as u32);
        flags |= SCANF_FLAG_DIGITS_SEEN;
        consumed = consumed.wrapping_add(1);
        width -= 1;
        c = getc(input);
    }
    // Push back the field terminator. Failure (sticky EOF, start of
    // input) is fine — the original ignores ungetc's result too.
    ungetc(input);

    if flags & SCANF_FLAG_DIGITS_SEEN == 0 {
        return -2; // matching failure (original: mvn r0, #1)
    }
    if flags & SCANF_FLAG_SUPPRESS != 0 {
        return consumed; // '*' — no store, conversion not counted
    }

    // Store through the next varargs slot; ap advances by 4 bytes
    // (AAPCS va_list is a byte pointer into the stack).
    let slot = conv.ap as *const *mut u8;
    let dest = *slot;
    conv.ap = (conv.ap as *mut u8).add(4) as *mut c_void;

    if flags & SCANF_FLAG_SIGN_OK != 0 && flags & SCANF_FLAG_NEGATIVE != 0 {
        value = value.wrapping_neg();
    }
    if flags & SCANF_FLAG_HH != 0 {
        *dest = value as u8;
    } else if flags & SCANF_FLAG_H != 0 {
        *(dest as *mut u16) = value as u16;
    } else {
        // No ll case: this build's engine NOPs out the %ll call sites.
        *(dest as *mut u32) = value;
    }
    consumed
}

/// Digit valuation, mirroring `_chval` @ 0x08032fec (32 bytes) as called
/// here with the full 32-bit character word: `cmp #0x3a; subcc #0x30;
/// bic #0x20; cmp #0x41; subcs #0x37; cmp base; mvncs #-1`. Characters
/// below `'0'` and EOF's -1 wrap huge after the subtracts and are
/// rejected by the final unsigned base compare, as in the original.
fn digit_value(c: i32, base: u32) -> i32 {
    let mut value = c as u32;
    if value < 0x3a {
        value = value.wrapping_sub(0x30);
    }
    let upper = value & !0x20; // fold lowercase to uppercase
    if upper >= 0x41 {
        value = upper.wrapping_sub(0x37);
    }
    if value >= base { -1 } else { value as i32 }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::scanf_helpers::{string_getc, string_ungetc};

    /// Whitespace test standing in for the original's `FUN_082d7340`:
    /// 1 for the C whitespace set, 0 otherwise (and 0 for EOF's -1).
    unsafe extern "C" fn test_ctype(c: i32) -> i32 {
        match c {
            0x20 | 0x09..=0x0d => 1,
            _ => 0,
        }
    }

    /// Builds the string-input state + conv state pair the veneers build,
    /// with `ap` pointed at a two-slot varargs buffer holding `dest`.
    struct Fixture {
        input: ScanfState,
        conv: ScanfConvState,
        args: [*mut u8; 2],
    }

    fn fixture(text: &[u8], flags: u32, width: i32, dest: *mut u8) -> Fixture {
        Fixture {
            input: ScanfState {
                ptr: text.as_ptr(),
                count: -1,
                base: text.as_ptr(),
                eof: 0,
                ap: core::ptr::null_mut(),
                flags: 0,
                width: 0,
                fmt_cursor: core::ptr::null(),
                scanset_flag: 0,
                fmt_getc: None,
                getc: None,
                ungetc: None,
                ctype: None,
            },
            conv: ScanfConvState {
                ap: core::ptr::null_mut(),
                flags,
                width,
                fmt_cursor: core::ptr::null(),
                scanset_flag: 0,
                fmt_getc: None,
                getc: Some(string_getc),
                ungetc: Some(string_ungetc),
                ctype: Some(test_ctype),
            },
            args: [dest, core::ptr::null_mut()],
        }
    }

    /// Runs the converter over `text`; returns (ret, value stored as u32,
    /// bytes ap advanced by — always 4 when a store happened).
    fn run(text: &[u8], flags: u32, width: i32, base: i32) -> (i32, u32, Fixture) {
        let mut stored: u32 = 0xDEAD_BEEF;
        let mut f = fixture(text, flags, width, &mut stored as *mut u32 as *mut u8);
        f.conv.ap = f.args.as_mut_ptr() as *mut c_void;
        let ap_before = f.conv.ap as usize;
        let ret = unsafe { scanf_convert_int(-2, &mut f.input, base, &mut f.conv) };
        let advanced = f.conv.ap as usize - ap_before;
        assert!(advanced == 0 || advanced == 4, "ap advances by 0 or 4");
        (ret, stored, f)
    }

    /// Byte/halfword variants need their own dest; also returns the ap
    /// displacement so suppression can be checked.
    fn run_into(
        text: &[u8],
        flags: u32,
        width: i32,
        base: i32,
        dest: *mut u8,
    ) -> (i32, usize, ScanfState, ScanfConvState) {
        let mut f = fixture(text, flags, width, dest);
        f.conv.ap = f.args.as_mut_ptr() as *mut c_void;
        let ap_before = f.conv.ap as usize;
        let ret = unsafe { scanf_convert_int(-2, &mut f.input, base, &mut f.conv) };
        (ret, f.conv.ap as usize - ap_before, f.input, f.conv)
    }

    const SIGNED: u32 = SCANF_FLAG_SIGN_OK;
    const W: i32 = 100; // generous width

    #[test]
    fn decimal_basic_stops_at_terminator() {
        let (ret, value, f) = run(b"123;rest\0", SIGNED, W, 10);
        assert_eq!(ret, 3);
        assert_eq!(value, 123);
        // Terminator was pushed back: the next read sees ';' again.
        let mut input = f.input;
        assert_eq!(unsafe { string_getc(&mut input) }, b';' as i32);
    }

    #[test]
    fn whitespace_is_skipped_and_counted() {
        let (ret, value, _) = run(b"  \t42x\0", SIGNED, W, 10);
        assert_eq!(value, 42);
        // 3 whitespace + 2 digits = 5 net characters.
        assert_eq!(ret, 5);
    }

    #[test]
    fn hex_prefix_with_base16() {
        let (ret, value, _) = run(b"0x1F!\0", SIGNED, W, 16);
        assert_eq!(ret, 4);
        assert_eq!(value, 0x1F);
    }

    #[test]
    fn hex_without_prefix_base16() {
        let (ret, value, _) = run(b"ff,\0", SIGNED, W, 16);
        assert_eq!(ret, 2);
        assert_eq!(value, 255);
    }

    #[test]
    fn hex_prefix_rejected_for_explicit_decimal() {
        // "%d" on "0x10": the '0' is the whole field; 'x' is pushed back.
        let (ret, value, f) = run(b"0x10\0", SIGNED, W, 10);
        assert_eq!(ret, 1);
        assert_eq!(value, 0);
        let mut input = f.input;
        assert_eq!(unsafe { string_getc(&mut input) }, b'x' as i32);
    }

    #[test]
    fn base0_auto_detection() {
        // "%i": 0x -> hex, 0 -> octal, else decimal.
        let (ret, value, _) = run(b"0x1a\0", SIGNED, W, 0);
        assert_eq!((ret, value), (4, 26));
        let (ret, value, _) = run(b"0XAB\0", SIGNED, W, 0);
        assert_eq!((ret, value), (4, 0xAB));
        let (ret, value, _) = run(b"017\0", SIGNED, W, 0);
        assert_eq!((ret, value), (3, 15));
        let (ret, value, _) = run(b"42\0", SIGNED, W, 0);
        assert_eq!((ret, value), (2, 42));
        let (ret, value, _) = run(b"0\0", SIGNED, W, 0);
        assert_eq!((ret, value), (1, 0));
    }

    #[test]
    fn octal_explicit_base() {
        // '8' is not an octal digit: field ends after "17".
        let (ret, value, f) = run(b"178\0", SIGNED, W, 8);
        assert_eq!((ret, value), (2, 15));
        let mut input = f.input;
        assert_eq!(unsafe { string_getc(&mut input) }, b'8' as i32);
    }

    #[test]
    fn signs() {
        let (ret, value, _) = run(b"-42x\0", SIGNED, W, 10);
        assert_eq!(ret, 3);
        assert_eq!(value, -42i32 as u32);
        let (ret, value, _) = run(b"+7\0", SIGNED, W, 10);
        assert_eq!((ret, value), (2, 7));
        let (ret, value, _) = run(b"-0x10\0", SIGNED, W, 0);
        assert_eq!(ret, 5);
        assert_eq!(value, -16i32 as u32);
    }

    #[test]
    fn sign_ignored_without_sign_ok_flag() {
        // Flag 0x40 clear: '-' is not consumed as a sign, so no digits.
        let (ret, _, _) = run(b"-5\0", 0, W, 10);
        assert_eq!(ret, -2);
    }

    #[test]
    fn suppression_consumes_but_does_not_store() {
        let mut stored: u32 = 0xCAFE_BABE;
        let (ret, ap_advanced, _, _) = run_into(
            b"99\0",
            SIGNED | SCANF_FLAG_SUPPRESS,
            W,
            10,
            &mut stored as *mut u32 as *mut u8,
        );
        assert_eq!(ret, 2);
        assert_eq!(stored, 0xCAFE_BABE, "'*' must not store");
        assert_eq!(ap_advanced, 0, "'*' must not advance ap");
    }

    #[test]
    fn stores_narrow_per_length_flags() {
        // hh: byte store.
        let mut dest8: u8 = 0;
        let (ret, ap_advanced, _, _) = run_into(
            b"300\0",
            SIGNED | SCANF_FLAG_HH,
            W,
            10,
            &mut dest8 as *mut u8,
        );
        assert_eq!(ret, 3);
        assert_eq!(ap_advanced, 4);
        assert_eq!(dest8, 44); // 300 truncated
        // h: halfword store.
        let mut dest16: u16 = 0;
        let (ret, _, _, _) = run_into(
            b"74565\0", // 0x12345
            SIGNED | SCANF_FLAG_H,
            W,
            10,
            &mut dest16 as *mut u16 as *mut u8,
        );
        assert_eq!(ret, 5);
        assert_eq!(dest16, 0x2345);
        // default: word store.
        let mut dest32: u32 = 0;
        let (ret, _, _, _) = run_into(
            b"74565\0",
            SIGNED,
            W,
            10,
            &mut dest32 as *mut u32 as *mut u8,
        );
        assert_eq!(ret, 5);
        assert_eq!(dest32, 0x12345);
        // negative byte store through hh.
        let mut neg8: u8 = 0;
        run_into(
            b"-1\0",
            SIGNED | SCANF_FLAG_HH,
            W,
            10,
            &mut neg8 as *mut u8,
        );
        assert_eq!(neg8, 0xFF);
    }

    #[test]
    fn overflow_wraps_without_saturation() {
        // mla r8, r9, r8, r0 — mod 2^32, no clamping in the original.
        let (ret, value, _) = run(b"4294967297\0", SIGNED, W, 10); // 2^32 + 1
        assert_eq!(ret, 10);
        assert_eq!(value, 1);
        let (_, value, _) = run(b"8589934593\0", SIGNED, W, 10); // 2*2^32 + 1
        assert_eq!(value, 1);
        // Negation wraps the same way: -(2^32) == 0.
        let (_, value, _) = run(b"-4294967296\0", SIGNED, W, 10);
        assert_eq!(value, 0);
    }

    #[test]
    fn eof_mid_field_keeps_digits() {
        // Sticky EOF makes the final ungetc fail; the digits still count.
        let (ret, value, f) = run(b"42\0", SIGNED, W, 10);
        assert_eq!(ret, 2);
        assert_eq!(value, 42);
        assert_eq!(f.input.eof, 1);
    }

    #[test]
    fn eof_before_field_returns_minus1() {
        let (ret, _, _) = run(b"\0", SIGNED, W, 10);
        assert_eq!(ret, -1);
        let (ret, _, _) = run(b"  \0", SIGNED, W, 10);
        assert_eq!(ret, -1);
    }

    #[test]
    fn matching_failures_return_minus2() {
        // Non-digit first character.
        let (ret, _, _) = run(b"x\0", SIGNED, W, 10);
        assert_eq!(ret, -2);
        // Bare "0x" is NOT the value 0 (digits-seen cleared by the prefix).
        let (ret, _, _) = run(b"0x\0", SIGNED, W, 0);
        assert_eq!(ret, -2);
        let (ret, _, _) = run(b"0xg\0", SIGNED, W, 0);
        assert_eq!(ret, -2);
        // Bare signs.
        let (ret, _, _) = run(b"-\0", SIGNED, W, 10);
        assert_eq!(ret, -2);
        let (ret, _, _) = run(b"+\0", SIGNED, W, 10);
        assert_eq!(ret, -2);
    }

    #[test]
    fn width_limits_the_field() {
        // "%3d": stops after 3 digits, pushes back the 4th.
        let (ret, value, f) = run(b"12345\0", SIGNED, 3, 10);
        assert_eq!((ret, value), (3, 123));
        let mut input = f.input;
        assert_eq!(unsafe { string_getc(&mut input) }, b'4' as i32);

        // Width 1 on "0" (%i): the '0' is the field; base resolves to 8
        // but no further reads happen.
        let (ret, value, _) = run(b"0\0", SIGNED, 1, 0);
        assert_eq!((ret, value), (1, 0));

        // Width 2 on "0x1" (%i): the prefix eats the whole width, the '1'
        // is pushed back and digits-seen is clear -> matching failure.
        let (ret, _, f) = run(b"0x1\0", SIGNED, 2, 0);
        assert_eq!(ret, -2);
        let mut input = f.input;
        assert_eq!(unsafe { string_getc(&mut input) }, b'1' as i32);

        // Width 1 with a sign: the sign eats the whole width -> failure.
        let (ret, _, _) = run(b"-5\0", SIGNED, 1, 10);
        assert_eq!(ret, -2);

        // Width 0: no field at all, but the terminator is still pushed back.
        let (ret, _, _) = run(b"5\0", SIGNED, 0, 10);
        assert_eq!(ret, -2);
    }

    #[test]
    fn conv_flags_and_width_are_not_written_back() {
        let mut stored: u32 = 0;
        let flags = SIGNED | SCANF_FLAG_LL; // ll bit present: still a word store here
        let (ret, _, _, conv) = run_into(
            b"-7\0",
            flags,
            W,
            10,
            &mut stored as *mut u32 as *mut u8,
        );
        assert_eq!(ret, 2);
        assert_eq!(stored, -7i32 as u32, "ll flag has no 64-bit store in this build");
        assert_eq!(conv.flags, flags, "internal bits stay register-local");
        assert_eq!(conv.width, W);
    }

    #[test]
    fn ap_advances_one_word_per_store() {
        let mut a: u32 = 0;
        let mut f = fixture(b"1\0", SIGNED, W, &mut a as *mut u32 as *mut u8);
        f.conv.ap = f.args.as_mut_ptr() as *mut c_void;
        let before = f.conv.ap as usize;
        unsafe { scanf_convert_int(-2, &mut f.input, 10, &mut f.conv) };
        assert_eq!(f.conv.ap as usize - before, 4);
    }

    #[test]
    fn digit_value_matches_reference_all_bytes() {
        fn reference(c: i32, base: u32) -> i32 {
            let v = match c as u8 {
                b'0'..=b'9' => (c as u8 - b'0') as i32,
                b'a'..=b'z' => (c as u8 - b'a') as i32 + 10,
                b'A'..=b'Z' => (c as u8 - b'A') as i32 + 10,
                _ => -1,
            };
            if v < 0 || v as u32 >= base { -1 } else { v }
        }
        for c in 0..=255i32 {
            for base in [2u32, 8, 10, 16, 36] {
                assert_eq!(digit_value(c, base), reference(c, base), "c={c} base={base}");
            }
        }
        assert_eq!(digit_value(-1, 10), -1, "EOF folds to -1");
    }
}
