//! printf `%o` octal converter — port of `FUN_080323ec` @ 0x080323ec
//! (224 bytes), ARM ADS 1.0.1 build.
//!
//! Original algorithm:
//! 1. Unless FLAG_LEN_LL (`ll`) is set, re-widen the argument through
//!    `widen_unsigned` (masks to 8/16 bits for `hh`/`h`).
//! 2. `#` alternate form: when set, and either a precision was given or the
//!    value is nonzero, select the prefix string "0" (@ 0x080324d0; the
//!    default empty prefix "" sits @ 0x080324cc) and decrement `precision`
//!    by one — the prefix '0' counts toward the precision.
//! 3. Extract octal digits least-significant first into a 32-byte stack
//!    buffer. The original walks a 64-bit value with a funnel shift
//!    (`lo = lo>>3 | hi<<29; hi >>= 3`) — three bits per digit, no division.
//! 4. Tail-call the shared integer emitter @ 0x080322cc with
//!    (state, buffer, digit_count, prefix, prefix_len); it applies
//!    precision zero-fill, field-width padding (spaces before, zeros after
//!    the prefix, trailing spaces when left-justified) and bumps `count`.
//!
//! Simplifications vs. the original:
//! - The original takes a 64-bit value in r2/r3 (AAPCS even-register pair,
//!   r1 skipped); FLAG_LEN_LL (0x80) selects that pair untouched, otherwise
//!   the widened low word with hi = 0. This port takes `value: u32`, so the
//!   high word is always zero: with FLAG_LEN_LL the low word passes through
//!   unmasked, matching the original's low-word behavior exactly.
//! - The 64-bit funnel shift collapses to a plain `>>= 3` on the u32 value.
//!   Digit extraction is identical (the hi word only ever fed in zeros for
//!   32-bit values), so the emitted text is unchanged.
//! - The emitter @ 0x080322cc is ported separately (src/printf_out.rs) and
//!   may not be imported here; an equivalent private copy (`emit_number`)
//!   is inlined so this module is self-contained and host-testable. The
//!   logic is instruction-faithful: precision clears FLAG_ZERO_PAD,
//!   `pad_remaining` is charged `zero_run + digits + prefix` up front,
//!   zero padding is emitted between prefix and digits.
//! - Ghidra shows putc calls through `fn_ptr & 0xfffffffc` (Thumb-bit
//!   clear); the firmware is pure ARM, so the mask is omitted (same as
//!   src/printf_helpers.rs).

use crate::printf_helpers::{
    pad_emit, pad_emit_zero, widen_unsigned, PrintfState, FLAG_PRECISION_GIVEN, FLAG_ZERO_PAD,
};

/// Format flag: `#` — alternate form. For `%o` this forces a leading '0'.
/// Not part of the shared set in printf_helpers (only the octal converter
/// and the hex converter consume it).
const FLAG_ALTERNATE: u32 = 0x008;
/// Length modifier `ll`: the original reads a 64-bit argument and skips
/// `widen_unsigned`. With this port's u32 signature it only suppresses the
/// `hh`/`h` masking (see module header).
const FLAG_LEN_LL: u32 = 0x080;

/// `convert_o` — original: `FUN_080323ec` @ 0x080323ec (224 bytes).
///
/// Formats `value` as octal into the state's putc sink, honoring the `#`,
/// `0`, `-`, `hh`/`h` flags plus field width (`pad_remaining`, pre-loaded
/// by the printf core) and `precision`.
#[no_mangle]
pub unsafe extern "C" fn convert_o(state: *mut PrintfState, mut value: u32) {
    if (*state).flags & FLAG_LEN_LL == 0 {
        value = widen_unsigned(value, state);
    }

    // `#`: prefix "0" unless the value is zero and no precision was given
    // (a bare "%#o" of 0 prints "0", not "00"). The prefix consumes one
    // unit of precision.
    let mut prefix: &[u8] = b"";
    if (*state).flags & FLAG_ALTERNATE != 0
        && ((*state).flags & FLAG_PRECISION_GIVEN != 0 || value != 0)
    {
        prefix = b"0";
        (*state).precision -= 1;
    }

    // Octal digits, least-significant first (original: 3-bit funnel shift).
    let mut digits = [0u8; 32];
    let mut ndigits = 0;
    let mut remaining = value;
    while remaining != 0 {
        digits[ndigits] = b'0' + (remaining & 7) as u8;
        remaining >>= 3;
        ndigits += 1;
    }

    emit_number(state, &digits[..ndigits], prefix);
}

/// Private inline of the shared integer emitter @ 0x080322cc
/// (`FUN_080322cc`), see the module header for why it is duplicated here.
///
/// `digits` are least-significant first; they are emitted in reverse.
/// Emission order: space padding, prefix, zero padding (FLAG_ZERO_PAD),
/// precision zero-fill, digits, trailing spaces (left-justified).
unsafe fn emit_number(state: *mut PrintfState, digits: &[u8], prefix: &[u8]) {
    // With an explicit precision, zero-padding is suppressed (C99) — the
    // original clears FLAG_ZERO_PAD so pad_emit below fills with spaces.
    let min_digits = if (*state).flags & FLAG_PRECISION_GIVEN == 0 {
        1
    } else {
        (*state).flags &= !FLAG_ZERO_PAD;
        (*state).precision
    };
    let zero_run = (min_digits - digits.len() as i32).max(0);

    (*state).pad_remaining -= zero_run + digits.len() as i32 + prefix.len() as i32;

    if (*state).flags & FLAG_ZERO_PAD == 0 {
        pad_emit(state);
    }
    for &c in prefix {
        ((*state).putc)(c, (*state).putc_ctx);
        (*state).count += 1;
    }
    if (*state).flags & FLAG_ZERO_PAD != 0 {
        pad_emit(state);
    }
    for _ in 0..zero_run {
        ((*state).putc)(b'0', (*state).putc_ctx);
        (*state).count += 1;
    }
    for &c in digits.iter().rev() {
        ((*state).putc)(c, (*state).putc_ctx);
        (*state).count += 1;
    }
    pad_emit_zero(state);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::printf_helpers::{FLAG_LEFT_JUSTIFY, FLAG_LEN_H, FLAG_LEN_HH};
    use core::ffi::c_void;
    use std::vec::Vec;

    /// Recording sink mirroring the one in printf_helpers tests.
    struct Sink {
        buf: Vec<u8>,
    }

    unsafe extern "C" fn sink_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Sink)).buf.push(c);
    }

    /// Build a state with the printf core's pre-conditions: `pad_remaining`
    /// pre-loaded with the field width, `precision` valid when
    /// FLAG_PRECISION_GIVEN is set.
    fn state(flags: u32, width: i32, precision: i32, sink: &mut Sink) -> PrintfState {
        PrintfState {
            reserved_00: [0; 2],
            prefix: core::ptr::null(),
            reserved_0c: [0; 3],
            flags,
            putc: sink_putc,
            emit_str: None,
            putc_ctx: sink as *mut Sink as *mut c_void,
            reserved_28: [0; 3],
            pad_remaining: width,
            precision,
            count: 0,
        }
    }

    /// Run convert_o and return (output text, final count).
    fn convert(flags: u32, width: i32, precision: i32, value: u32) -> (std::string::String, i32) {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(flags, width, precision, &mut sink);
        unsafe { convert_o(&mut st, value) };
        (
            std::string::String::from_utf8(sink.buf).unwrap(),
            st.count,
        )
    }

    const P: u32 = FLAG_PRECISION_GIVEN;
    const Z: u32 = FLAG_ZERO_PAD;
    const L: u32 = FLAG_LEFT_JUSTIFY;
    const A: u32 = FLAG_ALTERNATE;

    #[test]
    fn plain_values() {
        assert_eq!(convert(0, 0, 0, 0).0, "0");
        assert_eq!(convert(0, 0, 0, 7).0, "7");
        assert_eq!(convert(0, 0, 0, 8).0, "10");
        assert_eq!(convert(0, 0, 0, 64).0, "100");
        assert_eq!(convert(0, 0, 0, 0o777).0, "777");
        assert_eq!(convert(0, 0, 0, u32::MAX).0, "37777777777");
        // count tracks emitted characters.
        assert_eq!(convert(0, 0, 0, u32::MAX).1, 11);
    }

    #[test]
    fn alternate_form_prefix() {
        // '#' forces a leading 0 for nonzero values.
        assert_eq!(convert(A, 0, 0, 8).0, "010");
        assert_eq!(convert(A, 0, 0, 64).0, "0100");
        // ... but not for zero without a precision.
        assert_eq!(convert(A, 0, 0, 0).0, "0");
        // With an explicit precision the prefix always applies.
        assert_eq!(convert(A | P, 0, 0, 0).0, "0");
        // The prefix counts toward the precision: "%#.5o" of 8.
        assert_eq!(convert(A | P, 0, 5, 8).0, "00010");
    }

    #[test]
    fn precision_zero_fill() {
        // "%.5o" of 64: zero-fill to 5 digits.
        assert_eq!(convert(P, 0, 5, 64).0, "00100");
        // "%.0o" of 0 prints nothing at all.
        assert_eq!(convert(P, 0, 0, 0).0, "");
        // Precision already satisfied: no extra zeros.
        assert_eq!(convert(P, 0, 2, 64).0, "100");
        // Precision suppresses the '0' flag: "%08.5o" of 64 pads with spaces.
        assert_eq!(convert(P | Z, 8, 5, 64).0, "   00100");
    }

    #[test]
    fn field_width_padding() {
        // Right-justified spaces: "%8o" of 64.
        assert_eq!(convert(0, 8, 0, 64).0, "     100");
        // Zero pad: "%08o" of 64.
        assert_eq!(convert(Z, 8, 0, 64).0, "00000100");
        // Zero pad goes after the prefix: "%#08o" of 8.
        assert_eq!(convert(A | Z, 8, 0, 8).0, "00000010");
        // Left-justified: "%-8o" of 64 (zeros never trail).
        assert_eq!(convert(L | Z, 8, 0, 64).0, "100     ");
        // Width smaller than content: no truncation, no padding.
        assert_eq!(convert(0, 2, 0, u32::MAX).0, "37777777777");
        // Exact fit.
        assert_eq!(convert(0, 11, 0, u32::MAX).0, "37777777777");
        assert_eq!(convert(0, 12, 0, u32::MAX).0, " 37777777777");
        assert_eq!(convert(0, 12, 0, u32::MAX).1, 12);
    }

    #[test]
    fn length_flags_widen() {
        // hh masks to 8 bits: 0x1ff -> 0xff -> "377".
        assert_eq!(convert(FLAG_LEN_HH, 0, 0, 0x1ff).0, "377");
        // h masks to 16 bits: 0x1ffff -> 0xffff -> "177777".
        assert_eq!(convert(FLAG_LEN_H, 0, 0, 0x1ffff).0, "177777");
        // ll (0x80) skips widening; the u32 value passes through whole.
        assert_eq!(convert(FLAG_LEN_LL, 0, 0, 0x1ff).0, "777");
        assert_eq!(convert(FLAG_LEN_LL, 0, 0, u32::MAX).0, "37777777777");
    }
}
