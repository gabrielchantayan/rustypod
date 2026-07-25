//! printf converters for 64-bit decimal: `%lld` / `%llu`.
//!
//! Ports:
//! - `convert_lld` / `convert_llu` — original: `FUN_0802f574` @ 0x0802f574
//!   (208 bytes). The original is a single function dispatched on the
//!   conversion character in r1 (`'u'` selects the unsigned path); the port
//!   splits that dispatch into the two entry points. Signed path: a
//!   negative value is negated (wrapping, so `i64::MIN` yields 2^63) and
//!   gets a `"-"` prefix; otherwise the `+` flag (0x2) or space flag (0x4)
//!   selects its one-char prefix. Digits are peeled least-significant-first
//!   into a 32-byte stack buffer by repeated division via `_ll_udiv10`
//!   ([`ll_udiv10_full`] — the same helper the original bl's to at
//!   0x080320d0), then handed to the emitter.
//! - `emit_decimal` (private) — original: `FUN_080322cc` @ 0x080322cc
//!   (288 bytes), the shared integer emitter: a given precision becomes the
//!   minimum digit count and cancels zero padding, `pad_remaining` is
//!   reduced by the total content length, then leading pad / prefix / zero
//!   pad / precision zeros / digits (most-significant first) / trailing pad
//!   are emitted. Ported here as a private helper — its own module
//!   (printf_out) is being ported concurrently — calling the stable
//!   [`pad_emit`] / [`pad_emit_zero`] from printf_helpers exactly where the
//!   original bl's to 0x0802f208 / 0x0802f25c.
//!
//! Simplifications vs. the original:
//! - Sign prefixes are Rust byte-string literals instead of the literal
//!   pool at 0x0802f644 (`""` / `"-"` / `"+"` / `" "`); the emitter takes
//!   slices rather than (pointer, length) register pairs.
//! - Value 0 produces zero digits; the lone `'0'` comes from the emitter's
//!   default minimum of one digit, so `"%.0lld"` of 0 prints nothing,
//!   matching C. This is the original's behavior, not a deviation.
//! - No 64-bit `/` or `%` anywhere: all ÷10 goes through the ported
//!   `_ll_udiv10` (shift-add magic multiply, no `__aeabi_uldivmod`).

use crate::ll_udiv10::ll_udiv10_full;
use crate::printf_helpers::{pad_emit, pad_emit_zero, PrintfState, FLAG_PRECISION_GIVEN, FLAG_ZERO_PAD};

/// Format flag: `+` — always show a sign on signed conversions.
const FLAG_PLUS_SIGN: u32 = 0x002;
/// Format flag: ` ` (space) — prefix non-negative signed values with a
/// space (ignored when `+` is also given).
const FLAG_SPACE_SIGN: u32 = 0x004;

/// `convert_lld` — original: `FUN_0802f574` @ 0x0802f574, r1 != 'u' path.
///
/// Signed 64-bit decimal converter. Picks the sign prefix (negative wins
/// over the `+`/space flags), reduces to the magnitude, and defers to the
/// shared digit loop + emitter.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn convert_lld(state: *mut PrintfState, value: i64) {
    let flags = (*state).flags;
    let (magnitude, prefix): (u64, &[u8]) = if value < 0 {
        // Wrapping negate: i64::MIN maps to 2^63, its true magnitude.
        ((value as u64).wrapping_neg(), b"-")
    } else if flags & FLAG_PLUS_SIGN != 0 {
        (value as u64, b"+")
    } else if flags & FLAG_SPACE_SIGN != 0 {
        (value as u64, b" ")
    } else {
        (value as u64, b"")
    };
    convert_magnitude(state, magnitude, prefix);
}

/// `convert_llu` — original: `FUN_0802f574` @ 0x0802f574, r1 == 'u' path.
///
/// Unsigned 64-bit decimal converter: no sign handling at all — the `+` and
/// space flags are ignored, exactly like the original's early-out on 'u'.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn convert_llu(state: *mut PrintfState, value: u64) {
    convert_magnitude(state, value, b"");
}

/// Shared digit peel: divide by 10 repeatedly, storing digits
/// least-significant-first (original: `char local_40[32]`, `_ll_udiv10`
/// per digit, `remainder + '0'`).
unsafe fn convert_magnitude(state: *mut PrintfState, magnitude: u64, prefix: &[u8]) {
    let mut digits = [0u8; 32];
    let mut num_digits = 0usize;
    let mut remaining = magnitude;
    while remaining != 0 {
        let (quotient, digit) = ll_udiv10_full(remaining);
        // A u64 has at most 20 decimal digits; the buffer cannot overflow.
        *digits.get_unchecked_mut(num_digits) = digit + b'0';
        num_digits += 1;
        remaining = quotient;
    }
    // from_raw_parts rather than &digits[..num_digits]: the slicing
    // operator keeps a bounds check (slice_index_fail) LLVM cannot elide.
    emit_decimal(state, core::slice::from_raw_parts(digits.as_ptr(), num_digits), prefix);
}

/// `emit_decimal` — original: `FUN_080322cc` @ 0x080322cc (288 bytes).
///
/// Shared integer emitter. `digits` is least-significant-first as produced
/// by the converters; `prefix` is the 0/1-char sign string. See the module
/// header for the algorithm.
unsafe fn emit_decimal(state: *mut PrintfState, digits: &[u8], prefix: &[u8]) {
    let num_digits = digits.len() as i32;
    let prefix_len = prefix.len() as i32;

    // A given precision is the minimum digit count and cancels zero
    // padding (original: tst flags,#0x20; ldrne precision; bicne
    // flags,#0x10). Default minimum is one digit so 0 prints as "0".
    let min_digits = if (*state).flags & FLAG_PRECISION_GIVEN != 0 {
        (*state).flags &= !FLAG_ZERO_PAD;
        (*state).precision
    } else {
        1
    };
    let zero_digits = if num_digits < min_digits {
        min_digits - num_digits
    } else {
        0
    };

    // The field width must cover the whole content; the pad emitters
    // consume whatever is left (non-positive emits nothing).
    (*state).pad_remaining -= zero_digits + num_digits + prefix_len;

    // Space padding goes before the prefix; zero padding after it.
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
    for _ in 0..zero_digits {
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
    use crate::printf_helpers::{FLAG_LEFT_JUSTIFY, PutcFn};
    use core::ffi::c_void;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    /// Recording sink, same pattern as printf_helpers' tests.
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
            // The printf core seeds pad_remaining with the field width;
            // the emitter subtracts the content length from it.
            pad_remaining: width,
            precision,
            count: 0,
        }
    }

    fn lld(value: i64, flags: u32, width: i32, precision: i32) -> (String, i32) {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = make_state(flags, width, precision, &mut sink);
        unsafe { convert_lld(&mut st, value) };
        let count = st.count;
        (String::from_utf8(sink.buf).unwrap(), count)
    }

    fn llu(value: u64, flags: u32, width: i32, precision: i32) -> (String, i32) {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = make_state(flags, width, precision, &mut sink);
        unsafe { convert_llu(&mut st, value) };
        let count = st.count;
        (String::from_utf8(sink.buf).unwrap(), count)
    }

    #[test]
    fn zero_and_small_values() {
        assert_eq!(lld(0, 0, 0, 0), (std::string::ToString::to_string("0"), 1));
        assert_eq!(lld(1, 0, 0, 0).0, "1");
        assert_eq!(lld(-1, 0, 0, 0).0, "-1");
        assert_eq!(lld(9, 0, 0, 0).0, "9");
        assert_eq!(lld(10, 0, 0, 0).0, "10");
        assert_eq!(lld(-10, 0, 0, 0).0, "-10");
        assert_eq!(llu(0, 0, 0, 0).0, "0");
        assert_eq!(llu(1, 0, 0, 0).0, "1");
        assert_eq!(llu(10, 0, 0, 0).0, "10");
    }

    #[test]
    fn extremes() {
        assert_eq!(lld(i64::MAX, 0, 0, 0).0, "9223372036854775807");
        // i64::MIN: wrapping negate must yield 2^63, not UB/overflow.
        assert_eq!(lld(i64::MIN, 0, 0, 0).0, "-9223372036854775808");
        assert_eq!(lld(i64::MIN + 1, 0, 0, 0).0, "-9223372036854775807");
        assert_eq!(llu(u64::MAX, 0, 0, 0).0, "18446744073709551615");
        assert_eq!(llu(u64::MAX - 1, 0, 0, 0).0, "18446744073709551614");
    }

    #[test]
    fn nineteen_digit_values() {
        assert_eq!(lld(1_000_000_000_000_000_000, 0, 0, 0).0, "1000000000000000000");
        assert_eq!(lld(-1_000_000_000_000_000_000, 0, 0, 0).0, "-1000000000000000000");
        assert_eq!(llu(9_999_999_999_999_999_999, 0, 0, 0).0, "9999999999999999999");
        // Every power of ten up to 10^19, plus neighbors.
        let mut p = 1u64;
        for _ in 0..20 {
            assert_eq!(llu(p, 0, 0, 0).0, format!("{p}"));
            assert_eq!(llu(p - 1, 0, 0, 0).0, format!("{}", p - 1));
            p = p.wrapping_mul(10);
        }
    }

    /// Plain conversion must match std's Display exactly (deterministic
    /// xorshift64* stream, same generator as ll_udiv10's tests).
    #[test]
    fn matches_std_display() {
        let mut state = 0x9E3779B97F4A7C15u64;
        for _ in 0..10_000 {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let v = state.wrapping_mul(0x2545F4914F6CDD1D);
            assert_eq!(llu(v, 0, 0, 0).0, format!("{v}"), "llu({v})");
            let s = v as i64;
            assert_eq!(lld(s, 0, 0, 0).0, format!("{s}"), "lld({s})");
        }
    }

    #[test]
    fn width_right_justified() {
        assert_eq!(lld(42, 0, 10, 0), (std::string::ToString::to_string("        42"), 10));
        assert_eq!(lld(-42, 0, 10, 0).0, "       -42");
        assert_eq!(llu(42, 0, 10, 0).0, "        42");
        // Width smaller than content: no padding, content uncut.
        assert_eq!(lld(12345, 0, 3, 0).0, "12345");
        assert_eq!(lld(-1, 0, 1, 0).0, "-1");
    }

    #[test]
    fn width_zero_padded() {
        // Zeros go after the sign, before the digits.
        assert_eq!(lld(-42, FLAG_ZERO_PAD, 10, 0).0, "-000000042");
        assert_eq!(lld(42, FLAG_ZERO_PAD, 10, 0).0, "0000000042");
        assert_eq!(llu(42, FLAG_ZERO_PAD, 8, 0).0, "00000042");
        // ... and after a '+' prefix too (C: printf("%+010d", 42)).
        assert_eq!(lld(42, FLAG_ZERO_PAD | FLAG_PLUS_SIGN, 10, 0).0, "+000000042");
    }

    #[test]
    fn precision_minimum_digits() {
        assert_eq!(lld(42, FLAG_PRECISION_GIVEN, 0, 5).0, "00042");
        assert_eq!(lld(-42, FLAG_PRECISION_GIVEN, 0, 5).0, "-00042");
        assert_eq!(llu(42, FLAG_PRECISION_GIVEN, 0, 5).0, "00042");
        // Precision below the digit count changes nothing.
        assert_eq!(lld(12345, FLAG_PRECISION_GIVEN, 0, 3).0, "12345");
        // "%.0d" of zero prints nothing at all.
        assert_eq!(lld(0, FLAG_PRECISION_GIVEN, 0, 0), (String::new(), 0));
        assert_eq!(llu(0, FLAG_PRECISION_GIVEN, 0, 0).0, "");
        // ... but width padding still applies around the empty content.
        assert_eq!(lld(0, FLAG_PRECISION_GIVEN, 5, 0).0, "     ");
    }

    #[test]
    fn precision_cancels_zero_pad() {
        // C: printf("%010.5d", 42) -> "     00042" (precision wins over '0').
        assert_eq!(
            lld(42, FLAG_ZERO_PAD | FLAG_PRECISION_GIVEN, 10, 5).0,
            "     00042"
        );
        assert_eq!(
            lld(-42, FLAG_ZERO_PAD | FLAG_PRECISION_GIVEN, 10, 5).0,
            "    -00042"
        );
    }

    #[test]
    fn left_justified() {
        assert_eq!(lld(-7, FLAG_LEFT_JUSTIFY, 6, 0).0, "-7    ");
        assert_eq!(llu(42, FLAG_LEFT_JUSTIFY, 6, 0).0, "42    ");
        // Trailing pad is spaces even when the '0' flag is set.
        assert_eq!(
            lld(42, FLAG_LEFT_JUSTIFY | FLAG_ZERO_PAD, 6, 0).0,
            "42    "
        );
        // Left-justified with precision: zeros inside, spaces outside.
        assert_eq!(
            lld(42, FLAG_LEFT_JUSTIFY | FLAG_PRECISION_GIVEN, 8, 5).0,
            "00042   "
        );
    }

    #[test]
    fn sign_flags() {
        assert_eq!(lld(42, FLAG_PLUS_SIGN, 0, 0).0, "+42");
        assert_eq!(lld(0, FLAG_PLUS_SIGN, 0, 0).0, "+0");
        assert_eq!(lld(42, FLAG_SPACE_SIGN, 0, 0).0, " 42");
        // '+' wins over space.
        assert_eq!(lld(42, FLAG_PLUS_SIGN | FLAG_SPACE_SIGN, 0, 0).0, "+42");
        // Negative always wins over the flags.
        assert_eq!(lld(-42, FLAG_PLUS_SIGN, 0, 0).0, "-42");
        assert_eq!(lld(-42, FLAG_SPACE_SIGN, 0, 0).0, "-42");
        // Unsigned conversion ignores both flags entirely.
        assert_eq!(llu(42, FLAG_PLUS_SIGN, 0, 0).0, "42");
        assert_eq!(llu(42, FLAG_SPACE_SIGN, 0, 0).0, "42");
    }

    #[test]
    fn count_tracks_emitted_chars() {
        for (text, count) in [
            lld(0, 0, 0, 0),
            lld(i64::MIN, 0, 0, 0),
            llu(u64::MAX, 0, 0, 0),
            lld(-42, FLAG_ZERO_PAD, 10, 0),
            lld(42, FLAG_LEFT_JUSTIFY | FLAG_PRECISION_GIVEN, 8, 5),
        ] {
            assert_eq!(text.len() as i32, count, "count mismatch for {text:?}");
        }
    }
}
