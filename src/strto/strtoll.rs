//! Port of the ARM ADS 1.0.1 signed 64-bit string-to-integer routine
//! `strtoll` @ 0x080332d0 (248 bytes).
//!
//! Algorithm (original): skip C-locale whitespace (ADS ctype table bit 0x01,
//! fetched through the table-pointer getter @ 0x0802eca0), consume an
//! optional `+`/`-` sign, then call the unsigned core `__strtoull`
//! @ 0x08034e68. If the core reports no conversion (`*endptr` left at the
//! post-sign position), `endptr` is reset to the original string start.
//! Finally the unsigned magnitude is range-checked against the signed
//! 64-bit domain: a `-` sign negates (wrapping) and a magnitude above 2^63
//! clamps to `LLONG_MIN`; without a sign a magnitude at or above 2^63
//! clamps to `LLONG_MAX`. On either clamp the original also stores 2
//! (ERANGE) through `__rt_errno_addr` @ 0x0802ecb4 — this port skips errno
//! entirely, like the other stdlib ports.
//!
//! Per the port assignment this module does NOT import `__strtoull` from
//! strtoull.rs (owned by another agent); the unsigned accumulation is
//! re-implemented inline with the same semantics, digit valuation included
//! (the `_chval` @ 0x08032fec wrap-and-compare idiom). Accumulation keeps
//! the original's never-64x64-multiply discipline using two 32-bit limbs,
//! so the ARMv5 build needs no `__aeabi_lmul`/`__aeabi_uldivmod` helpers.
//!
//! Original quirks preserved:
//! - `"0x"` (or `"0X"`) with base 0/16 and no hex digit after it counts as
//!   *no conversion*: `endptr` is left at the string start and 0 is
//!   returned (ISO C would stop after the `0`).
//! - `"-9223372036854775808"` is accepted exactly (magnitude 2^63 negates
//!   to `LLONG_MIN` without clamping); one more digit of magnitude clamps.
//! - Digit valuation keeps `_chval`'s raw unsigned compare, so characters
//!   between `'9'` and `'A'` (e.g. `':'`) are only rejected because their
//!   value exceeds sane bases.
//!
//! Behavioral verification: host-side `cargo test` compares against an
//! i128-based reference implementation; `tools/match.py` (ipod-decomp)
//! reports the mnemonic-level diff against the original machine code.

/// strtoll — original: `strtoll` @ 0x080332d0 (248 bytes).
///
/// Parses a signed 64-bit integer in `base` (0 = auto: `0x` -> 16, `0` ->
/// 8, else 10). Skips C-locale whitespace, consumes an optional `+`/`-`
/// sign, converts the unsigned magnitude, then clamps to the `i64` range:
/// overflow returns `i64::MAX` (positive) or `i64::MIN` (negative); the
/// original sets errno = ERANGE on clamping, which this port skips.
/// `endptr`, when non-NULL, receives a pointer to the first character not
/// consumed, or `s` itself when no conversion was performed (including the
/// `"0x"`-with-no-hex-digit case).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strtoll(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
    let mut p = s;
    while is_c_space(*p) {
        p = p.add(1);
    }
    let mut negative = false;
    let c = *p;
    if c == b'+' {
        p = p.add(1);
    } else if c == b'-' {
        negative = true;
        p = p.add(1);
    }

    let magnitude = parse_magnitude(p, endptr, base);

    // No-conversion fixup: the unsigned core leaves `*endptr` at the
    // post-sign position it was given; strtoll rewinds it to the original
    // string start.
    if !endptr.is_null() && *endptr == p as *mut u8 {
        *endptr = s as *mut u8;
    }

    if negative {
        // Wrapping negate, exactly the original's rsbs/rsc pair: a
        // magnitude of exactly 2^63 maps to i64::MIN and is accepted.
        let value = (magnitude as i64).wrapping_neg();
        if value > 0 {
            // Magnitude above 2^63: original sets errno = ERANGE here.
            i64::MIN
        } else {
            value
        }
    } else {
        let value = magnitude as i64;
        if value < 0 {
            // Magnitude at or above 2^63: original sets errno = ERANGE here.
            i64::MAX
        } else {
            value
        }
    }
}

/// C-locale `isspace`, matching the ADS ctype table's bit-0x01 set.
#[inline]
fn is_c_space(c: u8) -> bool {
    matches!(c, b'\t'..=b'\r' | b' ')
}

/// Digit valuation, mirroring `_chval` @ 0x08032fec: characters below `'0'`
/// wrap to huge unsigned values after the subtract and are rejected by the
/// final base compare, as in the original. Returns -1 when the character
/// is not a digit valid for `base`.
#[inline]
fn digit_value(c: u8, base: u32) -> i32 {
    let mut value = c as u32;
    if value < 0x3a {
        // '0'..'9' -> 0..9; anything below '0' wraps huge.
        value = value.wrapping_sub(0x30);
    }
    let upper = value & !0x20; // fold lowercase to uppercase
    if upper >= 0x41 {
        // 'A'..'Z' (and wrapped-huge values) -> letter value or still-huge.
        value = upper.wrapping_sub(0x37);
    }
    if value >= base { -1 } else { value as i32 }
}

/// Inline re-implementation of the `__strtoull` @ 0x08034e68 body (this
/// module is self-contained by assignment). `s` must point just past any
/// whitespace and sign. Returns the converted magnitude, saturated to
/// `u64::MAX` on overflow; `endptr`, when non-NULL, receives a pointer to
/// the first character not consumed (`s` itself when no digit was
/// converted — including the `"0x"`-with-no-hex-digit case).
unsafe fn parse_magnitude(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
    let mut base = base as u32;
    let mut any_digits = false;
    let mut p = s.add(1);
    let mut c = *s;
    if c == b'0' {
        c = *p;
        p = p.add(1);
        // A leading '0' is itself a converted digit, unless it turns out
        // to be part of a consumed "0x" prefix.
        any_digits = true;
        if c == b'x' || c == b'X' {
            if base == 0 || base == 16 {
                c = *p;
                p = p.add(1);
                any_digits = false;
                base = 16;
            }
        } else if base == 0 {
            base = 8;
        }
    } else if base == 0 {
        base = 10;
    }

    let mut acc: u64 = 0;
    let mut overflow = false;
    loop {
        let digit = digit_value(c, base);
        if digit < 0 {
            break;
        }
        // acc = acc * base + digit, computed on two 32-bit limbs so every
        // multiply is 32x32->64 (umull) and LLVM emits no __aeabi_lmul call
        // on ARMv5. Bits at or above 2^64 set the sticky overflow flag,
        // exactly like the original's top-limb test.
        let wide_base = base as u64;
        let lo = (acc as u32) as u64 * wide_base + digit as u64;
        let hi = (acc >> 32) * wide_base + (lo >> 32);
        acc = (lo & 0xffff_ffff) | (hi << 32);
        if hi >> 32 != 0 {
            overflow = true;
        }
        any_digits = true;
        c = *p;
        p = p.add(1);
    }

    if !endptr.is_null() {
        *endptr = (if any_digits { p.sub(1) } else { s }) as *mut u8;
    }
    if overflow { u64::MAX } else { acc }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    use std::{format, vec};

    /// Independent i128-based reference: same ADS semantics (prefix rules,
    /// `"0x"`-without-digits quirk, u64 saturation, sign/endptr handling,
    /// i64 clamping) but written with straightforward wide arithmetic.
    /// Returns `(value, end_offset_from_s)`.
    fn ref_strtoll(s: &[u8], base: i32) -> (i64, usize) {
        let mut i = 0;
        while i < s.len() && matches!(s[i], b'\t'..=b'\r' | b' ') {
            i += 1;
        }
        let mut negative = false;
        if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
            negative = s[i] == b'-';
            i += 1;
        }

        // __strtoull body.
        let mut base = base as u32;
        let mut any_digits = false;
        if i < s.len() && s[i] == b'0' {
            i += 1;
            any_digits = true;
            if i < s.len() && (s[i] == b'x' || s[i] == b'X') {
                if base == 0 || base == 16 {
                    i += 1;
                    any_digits = false;
                    base = 16;
                }
            } else if base == 0 {
                base = 8;
            }
        } else if base == 0 {
            base = 10;
        }
        // Same wrap-and-compare idiom as the original _chval.
        let digit = |c: u8| -> i32 {
            let mut v = c as u32;
            if v < 0x3a {
                v = v.wrapping_sub(0x30);
            }
            let upper = v & !0x20;
            if upper >= 0x41 {
                v = upper.wrapping_sub(0x37);
            }
            if v >= base { -1 } else { v as i32 }
        };
        let mut acc: i128 = 0;
        let mut overflow = false;
        while i < s.len() {
            let d = digit(s[i]);
            if d < 0 {
                break;
            }
            if !overflow {
                acc = acc * base as i128 + d as i128;
                if acc > u64::MAX as i128 {
                    overflow = true;
                }
            }
            any_digits = true;
            i += 1;
        }
        // No conversion: endptr = original string start, not post-sign.
        let end = if any_digits { i } else { 0 };
        let magnitude = if overflow { u64::MAX } else { acc as u64 };
        let value = if negative {
            let v = (magnitude as i64).wrapping_neg();
            if v > 0 { i64::MIN } else { v }
        } else {
            let v = magnitude as i64;
            if v < 0 { i64::MAX } else { v }
        };
        (value, end)
    }

    /// Run the port on a byte string; returns (value, endptr offset).
    fn run(s: &[u8], base: i32) -> (i64, usize) {
        let mut buf = s.to_vec();
        buf.push(0);
        let mut end: *mut u8 = core::ptr::null_mut();
        let value = unsafe { strtoll(buf.as_ptr(), &mut end, base) };
        let off = unsafe { end.offset_from(buf.as_ptr()) } as usize;
        (value, off)
    }

    fn check(s: &[u8], base: i32) {
        assert_eq!(run(s, base), ref_strtoll(s, base), "mismatch: {s:?} base={base}");
    }

    #[test]
    fn i64_range_edges() {
        check(b"9223372036854775806", 10);
        check(b"9223372036854775807", 10); // i64::MAX, exact
        check(b"9223372036854775808", 10); // MAX + 1: clamp
        check(b"-9223372036854775807", 10);
        check(b"-9223372036854775808", 10); // i64::MIN, exact (no clamp)
        check(b"-9223372036854775809", 10); // MIN - 1: clamp
        check(b"0x7FFFFFFFFFFFFFFF", 0); // i64::MAX in hex
        check(b"0x8000000000000000", 0); // 2^63: clamp to MAX
        check(b"-0x8000000000000000", 0); // i64::MIN in hex, exact
        check(b"-0x8000000000000001", 0); // clamp to MIN
        check(b"777777777777777777777", 8); // 2^63 - 1 octal
        check(b"1000000000000000000000", 8); // 2^63 octal: clamp
        check(b"-1000000000000000000000", 8); // i64::MIN octal, exact
        check(b"111111111111111111111111111111111111111111111111111111111111111", 2);
        check(b"1000000000000000000000000000000000000000000000000000000000000000", 2);
        check(b"-1000000000000000000000000000000000000000000000000000000000000000", 2);
    }

    #[test]
    fn clamping_both_ends() {
        assert_eq!(run(b"9223372036854775807", 10), (i64::MAX, 19));
        assert_eq!(run(b"9223372036854775808", 10), (i64::MAX, 19));
        assert_eq!(run(b"99999999999999999999999999999", 10), (i64::MAX, 29));
        assert_eq!(run(b"18446744073709551615", 10), (i64::MAX, 20)); // u64::MAX
        assert_eq!(run(b"18446744073709551616", 10), (i64::MAX, 20)); // u64 overflow
        assert_eq!(run(b"-9223372036854775808", 10), (i64::MIN, 20));
        assert_eq!(run(b"-9223372036854775809", 10), (i64::MIN, 20));
        assert_eq!(run(b"-99999999999999999999999999999", 10), (i64::MIN, 30));
        assert_eq!(run(b"-18446744073709551615", 10), (i64::MIN, 21));
        assert_eq!(run(b"-18446744073709551616", 10), (i64::MIN, 21));
        // Clamping consumes every valid digit: endptr reaches the NUL.
        assert_eq!(run(b"99999999999999999999xyz", 10), (i64::MAX, 20));
        assert_eq!(run(b"-99999999999999999999xyz", 10), (i64::MIN, 21));
    }

    #[test]
    fn signs_and_whitespace() {
        check(b"+42", 10);
        check(b"-42", 10);
        check(b"+0", 10);
        check(b"-0", 10);
        check(b"  42", 10);
        check(b"\t\n\r\x0b\x0c 42", 10);
        check(b"  -0x1f", 0);
        check(b" \t +123 ", 10);
        check(b"- 42", 10); // sign then space: no conversion, endptr = s
        check(b"-", 10); // no conversion
        check(b"+", 10);
        check(b"  -", 10);
        check(b"-abc", 16);
        check(b"--42", 10); // second sign not consumed
        check(b"++42", 10);
        check(b"-+42", 10);
    }

    #[test]
    fn bases() {
        check(b"0", 0);
        check(b"017", 0); // octal
        check(b"08", 0); // '8' stops the octal scan
        check(b"123", 0);
        check(b"0x1f", 0);
        check(b"0X1F", 0);
        check(b"-0X1F", 0);
        check(b"0x1f", 16);
        check(b"0x1f", 10); // 'x' stops: value 0, endptr after '0'
        check(b"0x1f", 8); // prefix not consumed: value 0, endptr after '0'
        check(b"0b101", 0); // no binary prefix in ADS: value 0
        check(b"101", 2);
        check(b"-101", 2);
        check(b"2", 2); // '2' invalid in base 2: no conversion
        check(b"777", 8);
        check(b"-777", 8);
        check(b"deadBEEF", 16);
        check(b"-deadBEEF", 16);
        check(b"z", 36);
        check(b"-z", 36);
        check(b"zzzzzzzz", 36);
        check(b"ZzZz", 36);
        check(b"007", 10);
    }

    #[test]
    fn endptr_behavior() {
        assert_eq!(run(b"42abc", 10), (42, 2));
        assert_eq!(run(b"  -42abc", 10), (-42, 5));
        assert_eq!(run(b"0x1f", 10), (0, 1)); // stops after the '0'
        assert_eq!(run(b"017", 0), (15, 3));
        assert_eq!(run(b"123", 0), (123, 3));
        assert_eq!(run(b"0", 0), (0, 1));
        // endptr = NULL is accepted everywhere.
        let buf = b"  -0x1fxyz\0";
        let value = unsafe { strtoll(buf.as_ptr(), core::ptr::null_mut(), 0) };
        assert_eq!(value, -31);
        let buf = b"99999999999999999999999\0";
        let value = unsafe { strtoll(buf.as_ptr(), core::ptr::null_mut(), 10) };
        assert_eq!(value, i64::MAX);
    }

    #[test]
    fn no_conversion() {
        assert_eq!(run(b"", 10), (0, 0));
        assert_eq!(run(b"abc", 10), (0, 0));
        assert_eq!(run(b"   ", 10), (0, 0));
        assert_eq!(run(b"  abc", 10), (0, 0));
        assert_eq!(run(b"-", 10), (0, 0));
        assert_eq!(run(b"+", 10), (0, 0));
        assert_eq!(run(b"  -", 10), (0, 0));
        assert_eq!(run(b"-abc", 10), (0, 0));
        assert_eq!(run(b"+xyz", 16), (0, 0));
        // ADS quirk: "0x" with no hex digit is no conversion at all.
        assert_eq!(run(b"0x", 0), (0, 0));
        assert_eq!(run(b"0x", 16), (0, 0));
        assert_eq!(run(b"0xg", 0), (0, 0));
        assert_eq!(run(b"-0x", 0), (0, 0));
        assert_eq!(run(b"  -0xg", 16), (0, 0));
        // ...but base 10 sees a plain '0' followed by 'x'.
        assert_eq!(run(b"0x", 10), (0, 1));
    }

    #[test]
    fn known_values() {
        assert_eq!(run(b"0", 10), (0, 1));
        assert_eq!(run(b"1", 10), (1, 1));
        assert_eq!(run(b"-1", 10), (-1, 2));
        assert_eq!(run(b"123", 10), (123, 3));
        assert_eq!(run(b"-123", 10), (-123, 4));
        assert_eq!(run(b"2147483647", 10), (i32::MAX as i64, 10));
        assert_eq!(run(b"2147483648", 10), (i32::MAX as i64 + 1, 10));
        assert_eq!(run(b"-2147483648", 10), (i32::MIN as i64, 11));
        assert_eq!(run(b"-2147483649", 10), (i32::MIN as i64 - 1, 11));
        assert_eq!(run(b"0x1f", 0), (31, 4));
        assert_eq!(run(b"-0x1f", 0), (-31, 5));
        assert_eq!(run(b"  -0x1f", 0), (-31, 7));
    }

    /// Round-trip: format values in every base 2..=36, parse them back.
    #[test]
    fn base_roundtrip() {
        let digits: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let values = [
            0i64,
            1,
            -1,
            2,
            -35,
            36,
            255,
            -4096,
            1_000_000,
            i32::MAX as i64,
            i32::MIN as i64,
            i64::MAX >> 1,
            i64::MAX - 1,
            i64::MAX,
            i64::MIN + 1,
            i64::MIN,
        ];
        for base in 2u32..=36 {
            for &v in &values {
                // Format the magnitude; '-' prefix for negatives.
                let mut mag = (v as i128).unsigned_abs() as u64;
                let mut text = Vec::new();
                if v < 0 {
                    text.push(b'-');
                }
                let start = text.len();
                loop {
                    text.push(digits[(mag % base as u64) as usize]);
                    mag /= base as u64;
                    if mag == 0 {
                        break;
                    }
                }
                text[start..].reverse();
                let (parsed, end) = run(&text, base as i32);
                assert_eq!(parsed, v, "roundtrip: {v} base={base} text={text:?}");
                assert_eq!(end, text.len());
            }
        }
    }

    /// Pseudo-random fuzz (xorshift) against the i128 reference across
    /// random alphabet soup and all bases.
    #[test]
    fn fuzz_vs_i128_reference() {
        let mut state = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: &[u8] = b"0123456789abcdefxyzABCDEFXYZ+- \t0xX";
        for _ in 0..20_000 {
            let len = (next() % 24) as usize;
            let text: Vec<u8> = (0..len)
                .map(|_| alphabet[(next() as usize) % alphabet.len()])
                .collect();
            let base = (next() % 40) as i32; // includes 0, 1 and >36
            check(&text, base);
        }
    }

    /// Long digit runs that always overflow (and clamp), every base,
    /// with and without a minus sign.
    #[test]
    fn fuzz_clamping_runs() {
        let mut state = 0xdeadbeefcafef00du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let digits: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        for _ in 0..2_000 {
            let base = 2 + (next() % 35) as i32;
            let len = 20 + (next() % 44) as usize;
            let mut text = vec![b'-'; 1];
            if next() & 1 == 0 {
                text.clear();
            }
            for _ in 0..len {
                text.push(digits[(next() as usize) % (base as usize)]);
            }
            check(&text, base);
        }
    }

    /// std's parser as a third opinion where ADS is ISO-compliant
    /// (plain decimal, no prefix quirks, no overflow).
    #[test]
    fn matches_std_for_plain_decimal() {
        for v in [0i64, 7, -99, 65535, -1_000_000_007, i64::MAX >> 3, i64::MAX, i64::MIN] {
            let text = format!("{v}");
            assert_eq!(run(text.as_bytes(), 10).0, v);
            if v >= 0 {
                let text = format!("  +{v}x");
                assert_eq!(run(text.as_bytes(), 10), (v, text.len() - 1));
            }
        }
    }
}
