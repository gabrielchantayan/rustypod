//! Ports of the ARM ADS 1.0.1 unsigned 64-bit string-to-integer routines:
//! the generic-base helper `__strtoull` and a `strtoull` entry point.
//!
//! Address note: the original port assignment cited 0x08030cd4 / 0x08030998,
//! but those are the ADS `qsort` insertion-sort / median-of-three quicksort
//! bodies. The real 64-bit helper is `__strtoull` @ 0x08034e68 (288 bytes),
//! called by `strtoll` @ 0x080332d0 and inlined twice inside retailOS
//! (0x0829c2a4 / 0x0829c2d0). No standalone `strtoull` wrapper exists in
//! osos: the one here reconstructs the standard wrapper from the
//! whitespace/sign prologue of `strtoll` @ 0x080332d0, with unsigned
//! semantics (no LLONG clamping) taken from `strtoul` @ 0x0802f87c.
//!
//! Algorithm (`__strtoull` @ 0x08034e68): optional `0`/`0x` prefix detection
//! (base 0 -> 8/16/10), then a digit loop valuing characters with `_chval`
//! (@ 0x08032fec, ported in chval.rs). The original accumulates in a
//! 16/32/16-bit split (r6/r8/r9) so it only needs 32x32->64 `umull`/`mla`;
//! overflow is flagged when the running value reaches 2^64 and the result
//! saturates to all-ones (errno = ERANGE on the original — skipped here,
//! like the other ports). The port keeps the same never-64x64-multiply
//! discipline using two 32-bit limbs, so the ARM build needs no
//! `__aeabi_lmul`.
//!
//! Original quirks preserved:
//! - `"0x"` (or `"0X"`) with base 0/16 and no hex digit after it counts as
//!   *no conversion*: `endptr` is left at the string start and 0 is
//!   returned (ISO C would stop after the `0`).
//! - `strtoull` negates the converted value for a `-` sign only when no
//!   overflow occurred (mirrors `strtoul`'s `errno != ERANGE` check), so
//!   `"-1"` -> `u64::MAX` but `"-18446744073709551616"` saturates to
//!   `u64::MAX` unnegated.
//!
//! Behavioral verification: host-side `cargo test` compares against a
//! u128-based reference implementation; `tools/match.py` (ipod-decomp)
//! reports the mnemonic-level diff against the original machine code.

use crate::chval::_chval;

/// __strtoull — original: `__strtoull` @ 0x08034e68 (288 bytes).
///
/// Parses an unsigned 64-bit integer in `base` (0 = auto: `0x` -> 16,
/// `0` -> 8, else 10) starting at `s`, which must point just past any
/// whitespace and sign (callers do that). On overflow the value saturates
/// to `u64::MAX`; the original also sets errno = ERANGE, which this port
/// skips. Returns the value; `endptr`, when non-NULL, receives a pointer
/// to the first character not consumed (`s` itself when no digit was
/// converted — including the `"0x"`-with-no-hex-digit case above).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __strtoull(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
    parse(s, endptr, base).0
}

/// strtoull — no standalone original in osos; wrapper prologue mirrors
/// `strtoll` @ 0x080332d0 (248 bytes), unsigned semantics as in
/// `strtoul` @ 0x0802f87c (176 bytes).
///
/// Skips C-locale whitespace, consumes an optional `+`/`-` sign, then defers
/// to `__strtoull`. A `-` sign negates the converted value (wrapping) unless
/// it overflowed. If no digits were converted, `endptr` is set to the
/// original string start, not the post-sign position. errno is never
/// touched (see module docs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strtoull(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
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
    let (mut value, overflow) = parse(p, endptr, base);
    if !endptr.is_null() && *endptr == p as *mut u8 {
        *endptr = s as *mut u8;
    }
    if negative && !overflow {
        value = value.wrapping_neg();
    }
    value
}

/// C-locale `isspace`, matching the ADS ctype table's bit-0x01 set.
#[inline]
fn is_c_space(c: u8) -> bool {
    matches!(c, b'\t'..=b'\r' | b' ')
}

/// The original `__strtoull` body. Returns the (possibly saturated) value
/// plus the overflow flag, which the `strtoull` wrapper needs to decide
/// whether a `-` sign negates.
unsafe fn parse(s: *const u8, endptr: *mut *mut u8, base: i32) -> (u64, bool) {
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
        let digit = _chval(c, base);
        if digit < 0 {
            break;
        }
        // acc = acc * base + digit, computed on two 32-bit limbs so every
        // multiply is 32x32->64 (umull) and LLVM emits no __aeabi_lmul call
        // on ARMv5. Bits at or above 2^64 set the sticky overflow flag,
        // exactly like the original's r9 >= 0x10000 test.
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
    (if overflow { u64::MAX } else { acc }, overflow)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    use std::{format, vec};

    /// Independent u128-based reference: same ADS semantics (prefix rules,
    /// `"0x"`-without-digits quirk, saturation, sign/endptr handling) but
    /// written with straightforward wide arithmetic. Returns
    /// `(value, end_offset_from_s)`.
    fn ref_strtoull(s: &[u8], base: i32) -> (u64, usize) {
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
        let digit = |c: u8| -> i32 {
            let v = match c {
                b'0'..=b'9' => (c - b'0') as i32,
                b'a'..=b'z' => (c - b'a') as i32 + 10,
                b'A'..=b'Z' => (c - b'A') as i32 + 10,
                _ => -1,
            };
            if v < 0 || v as u32 >= base {
                -1
            } else {
                v
            }
        };
        let mut acc: u128 = 0;
        let mut overflow = false;
        while i < s.len() {
            let d = digit(s[i]);
            if d < 0 {
                break;
            }
            if !overflow {
                acc = acc * base as u128 + d as u128;
                if acc > u64::MAX as u128 {
                    overflow = true;
                }
            }
            any_digits = true;
            i += 1;
        }
        // No conversion: endptr = original string start, not post-sign.
        let end = if any_digits { i } else { 0 };
        let mut value = if overflow { u64::MAX } else { acc as u64 };
        if negative && !overflow {
            value = value.wrapping_neg();
        }
        (value, end)
    }

    /// Run the port on a byte string; returns (value, endptr offset).
    fn run(s: &[u8], base: i32) -> (u64, usize) {
        let mut buf = s.to_vec();
        buf.push(0);
        let mut end: *mut u8 = core::ptr::null_mut();
        let value = unsafe { strtoull(buf.as_ptr(), &mut end, base) };
        let off = unsafe { end.offset_from(buf.as_ptr()) } as usize;
        (value, off)
    }

    fn check(s: &[u8], base: i32) {
        assert_eq!(run(s, base), ref_strtoull(s, base), "mismatch: {s:?} base={base}");
    }

    #[test]
    fn plain_values_and_endptr() {
        check(b"0", 10);
        check(b"1", 10);
        check(b"123", 10);
        check(b"42abc", 10); // endptr at 'a'
        check(b"18446744073709551615", 10); // u64::MAX
        check(b"", 10); // no conversion
        check(b"abc", 10); // no conversion
        check(b"z", 36);
        check(b"zzzz", 36);
        check(b"10", 2);
        check(b"2", 2); // '2' invalid in base 2
        check(b"007", 10);
    }

    #[test]
    fn prefixes_and_auto_base() {
        check(b"0", 0);
        check(b"017", 0); // octal
        check(b"08", 0); // '8' stops the octal scan
        check(b"123", 0);
        check(b"0x1f", 0);
        check(b"0X1F", 0);
        check(b"0x1f", 16);
        check(b"0x1f", 10); // 'x' stops: value 0, endptr after '0'
        check(b"0x", 0); // ADS quirk: no conversion at all
        check(b"0x", 16); // ADS quirk: no conversion at all
        check(b"0xg", 0); // ADS quirk: no conversion at all
        check(b"0x1f", 8); // prefix not consumed: value 0, endptr after '0'
        check(b"0b101", 0); // no binary prefix in ADS: value 0
        check(b"0", 16);
    }

    #[test]
    fn signs_and_whitespace() {
        check(b"+42", 10);
        check(b"-42", 10);
        check(b"-1", 10); // wraps to u64::MAX, no overflow
        check(b"-18446744073709551615", 10); // wraps to 1
        check(b"  42", 10);
        check(b"\t\n\r\x0b\x0c 42", 10);
        check(b"  -0x1f", 0);
        check(b"- 42", 10); // sign then space: no conversion, endptr = s
        check(b"-", 10); // no conversion
        check(b"+", 10);
        check(b"  -", 10);
        check(b"-abc", 16);
    }

    #[test]
    fn overflow_saturates() {
        check(b"18446744073709551616", 10); // MAX + 1
        check(b"184467440737095516150", 10);
        check(b"99999999999999999999999999999", 10);
        check(b"0xFFFFFFFFFFFFFFFF", 0); // exactly MAX
        check(b"0xFFFFFFFFFFFFFFFFF", 0); // MAX * 16 + 15
        check(b"0x10000000000000000", 0); // 2^64
        check(b"20000000000000000000", 10);
        check(b"-18446744073709551616", 10); // overflow: MAX, not negated
        check(b"-99999999999999999999999999999", 10);
        check(b"1777777777777777777777", 8); // 2^64 - 1 octal
        check(b"2000000000000000000000", 8); // 2^64 octal
        check(b"1111111111111111111111111111111111111111111111111111111111111111", 2);
        check(b"10000000000000000000000000000000000000000000000000000000000000000", 2);
    }

    #[test]
    fn known_values() {
        assert_eq!(run(b"0", 0), (0, 1));
        assert_eq!(run(b"017", 0), (15, 3));
        assert_eq!(run(b"0x1f", 0), (31, 4));
        assert_eq!(run(b"0x1f", 10), (0, 1));
        assert_eq!(run(b"0x", 16), (0, 0)); // ADS quirk
        assert_eq!(run(b"-1", 10), (u64::MAX, 2));
        assert_eq!(run(b"-18446744073709551615", 10), (1, 21));
        assert_eq!(run(b"18446744073709551615", 10), (u64::MAX, 20));
        assert_eq!(run(b"18446744073709551616", 10), (u64::MAX, 20));
        assert_eq!(run(b"  -0x1f", 0), ((-(31i64)) as u64, 7));
        assert_eq!(run(b"42abc", 10), (42, 2));
        assert_eq!(run(b"abc", 10), (0, 0));
    }

    /// endptr = NULL is accepted everywhere.
    #[test]
    fn null_endptr() {
        let mut buf = b"  -0x1fxyz\0".to_vec();
        let value = unsafe { strtoull(buf.as_mut_ptr(), core::ptr::null_mut(), 0) };
        assert_eq!(value, (-(31i64)) as u64);
        buf = b"18446744073709551616\0".to_vec();
        let value = unsafe { strtoull(buf.as_mut_ptr(), core::ptr::null_mut(), 10) };
        assert_eq!(value, u64::MAX);
    }

    /// __strtoull entry: no whitespace/sign handling of its own.
    #[test]
    fn helper_entry_point() {
        let buf = b"1f \0";
        let mut end: *mut u8 = core::ptr::null_mut();
        let value = unsafe { __strtoull(buf.as_ptr(), &mut end, 16) };
        assert_eq!(value, 0x1f);
        assert_eq!(unsafe { end.offset_from(buf.as_ptr()) }, 2);
        // Whitespace is not skipped by the helper.
        let buf = b" 42\0";
        let value = unsafe { __strtoull(buf.as_ptr(), core::ptr::null_mut(), 10) };
        assert_eq!(value, 0);
    }

    /// Round-trip: format values in every base 2..=36, parse them back.
    #[test]
    fn base_roundtrip() {
        let digits: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let values = [
            0u64,
            1,
            2,
            35,
            36,
            255,
            4096,
            1_000_000,
            u32::MAX as u64,
            u64::MAX >> 1,
            u64::MAX - 1,
            u64::MAX,
        ];
        for base in 2u32..=36 {
            for &v in &values {
                let mut text = Vec::new();
                let mut n = v;
                loop {
                    text.push(digits[(n % base as u64) as usize]);
                    n /= base as u64;
                    if n == 0 {
                        break;
                    }
                }
                text.reverse();
                let (parsed, end) = run(&text, base as i32);
                assert_eq!(parsed, v, "roundtrip: {v} base={base} text={text:?}");
                assert_eq!(end, text.len());
            }
        }
    }

    /// Pseudo-random fuzz (xorshift) against the u128 reference across
    /// random alphabet soup and all bases.
    #[test]
    fn fuzz_vs_u128_reference() {
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

    /// Long digit runs that always overflow, every base.
    #[test]
    fn fuzz_overflow_runs() {
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
        for v in [0u64, 7, 99, 65535, 1_000_000_007, u64::MAX >> 3, u64::MAX] {
            let text = format!("{v}");
            assert_eq!(run(text.as_bytes(), 10).0, v);
            let text = format!("  +{v}x");
            assert_eq!(run(text.as_bytes(), 10), (v, text.len() - 1));
        }
        // ISO: -1 mod 2^64.
        assert_eq!(run(b"-1", 10).0, u64::MAX);
    }
}
