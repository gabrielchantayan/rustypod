//! strtoul — original: conversion core `FUN_08033088` @ 0x08033088
//! (232 bytes), merged with the whitespace/sign wrapper of the real ADS
//! `strtoul` entry @ 0x0802f87c. In the firmware these are two functions:
//! the wrapper skips C whitespace (ctype table bit 0), consumes an optional
//! '+'/'-', calls the core, and fixes `endptr` back to the original string
//! when no digits were converted. The core alone does neither; here both
//! are ported as one function to give full C `strtoul` semantics.
//!
//! Algorithm: skip whitespace; optional sign; base 0 autodetect
//! ("0x"/"0X" -> 16, leading '0' -> 8, else 10) or explicit base 2..36;
//! accumulate digits with a 32-bit overflow check per step; on overflow
//! return u32::MAX and set errno = ERANGE. `endptr` receives a pointer to
//! the first unparsed character, or `s` itself when no digits converted.
//!
//! Deviations / simplifications:
//! - errno is NOT modeled yet: the original stores 2 (ERANGE) through the
//!   __errno() address (FUN_0802ecb4) on overflow. This port skips that
//!   store; overflow is observable only via the u32::MAX return.
//! - The original accumulates in a 16:16 split register pair and flags
//!   overflow when the high half reaches 0x10000 (value >= 2^32). This
//!   port uses wrapping u32 mul/add with carry detection — the same
//!   condition, and the same low-32-bit accumulation afterwards.
//! - Quirk kept from the original: a "0x"/"0X" prefix under base 0 or 16
//!   resets the digit-seen flag, so "0x" or "0xz" converts *no digits*
//!   (endptr = s, result 0) instead of ISO C's "0" with endptr at 'x'.

/// ADS digit-value helper — original: `FUN_08032fec` @ 0x08032fec.
///
/// Maps a character to its digit value in `base`, or -1 when invalid.
/// '0'..'9' -> 0..9; letters fold to uppercase (clear bit 5) -> 10..35.
/// All comparisons are unsigned, exactly like the original.
fn digit_value(c: u8, base: u32) -> i32 {
    let mut value = c as u32;
    if value < 58 {
        // c <= '9': subtract '0' (wraps harmlessly for c < '0').
        value = value.wrapping_sub(48);
    }
    let folded = value & !32;
    if folded >= 65 {
        // (folded) >= 'A': letter range -> 10..35, junk -> huge value.
        value = folded.wrapping_sub(55);
    }
    if value >= base {
        -1
    } else {
        value as i32
    }
}

/// C whitespace, as flagged by bit 0 of the ADS ctype table.
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

#[no_mangle]
pub unsafe extern "C" fn strtoul(s: *const u8, endptr: *mut *mut u8, base: i32) -> u32 {
    // --- wrapper @ 0x0802f87c: whitespace skip and optional sign ---
    let mut p = s;
    let mut c = p.read();
    while c != 0 && is_c_space(c) {
        p = p.add(1);
        c = p.read();
    }
    let negative = c == b'-';
    if c == b'+' || negative {
        p = p.add(1);
    }

    // --- conversion core @ 0x08033088 ---
    let mut base = base as u32;
    let mut digits_seen = false;
    c = p.read();
    if c == b'0' {
        digits_seen = true;
        p = p.add(1);
        c = p.read();
        if c == b'x' || c == b'X' {
            if base == 0 || base == 16 {
                p = p.add(1);
                c = p.read();
                digits_seen = false;
                base = 16;
            }
        } else if base == 0 {
            base = 8;
        }
    } else if base == 0 {
        base = 10;
    }

    let mut value: u32 = 0;
    let mut overflow = false;
    loop {
        let digit = digit_value(c, base);
        if digit < 0 {
            break;
        }
        let (product, mul_carry) = value.overflowing_mul(base);
        let (sum, add_carry) = product.overflowing_add(digit as u32);
        value = sum;
        if mul_carry || add_carry {
            overflow = true;
        }
        digits_seen = true;
        p = p.add(1);
        c = p.read();
    }

    if !endptr.is_null() {
        *endptr = if digits_seen { p as *mut u8 } else { s as *mut u8 };
    }

    if overflow {
        // Original stores 2 (ERANGE) via __errno(); not modeled yet.
        u32::MAX
    } else if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::ptr;
    use std::vec::Vec;

    /// Independent reference implementation of the documented ADS
    /// semantics (whitespace, sign, base autodetect, "0x"-resets-seen
    /// quirk, u32 overflow -> u32::MAX). Returns (value, end_offset).
    fn ref_strtoul(s: &[u8], base: i32) -> (u32, usize) {
        let mut i = 0usize;
        while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
            i += 1;
        }
        let mut negative = false;
        if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
            negative = s[i] == b'-';
            i += 1;
        }
        let start = i;
        let mut base = base as u32;
        let mut seen = false;
        if i < s.len() && s[i] == b'0' {
            seen = true;
            i += 1;
            if i < s.len() && (s[i] | 32) == b'x' && (base == 0 || base == 16) {
                seen = false;
                base = 16;
                i += 1;
            } else if base == 0 {
                base = 8;
            }
        } else if base == 0 {
            base = 10;
        }
        let mut value: u64 = 0;
        let mut overflow = false;
        while i < s.len() {
            let d = match s[i] {
                b'0'..=b'9' => (s[i] - b'0') as u32,
                b'a'..=b'z' => (s[i] - b'a' + 10) as u32,
                b'A'..=b'Z' => (s[i] - b'A' + 10) as u32,
                _ => break,
            };
            if d >= base {
                break;
            }
            value = value * base as u64 + d as u64;
            if value > u32::MAX as u64 {
                overflow = true;
                value &= u32::MAX as u64;
            }
            seen = true;
            i += 1;
        }
        let end = if seen { i } else { 0 };
        let _ = start;
        if overflow {
            (u32::MAX, end)
        } else if negative {
            ((value as u32).wrapping_neg(), end)
        } else {
            (value as u32, end)
        }
    }

    /// Run the port on a NUL-terminated copy of `s`; return (value, end_offset).
    fn run(s: &[u8], base: i32) -> (u32, usize) {
        let mut buf: Vec<u8> = s.to_vec();
        buf.push(0);
        let mut end: *mut u8 = ptr::null_mut();
        let value = unsafe { strtoul(buf.as_ptr(), &mut end, base) };
        let off = unsafe { end.offset_from(buf.as_ptr()) } as usize;
        (value, off)
    }

    fn check(s: &[u8], base: i32) {
        assert_eq!(run(s, base), ref_strtoul(s, base), "input {s:?} base {base}");
    }

    #[test]
    fn decimal() {
        check(b"0", 10);
        check(b"42", 10);
        check(b"12345", 10);
        check(b"4294967295", 10); // u32::MAX, no overflow
        check(b"000123", 10);
    }

    #[test]
    fn hex() {
        check(b"0x1A2B", 0);
        check(b"0Xff", 0);
        check(b"1A2B", 16);
        check(b"0xdeadBEEF", 16);
        check(b"0xffffffff", 0); // u32::MAX, no overflow
        check(b"deadbeef", 0); // base 0: parses '0'? no — 'd' first, base 10, no digits
    }

    #[test]
    fn octal_and_base0() {
        check(b"0755", 0);
        check(b"755", 8);
        check(b"017", 0);
        check(b"08", 0); // '8' is not octal: stops after '0'
        check(b"999", 0);
        check(b"0", 0);
    }

    #[test]
    fn signs() {
        check(b"+42", 10);
        check(b"-42", 10);
        check(b"-0", 0);
        check(b"+0x10", 0);
        check(b"- 42", 10); // sign then space: no digits
    }

    #[test]
    fn whitespace() {
        check(b"  42", 10);
        check(b"\t\n\x0b\x0c\r 42", 10);
        check(b"   -1", 10);
        check(b"   ", 10);
        check(b"42  ", 10);
    }

    #[test]
    fn overflow() {
        check(b"4294967296", 10); // u32::MAX + 1
        check(b"99999999999999999999", 10);
        check(b"0x100000000", 16);
        check(b"040000000000", 0); // octal 2^32
        check(b"-4294967296", 10); // overflow wins over negation
        check(b"42949672960", 10);
    }

    #[test]
    fn no_digits() {
        check(b"", 10);
        check(b"abc", 10);
        check(b"-", 10);
        check(b"+", 0);
        check(b"-abc", 10);
        check(b"0x", 0); // ADS quirk: no digits, endptr = s
        check(b"0xz", 16); // same quirk under explicit base 16
        check(b"0xg", 0);
    }

    #[test]
    fn endptr_positions() {
        assert_eq!(run(b"123abc", 10), (123, 3));
        assert_eq!(run(b"0x1fZ", 0), (0x1f, 4));
        assert_eq!(run(b"  -77x", 10), ((-77i32 as u32), 5));
        assert_eq!(run(b"abc", 10), (0, 0));
        assert_eq!(run(b"0x", 0), (0, 0));
        assert_eq!(run(b"0", 0), (0, 1));
        assert_eq!(run(b"0x5", 8), (0, 1)); // base 8: '0' then stop at 'x'
    }

    #[test]
    fn null_endptr() {
        let mut buf: Vec<u8> = b"  -0x1frest".to_vec();
        buf.push(0);
        let value = unsafe { strtoul(buf.as_ptr(), ptr::null_mut(), 0) };
        assert_eq!(value, (-0x1fi32) as u32);
    }

    /// Every base 2..36 (plus 0) over deterministic pseudo-random strings
    /// mixing digits, letters, signs, spaces and junk.
    #[test]
    fn all_bases_vs_reference() {
        let mut state: u32 = 0x12345678;
        let mut rand = move || {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        };
        let alphabet: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ +-\txZ:/";
        for base in 0..=36i32 {
            for len in 0..24usize {
                for _ in 0..20 {
                    let s: Vec<u8> = (0..len)
                        .map(|_| alphabet[(rand() as usize) % alphabet.len()])
                        .collect();
                    check(&s, base);
                }
            }
        }
    }

    /// Long runs of valid digits stress the overflow path in every base.
    #[test]
    fn long_digit_runs_vs_reference() {
        let digits: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        for base in 2..=36i32 {
            let valid = &digits[..base as usize];
            for len in [9usize, 10, 11, 32, 64] {
                let mut s: Vec<u8> = Vec::new();
                let mut state = (base as u32) << 16 | len as u32;
                for _ in 0..len {
                    state = state.wrapping_mul(1103515245).wrapping_add(12345);
                    s.push(valid[((state >> 16) as usize) % valid.len()]);
                }
                check(&s, base);
            }
        }
    }
}
