//! Ports of the ARM ADS 1.0.1 signed string-to-integer family:
//!
//! - `strtol` — original: `FUN_0802f87c` @ 0x0802f87c (176 bytes), on top of
//!   the unsigned core `FUN_08033088` @ 0x08033088 and digit classifier
//!   `FUN_08032fec` @ 0x08032fec.
//! - `atoi` — original: `FUN_0802f990` @ 0x0802f990 (52 bytes), a base-10
//!   wrapper over the clamping signed core `FUN_0802f7c4`.
//! - `atol` — original: `FUN_0802fba0` @ 0x0802fba0 (52 bytes), a base-10
//!   wrapper over the 64-bit clamping core `FUN_080332d0` @ 0x080332d0
//!   (`long` is 32-bit on this target, so `atol` == `strtol(s, NULL, 10)`).
//!
//! Algorithm (all three share one core here, as the originals do): skip
//! leading whitespace (the ADS `__ctype` space bit: space, \t, \n, \v, \f,
//! \r), read an optional '+'/'-' sign, auto-detect the base when `base == 0`
//! (leading "0x"/"0X" -> 16, leading '0' -> 8, else 10; base 16 also skips an
//! optional "0x" prefix), then accumulate '0'-'9'/'a'-'z'/'A'-'Z' digits
//! (case-insensitive, digit = upper - 55 as in FUN_08032fec) until the first
//! non-digit. On overflow the result clamps to i32::MAX / i32::MIN. `endptr`,
//! when non-NULL, is set just past the last digit consumed, or to `s` itself
//! when no conversion was performed.
//!
//! Documented deviations from the originals:
//! - errno is skipped entirely. The originals save/restore the thread errno
//!   via FUN_0802ecb4 and set ERANGE (2) on overflow; our port reports
//!   overflow only through the clamped return value.
//! - The literal FUN_0802f87c returns the unsigned core's raw 32-bit result
//!   (negated for '-'), i.e. it wraps instead of clamping; the ADS wrappers
//!   behind `atoi` (FUN_0802f7c4) and `atol` (FUN_080332d0) DO clamp to
//!   LONG_MAX/LONG_MIN, as does the documented strtol contract. We clamp
//!   everywhere — the wrapping behavior of FUN_0802f87c is not reproduced.
//! - One ADS quirk is kept: "0x" (or "0X") with no following hex digit is NOT
//!   a conversion at all (the prefix consumer resets the digit flag), so
//!   strtol("0x", &e, 0/16) returns 0 with e == s, where ISO C would parse
//!   the '0' and stop at 'x'.
//! - The originals never validate `base`; we support base 0 and 2..=36.

/// strtol — original @ 0x0802f87c. See module header for the errno/clamping
/// deviations from the literal binary.
#[no_mangle]
pub unsafe extern "C" fn strtol(s: *const u8, endptr: *mut *mut u8, base: i32) -> i32 {
    parse_signed(s, endptr, base)
}

/// atoi — original @ 0x0802f990: base-10 strtol with a NULL endptr.
#[no_mangle]
pub unsafe extern "C" fn atoi(s: *const u8) -> i32 {
    parse_signed(s, core::ptr::null_mut(), 10)
}

/// atol — original @ 0x0802fba0: identical to atoi on this 32-bit target.
#[no_mangle]
pub unsafe extern "C" fn atol(s: *const u8) -> i32 {
    parse_signed(s, core::ptr::null_mut(), 10)
}

/// The ADS ctype space bit (FUN_0802eca0 table, bit 0): isspace().
#[inline]
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// Digit classifier, mirroring FUN_08032fec @ 0x08032fec:
/// '0'-'9' -> 0-9, letters case-insensitively -> 10-35, anything else -> None
/// (for bases <= 36 the original's unsigned-wrap paths all land >= base).
#[inline]
fn digit_value(c: u8, base: u32) -> Option<u32> {
    let mut d = if c < b'0' + 10 { c.wrapping_sub(b'0') } else { c } as u32;
    let upper = c & !0x20;
    if upper >= b'A' {
        d = (upper - (b'A' - 10)) as u32;
    }
    if d < base {
        Some(d)
    } else {
        None
    }
}

/// Shared signed-parse core. `base` must be 0 or 2..=36.
unsafe fn parse_signed(s: *const u8, endptr: *mut *mut u8, base: i32) -> i32 {
    let mut p = s;

    // Skip whitespace. A NUL here falls through to the (failed) sign check
    // exactly like the original: no digits are found and endptr = s.
    while is_space(*p) {
        p = p.add(1);
    }

    let mut negative = false;
    match *p {
        b'+' => p = p.add(1),
        b'-' => {
            negative = true;
            p = p.add(1);
        }
        _ => {}
    }

    // Base detection, including the optional 0x prefix for base 0/16.
    // `saw_digit` starts as the original's r7: consuming a bare leading '0'
    // for base 0 counts as a digit, consuming "0x" does not.
    let mut base = base as u32;
    let mut saw_digit = false;
    if *p == b'0' {
        let q = p.add(1);
        let c = *q;
        if (c == b'x' || c == b'X') && (base == 0 || base == 16) {
            p = q.add(1);
            base = 16;
        } else {
            saw_digit = true;
            p = q;
            if base == 0 {
                base = 8;
            }
        }
    } else if base == 0 {
        base = 10;
    }

    // Accumulate the magnitude as u32, clamping against the signed limit.
    // Like the original, we keep scanning digits after overflow so endptr
    // lands past the full digit run. cutoff/cutlim are the glibc-style
    // precomputed limit split (one division per call, not per digit).
    let limit: u32 = if negative { 0x8000_0000 } else { 0x7fff_ffff };
    let cutoff = limit / base;
    let cutlim = limit % base;
    let mut acc: u32 = 0;
    let mut overflowed = false;
    while let Some(d) = digit_value(*p, base) {
        saw_digit = true;
        if !overflowed {
            if acc > cutoff || (acc == cutoff && d > cutlim) {
                overflowed = true;
            } else {
                acc = acc * base + d;
            }
        }
        p = p.add(1);
    }

    if !endptr.is_null() {
        *endptr = if saw_digit { p } else { s } as *mut u8;
    }

    if overflowed {
        if negative {
            i32::MIN
        } else {
            i32::MAX
        }
    } else if negative {
        // acc <= 0x8000_0000, so this two's-complement negate is exact,
        // including the i32::MIN case.
        (acc as i32).wrapping_neg()
    } else {
        acc as i32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Simple reference: standard C strtol semantics (whitespace, sign, base
    /// auto-detect, i32 clamping, end offset) plus the ADS "0x"-with-no-hex-
    /// digit quirk documented in the module header.
    fn ref_strtol(s: &[u8], base: i32) -> (i32, usize) {
        let mut i = 0;
        while i < s.len() && is_space(s[i]) {
            i += 1;
        }
        let mut negative = false;
        if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
            negative = s[i] == b'-';
            i += 1;
        }
        let mut base = base;
        let mut saw_digit = false;
        if i < s.len() && s[i] == b'0' {
            if i + 1 < s.len()
                && (s[i + 1] == b'x' || s[i + 1] == b'X')
                && (base == 0 || base == 16)
            {
                i += 2;
                base = 16;
            } else {
                saw_digit = true;
                i += 1;
                if base == 0 {
                    base = 8;
                }
            }
        } else if base == 0 {
            base = 10;
        }
        let mut acc: i64 = 0;
        let mut overflowed = false;
        let limit: i64 = if negative { 0x8000_0000 } else { 0x7fff_ffff };
        while i < s.len() {
            let d = match digit_value(s[i], base as u32) {
                Some(d) => d as i64,
                None => break,
            };
            saw_digit = true;
            if !overflowed {
                if acc > (limit - d) / base as i64 {
                    overflowed = true;
                } else {
                    acc = acc * base as i64 + d;
                }
            }
            i += 1;
        }
        if !saw_digit {
            return (0, 0);
        }
        if overflowed {
            return (if negative { i32::MIN } else { i32::MAX }, i);
        }
        let value = if negative { -acc } else { acc };
        (value as i32, i)
    }

    /// Run strtol on a NUL-terminated copy of `s`; returns (value, end offset).
    fn run_strtol(s: &[u8], base: i32) -> (i32, usize) {
        let mut buf: Vec<u8> = s.to_vec();
        buf.push(0);
        let mut end: *mut u8 = core::ptr::null_mut();
        let value = unsafe { strtol(buf.as_ptr(), &mut end, base) };
        let off = unsafe { end.offset_from(buf.as_ptr()) } as usize;
        (value, off)
    }

    fn run_atoi(s: &[u8]) -> i32 {
        let mut buf: Vec<u8> = s.to_vec();
        buf.push(0);
        unsafe { atoi(buf.as_ptr()) }
    }

    fn check(s: &[u8], base: i32) {
        assert_eq!(
            run_strtol(s, base),
            ref_strtol(s, base),
            "strtol({:?}, {base})",
            core::str::from_utf8(s).unwrap_or("?")
        );
    }

    #[test]
    fn basic_positive_negative() {
        for s in [
            &b"0"[..],
            b"1",
            b"42",
            b"+42",
            b"-42",
            b"2147483647",
            b"-2147483648",
            b"0000123",
            b"-0",
            b"+0",
        ] {
            check(s, 10);
        }
    }

    #[test]
    fn clamps_both_ends() {
        for s in [
            &b"2147483648"[..],
            b"21474836470",
            b"99999999999999999999999999",
            b"-2147483649",
            b"-99999999999999999999999999",
            b"0x80000000",
            b"-0x80000001",
            b"0x7fffffff",
            b"-0x80000000",
            b"0xffffffff",
        ] {
            check(s, 0);
            check(s, 10);
            check(s, 16);
        }
    }

    #[test]
    fn base_variants() {
        for base in [0, 2, 8, 10, 16, 36] {
            for s in [
                &b"0"[..],
                b"0x1F",
                b"0X1f",
                b"017",
                b"101",
                b"-0x7f",
                b"+0XABCDEF",
                b"zz",
                b"-zz",
                b"1z9",
            ] {
                check(s, base);
            }
        }
    }

    #[test]
    fn whitespace_sign_combos() {
        for s in [
            &b" 42"[..],
            b"\t\n\x0b\x0c\r 42",
            b"  -42",
            b" +42",
            b"- 42", // sign not followed by digits: no conversion
            b"+",
            b"-",
            b"++5",
            b"--5",
            b" ",
            b"",
        ] {
            check(s, 10);
            check(s, 0);
        }
    }

    #[test]
    fn endptr_placement() {
        assert_eq!(run_strtol(b"12abc", 10), (12, 2));
        assert_eq!(run_strtol(b"12abc", 16), (0x12abc, 5));
        assert_eq!(run_strtol(b"xyz", 10), (0, 0));
        assert_eq!(run_strtol(b"  7x", 10), (7, 3));
        // ADS quirk: "0x" with no hex digit is no conversion at all.
        assert_eq!(run_strtol(b"0x", 0), (0, 0));
        assert_eq!(run_strtol(b"0x", 16), (0, 0));
        assert_eq!(run_strtol(b"-0x", 0), (0, 0));
        assert_eq!(run_strtol(b"0xg", 16), (0, 0));
        // But "0x1" parses normally, and base-10 "0x" stops after '0'.
        assert_eq!(run_strtol(b"0x1", 0), (1, 3));
        assert_eq!(run_strtol(b"0x1", 10), (0, 1));
    }

    #[test]
    fn no_digit_garbage() {
        for s in [&b"abc"[..], b"!@#", b"  xyz", b"-abc", b"+", b""] {
            assert_eq!(run_strtol(s, 10), (0, 0));
            assert_eq!(run_strtol(s, 0), (0, 0));
        }
    }

    #[test]
    fn atoi_atol_match_strtol_base10() {
        for s in [
            &b"0"[..],
            b"42",
            b"-42",
            b"  17",
            b"2147483647",
            b"2147483648",
            b"-2147483648",
            b"-2147483649",
            b"99999999999999",
            b"12abc",
            b"xyz",
            b"",
        ] {
            let mut buf: Vec<u8> = s.to_vec();
            buf.push(0);
            let (want, _) = run_strtol(s, 10);
            assert_eq!(run_atoi(s), want, "atoi({s:?})");
            assert_eq!(unsafe { atol(buf.as_ptr()) }, want, "atol({s:?})");
        }
    }

    /// LCG-fuzzed garbage strings over a tricky alphabet, all bases.
    #[test]
    fn fuzz_vs_reference() {
        const ALPHA: &[u8] = b"0123456789abcdefxzAZX+- \t\n./";
        let mut state: u32 = 0x12345678;
        let mut next = move || {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            (state >> 16) as usize
        };
        for _ in 0..20_000 {
            let len = next() % 12;
            let s: Vec<u8> = (0..len).map(|_| ALPHA[next() % ALPHA.len()]).collect();
            let base = [0, 2, 8, 10, 16, 36][next() % 6];
            assert_eq!(
                run_strtol(&s, base),
                ref_strtol(&s, base),
                "strtol({s:?}, {base})"
            );
        }
    }
}
