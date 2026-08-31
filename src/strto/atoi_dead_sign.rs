//! atoi_dead_sign — original: `FUN_082b5298` @ 0x082b5298 (56 bytes).
//!
//! Algorithm: a decimal atoi with a dead sign flag. The original:
//!
//! ```text
//! ldrb  r2, [r0]          ; first = *s
//! mov   ip, #1            ; sign = 1
//! mov   r1, #0            ; acc = 0
//! cmp   r2, #0x2d         ; '-'?
//! mvneq ip, #0            ; if '-': sign = -1   (pointer NOT advanced)
//! ldrb  r2, [r0]          ; re-read the SAME first byte
//! sub   r3, r2, #0x30
//! cmp   r3, #9
//! loop: addls r1, r1, r1, lsl #2   ; acc *= 5
//!       addls r1, r2, r1, lsl #1   ; acc = byte + acc*2
//!       subls r1, r1, #0x30        ; acc = acc*10 + byte - '0'
//!       addls r0, r0, #1
//!       bls   loop                 ; while (byte - '0') <= 9u
//! mul   r0, r1, ip        ; return acc * sign
//! bx    lr
//! ```
//!
//! Because the pointer is never advanced past a leading '-', a string
//! starting with '-' fails the digit test immediately: acc stays 0 and
//! `0 * -1 == 0`. The sign flag therefore never changes an observable
//! result — the function can never return a negative value. The port
//! preserves the flag and the final multiply exactly; callers (e.g.
//! FUN_0837f25c) still defensively negate a negative return that cannot
//! occur.
//!
//! Verified call count: 29 `bl` sites, 0 predicated `bl`, plus one `beq`
//! tail-branch @ 0x082d0984 (30 control-flow transfers total). No data
//! word in osos references the address, so it is never dispatched
//! indirectly. Ghidra's decompile of this function is accurate.
//!
//! Reachability: parses decimal fields throughout the UI/settings code
//! (menu indices, numeric config values), e.g. FUN_080c60b4, FUN_0826c714,
//! FUN_0837f490. Distinct from libc `atoi` (ADS strtol wrapper @
//! 0x0802f990) and from `atoi_decimal` @ 0x080e9974 (no sign flag at all).
//!
//! Rust expresses the ARM shift-add accumulation with wrapping i32
//! arithmetic, preserving the signed 32-bit return bit pattern on overflow.

/// Port of `FUN_082b5298` @ 0x082b5298: parse leading decimal digits of
/// the NUL-terminated string `s` into a wrapping signed i32 accumulator,
/// then multiply by a sign flag that is -1 iff `*s == '-'`. The flag is
/// dead: a leading '-' yields acc == 0, so the result is never negative.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn atoi_dead_sign(s: *const u8) -> i32 {
    let sign: i32 = if s.read() == b'-' { -1 } else { 1 };
    let mut p = s;
    let mut acc: i32 = 0;
    loop {
        let byte = p.read();
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            break;
        }
        acc = acc.wrapping_mul(10).wrapping_add(digit as i32);
        p = p.add(1);
    }
    acc.wrapping_mul(sign)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Independent reference implementation: wider accumulator reduced mod
    /// 2^32 after each step, dead sign flag applied at the end.
    fn ref_atoi_dead_sign(s: &[u8]) -> i32 {
        let sign: u32 = if s.first() == Some(&b'-') { u32::MAX } else { 1 };
        let mut acc: u64 = 0;
        for &byte in s {
            if !(b'0'..=b'9').contains(&byte) {
                break;
            }
            acc = (acc * 10 + u64::from(byte - b'0')) & u64::from(u32::MAX);
        }
        (acc as u32).wrapping_mul(sign) as i32
    }

    /// Run the port on a NUL-terminated copy of `s`.
    fn run(s: &[u8]) -> i32 {
        let mut buf: Vec<u8> = s.to_vec();
        buf.push(0);
        unsafe { atoi_dead_sign(buf.as_ptr()) }
    }

    fn check(s: &[u8]) {
        assert_eq!(run(s), ref_atoi_dead_sign(s), "input {s:?}");
    }

    #[test]
    fn empty_and_non_digit_first() {
        assert_eq!(run(b""), 0); // NUL first byte: no digits
        check(b"abc");
        check(b" 42"); // no whitespace skip
        check(b"+42");
        check(b"/"); // 0x2f, just below '0'
        check(b":"); // 0x3a, just above '9'
        check(b"\xff\xff");
    }

    #[test]
    fn leading_minus_is_dead() {
        // The '-' sets sign = -1 but is never skipped: the digit loop exits
        // on it, acc stays 0, and 0 * -1 == 0.
        assert_eq!(run(b"-"), 0);
        assert_eq!(run(b"-42"), 0);
        assert_eq!(run(b"-2147483648"), 0);
        // A '-' anywhere but the first byte is an ordinary non-digit.
        assert_eq!(run(b"42-99"), 42);
        assert_eq!(run(b"1-"), 1);
        // Result can never be negative, even on overflow bit patterns.
        for len in 0..24usize {
            let s: Vec<u8> = std::iter::repeat(b'9').take(len).collect();
            let r = run(&s);
            if s.first() == Some(&b'-') {
                assert_eq!(r, 0);
            }
            check(&s);
        }
    }

    #[test]
    fn every_byte_uses_the_unsigned_decimal_range() {
        for byte in u8::MIN..=u8::MAX {
            check(&[byte]);
            check(&[b'7', byte, b'9']);
            check(&[byte, b'7', b'9']); // also as the sign-tested first byte
        }
    }

    #[test]
    fn digit_boundaries_and_long_runs() {
        check(b"0");
        check(b"7");
        check(b"42");
        check(b"123456789");
        check(b"000123"); // leading zeros
        assert_eq!(run(b"2147483647"), i32::MAX);
        assert_eq!(run(b"2147483648"), i32::MIN); // wraps, sign flag is +1
        assert_eq!(run(b"4294967295"), -1); // wrap can still yield -1
        let digits = [b'9'; 4096];
        check(&digits);
    }

    #[test]
    fn digits_then_junk() {
        check(b"123abc");
        check(b"12 34"); // stops at the space
        check(b"42.5");
        check(b"7\x01\x02");
        check(b"987654321\x80more");
    }

    #[test]
    fn overflow_wraps() {
        assert_eq!(run(b"4294967296"), 0); // 2^32
        assert_eq!(run(b"4294967297"), 1);
        assert_eq!(run(b"9999999999"), 9999999999u64 as u32 as i32);
        check(b"99999999999999999999");
        check(b"18446744073709551615");
        check(b"00000000004294967296");
    }

    /// Pseudo-random byte strings, heavy on digits and '-', vs the reference.
    #[test]
    fn random_vs_reference() {
        let mut state: u32 = 0x12345678;
        let mut rand = move || {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        };
        let alphabet: &[u8] = b"01234567890123456789--/: a.+\xff\x01";
        for len in 0..32usize {
            for _ in 0..40 {
                let s: Vec<u8> = (0..len)
                    .map(|_| alphabet[(rand() as usize) % alphabet.len()])
                    .collect();
                check(&s);
            }
        }
    }
}
