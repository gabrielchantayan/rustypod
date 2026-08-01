//! atoi_decimal — original: `FUN_080e9974` @ 0x080e9974 (44 bytes).
//!
//! Algorithm: a minimal decimal atoi. Starting with a zero signed i32 accumulator,
//! read bytes while `(byte - '0') <= 9` (unsigned comparison, so any byte
//! outside '0'..='9' stops the loop) and accumulate
//! `acc = acc * 10 + (byte - '0')`. The original computes this as
//! `acc = byte + (acc + acc*4) * 2 - 0x30`; the ARM arithmetic wraps mod 2^32
//! with no overflow detection. No whitespace skip, no sign handling, no
//! endptr. NUL is non-digit, so any C string terminates the loop.
//!
//! Reachability: six `bl` call sites, all inside `FUN_08056d70` @
//! 0x08056d70, which parses a space-separated line of six decimal fields
//! (fetched via FUN_080e6564) into a struct at offsets 0x11c..0x128 plus
//! two stack locals. It is a bespoke field parser, not the libc `atoi`
//! (that one is the ADS strtol wrapper @ 0x0802f990).
//!
//! Rust expresses the ARM shift-add sequence with wrapping i32 multiply/add,
//! preserving its signed 32-bit return bit pattern after every overflow.

/// Port of `FUN_080e9974` @ 0x080e9974: parse leading decimal digits of
/// the NUL-terminated string `s` into a wrapping signed i32 accumulator.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn atoi_decimal(s: *const u8) -> i32 {
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
    acc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Independent reference implementation. It uses a wider accumulator
    /// reduced after each decimal step, rather than the port's wrapping i32
    /// arithmetic, and then reinterprets the final 32-bit result as signed.
    fn ref_atoi_decimal(s: &[u8]) -> i32 {
        let mut acc: u64 = 0;
        for &byte in s {
            if !(b'0'..=b'9').contains(&byte) {
                break;
            }
            acc = (acc * 10 + u64::from(byte - b'0')) & u64::from(u32::MAX);
        }
        acc as u32 as i32
    }

    /// Run the port on a NUL-terminated copy of `s`.
    fn run(s: &[u8]) -> i32 {
        let mut buf: Vec<u8> = s.to_vec();
        buf.push(0);
        unsafe { atoi_decimal(buf.as_ptr()) }
    }

    fn check(s: &[u8]) {
        assert_eq!(run(s), ref_atoi_decimal(s), "input {s:?}");
    }

    #[test]
    fn empty_and_non_digit_first() {
        assert_eq!(run(b""), 0); // NUL first byte: no digits
        check(b"abc");
        check(b" 42"); // no whitespace skip
        check(b"-42"); // no sign handling
        check(b"+42");
        check(b"/"); // 0x2f, just below '0'
        check(b":"); // 0x3a, just above '9'
        check(b"\xff\xff");
    }

    #[test]
    fn every_byte_uses_the_unsigned_decimal_range() {
        for byte in u8::MIN..=u8::MAX {
            check(&[byte]);
            check(&[b'7', byte, b'9']);
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
        assert_eq!(run(b"2147483648"), i32::MIN);
        assert_eq!(run(b"4294967295"), -1);
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
        // No saturation: the accumulator wraps mod 2^32.
        assert_eq!(run(b"4294967296"), 0); // 2^32
        assert_eq!(run(b"4294967297"), 1);
        assert_eq!(run(b"9999999999"), 9999999999u64 as u32 as i32);
        check(b"4294967296");
        check(b"4294967297");
        check(b"99999999999999999999");
        check(b"18446744073709551615");
        check(b"00000000004294967296"); // leading zeros don't dodge the wrap
    }

    /// Pseudo-random byte strings, heavy on digits, vs the reference.
    #[test]
    fn random_vs_reference() {
        let mut state: u32 = 0xdeadbeef;
        let mut rand = move || {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        };
        let alphabet: &[u8] = b"01234567890123456789/: a.-\xff\x01";
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
