//! `parse_i32_decimal` — original: `FUN_080e7904` @ 0x080e7904 (108 bytes,
//! 0x080e7904..0x080e796c; the next real function begins at 0x080e7970).
//!
//! Verified call count: four incoming plain `bl` call sites and no predicated
//! incoming calls; decoding the 27 body words finds no `bl` instructions.
//!
//! Algorithm: skip only space, tab, and LF; consume one optional sign; then
//! accumulate leading decimal digits as `value = value * 10 + digit`. All
//! arithmetic wraps modulo 2^32, and a leading minus wraps the final negate.
//!
//! Deliberate deviations: none.

/// Parse a NUL-terminated decimal string into a wrapping signed i32.
///
/// # Safety
///
/// `text` must point to readable, NUL-terminated storage. As in retailOS,
/// there is no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_i32_decimal(text: *const u8) -> i32 {
    let mut cursor = text;
    loop {
        let byte = cursor.read();
        if byte != b' ' && byte != b'\t' && byte != b'\n' {
            break;
        }
        cursor = cursor.add(1);
    }

    let negative = if cursor.read() == b'-' {
        cursor = cursor.add(1);
        true
    } else {
        if cursor.read() == b'+' {
            cursor = cursor.add(1);
        }
        false
    };

    let mut value = 0i32;
    loop {
        let digit = cursor.read().wrapping_sub(b'0');
        if digit > 9 {
            break;
        }
        value = value.wrapping_mul(10).wrapping_add(i32::from(digit));
        cursor = cursor.add(1);
    }
    if negative { value.wrapping_neg() } else { value }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// A model with a u64 accumulator, deliberately independent of the port's
    /// pointer walk and i32 arithmetic.
    fn reference(text: &[u8]) -> i32 {
        let mut index = 0;
        while matches!(text.get(index), Some(b' ' | b'\t' | b'\n')) {
            index += 1;
        }
        let negative = match text.get(index) {
            Some(b'-') => {
                index += 1;
                true
            }
            Some(b'+') => {
                index += 1;
                false
            }
            _ => false,
        };
        let mut value = 0u64;
        while let Some(&byte) = text.get(index) {
            if !(b'0'..=b'9').contains(&byte) {
                break;
            }
            value = (value * 10 + u64::from(byte - b'0')) & u64::from(u32::MAX);
            index += 1;
        }
        let value = value as u32 as i32;
        if negative { value.wrapping_neg() } else { value }
    }

    fn run(text: &[u8]) -> i32 {
        let mut input = Vec::from(text);
        input.push(0);
        unsafe { parse_i32_decimal(input.as_ptr()) }
    }

    fn check(text: &[u8]) {
        assert_eq!(run(text), reference(text), "input {text:?}");
    }

    #[test]
    fn whitespace_and_sign_are_intentionally_narrow() {
        check(b"");
        check(b" \t\n+42");
        check(b" \t\n-42");
        check(b"\r42");
        check(b"\x0b42");
        check(b"--42");
        check(b"+-42");
        check(b"+ 42");
    }

    #[test]
    fn decimal_boundaries_and_terminators() {
        check(b"0");
        check(b"000123");
        check(b"2147483647");
        check(b"2147483648");
        check(b"-2147483648");
        check(b"12x34");
        check(b"9.5");
        for byte in u8::MIN..=u8::MAX {
            check(&[byte]);
            check(&[b'7', byte, b'9']);
        }
    }

    #[test]
    fn overflow_wraps_before_optional_negation() {
        assert_eq!(run(b"4294967296"), 0);
        assert_eq!(run(b"-4294967296"), 0);
        assert_eq!(run(b"4294967295"), -1);
        assert_eq!(run(b"-4294967295"), 1);
        check(b"999999999999999999999999999999");
    }
}
