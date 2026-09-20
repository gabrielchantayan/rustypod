//! `parse_i32_decimal_checked` — original: `FUN_0837a28c` @ 0x0837a28c (200
//! bytes, 0x0837a28c..0x0837a354; the next real function begins at
//! 0x0837a354).
//!
//! Verified call count: three incoming unconditional plain `bl` call sites
//! and no predicated incoming calls. Decoding the 50 body words finds no `bl`
//! instructions.
//!
//! Algorithm: consume one optional sign and any following ASCII zeroes, then
//! accumulate at most ten decimal digits into a 64-bit magnitude. Accept only
//! magnitudes in the signed i32 range, with one additional unit allowed for a
//! negative sign; on success write the signed result and return one. Empty and
//! non-digit input after the prefix is accepted as zero.
//!
//! Deliberate deviations: Rust uses a u64 accumulator rather than the retail
//! carry-chain registers; the accepted inputs, output store, and return value
//! are identical.

/// Parse a signed decimal prefix if it fits in an i32.
///
/// Returns one and writes `output` on success; returns zero without writing it
/// when more than ten non-leading-zero digits occur or the value is out of
/// range.
///
/// # Safety
///
/// `text` must point to readable NUL-terminated storage and `output` must be
/// writable. As in retailOS, neither pointer is NULL-guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_i32_decimal_checked(text: *const u8, output: *mut i32) -> i32 {
    let mut cursor = text;
    let first = cursor.read();
    let negative = first == b'-';
    if negative || first == b'+' {
        cursor = cursor.add(1);
    }
    while cursor.read() == b'0' {
        cursor = cursor.add(1);
    }

    let mut digits = 0usize;
    let mut magnitude = 0u64;
    loop {
        let digit = cursor.add(digits).read().wrapping_sub(b'0');
        if digit > 9 {
            break;
        }
        magnitude = magnitude * 10 + digit as u64;
        digits += 1;
        if digits == 11 {
            return 0;
        }
    }

    let limit = if negative { 2_147_483_648 } else { 2_147_483_647 };
    if magnitude > limit {
        return 0;
    }
    output.write(if negative { (magnitude as i32).wrapping_neg() } else { magnitude as i32 });
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::parse_i32_decimal_checked;

    fn reference(text: &[u8], output: i32) -> (i32, i32) {
        let mut cursor = 0;
        let negative = text[cursor] == b'-';
        if negative || text[cursor] == b'+' {
            cursor += 1;
        }
        while text[cursor] == b'0' {
            cursor += 1;
        }
        let mut magnitude = 0u64;
        let mut digits = 0;
        while text[cursor + digits].is_ascii_digit() {
            magnitude = magnitude * 10 + (text[cursor + digits] - b'0') as u64;
            digits += 1;
            if digits == 11 {
                return (0, output);
            }
        }
        let limit = if negative { 2_147_483_648 } else { 2_147_483_647 };
        if magnitude > limit {
            (0, output)
        } else if negative {
            (1, (magnitude as i32).wrapping_neg())
        } else {
            (1, magnitude as i32)
        }
    }

    fn check(text: &[u8]) {
        let mut output = 0x1357_9bdf;
        let expected = reference(text, output);
        let result = unsafe { parse_i32_decimal_checked(text.as_ptr(), &mut output) };
        assert_eq!((result, output), expected, "input {text:?}");
    }

    #[test]
    fn accepts_signed_i32_boundaries() {
        for text in [b"2147483647\0".as_slice(), b"-2147483648\0", b"+00042\0", b"-000\0"] {
            check(text);
        }
    }

    #[test]
    fn rejects_overflow_and_eleven_significant_digits_without_writing() {
        for text in [b"2147483648\0".as_slice(), b"-2147483649\0", b"12345678901\0", b"0000000000012345678901\0"] {
            check(text);
        }
    }

    #[test]
    fn accepts_empty_and_stops_at_first_non_digit() {
        for text in [b"\0".as_slice(), b"+\0", b"-x\0", b"12x34\0", b" 42\0"] {
            check(text);
        }
    }
}
