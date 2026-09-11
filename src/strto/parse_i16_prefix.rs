//! parse_i16_prefix — original: `FUN_080f3d3c` @ 0x080f3d3c (200 bytes).
//!
//! Raw decoding gives a 184-byte instruction body followed by its 16-byte
//! literal pool; the distinct next entry starts at 0x080f3e04. The function
//! has nine direct `bl` call sites, all unconditional (zero predicated calls):
//! five at 0x08098a3c..0x08098cf8 and four at 0x080a07f8..0x080a0840.
//!
//! Algorithm: reject a NULL or empty string; consume an optional leading '-';
//! select radix 8 or 16 only when requested (every other value means 10); and
//! unconditionally recognize a `0x`/`0X` prefix as hexadecimal. It accumulates
//! each accepted ASCII digit into a signed 16-bit value, truncating after every
//! multiply-add, stores the stopping cursor when supplied, then negates the
//! final 16-bit result for a leading '-'. It neither skips whitespace nor
//! accepts '+'.
//!
//! Deviation: the raw body indexes three digit bitmaps and one digit-value map
//! at 0x0890c464, 0x0890c4a4, 0x0890c484, and 0x0890c3e4. Those image locations
//! are zero-filled runtime storage in `osos.dec`; their initializer was not
//! identifiable from this leaf. This port expresses the implied C-locale ASCII
//! sets directly: `0..7`, `0..9`, and `0..9` plus `A..F`/`a..f`.

/// Parse the maximal signed 16-bit integer prefix of a NUL-terminated string.
///
/// Port of `FUN_080f3d3c` @ 0x080f3d3c. `endptr` receives the first byte not
/// accepted as a digit, except that NULL and empty inputs leave it untouched.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_i16_prefix(s: *const u8, endptr: *mut *mut u8, base: i32) -> i32 {
    if s.is_null() || s.read() == 0 {
        return 0;
    }

    let mut cursor = s;
    let negative = cursor.read() == b'-';
    if negative {
        cursor = cursor.add(1);
    }

    let mut radix: i16 = match base {
        8 => 8,
        16 => 16,
        _ => 10,
    };
    if cursor.read() == b'0' && matches!(cursor.add(1).read(), b'x' | b'X') {
        radix = 16;
        cursor = cursor.add(2);
    }

    let mut value: i16 = 0;
    while let Some(digit) = digit_for_radix(cursor.read(), radix) {
        cursor = cursor.add(1);
        value = value.wrapping_mul(radix).wrapping_add(digit);
    }

    if !endptr.is_null() {
        endptr.write(cursor as *mut u8);
    }
    if negative {
        value = value.wrapping_neg();
    }
    value as i32
}

#[inline(always)]
fn digit_for_radix(byte: u8, radix: i16) -> Option<i16> {
    let digit = match byte {
        b'0'..=b'9' => (byte - b'0') as i16,
        b'A'..=b'F' => (byte - b'A' + 10) as i16,
        b'a'..=b'f' => (byte - b'a' + 10) as i16,
        _ => return None,
    };
    (digit < radix).then_some(digit)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::vec::Vec;

    fn run(s: &[u8], base: i32) -> (i32, usize) {
        let mut input = Vec::from(s);
        input.push(0);
        let mut end = ptr::null_mut();
        let value = unsafe { parse_i16_prefix(input.as_ptr(), &mut end, base) };
        (value, unsafe { end.offset_from(input.as_mut_ptr()) } as usize)
    }

    #[test]
    fn accepts_only_leading_ascii_digits_for_the_selected_radix() {
        assert_eq!(run(b"123stop", 10), (123, 3));
        assert_eq!(run(b"1278", 8), (87, 3));
        assert_eq!(run(b"aFz", 16), (175, 2));
        assert_eq!(run(b"A", 10), (0, 0));
        assert_eq!(run(b"+12", 10), (0, 0));
        assert_eq!(run(b" 12", 10), (0, 0));
    }

    #[test]
    fn normalizes_unknown_bases_but_always_consumes_hex_prefixes() {
        assert_eq!(run(b"19", 0), (19, 2));
        assert_eq!(run(b"19", 2), (19, 2));
        assert_eq!(run(b"0x1fZ", 8), (31, 4));
        assert_eq!(run(b"0X2A", 10), (42, 4));
        assert_eq!(run(b"0x", 10), (0, 2));
    }

    #[test]
    fn sign_and_every_step_i16_truncation_match_arm_register_shifts() {
        assert_eq!(run(b"-32768", 10), (-32768, 6));
        assert_eq!(run(b"32768", 10), (-32768, 5));
        assert_eq!(run(b"400000", 10), (6784, 6));
        assert_eq!(run(b"-400000", 10), (-6784, 7));
        assert_eq!(run(b"-", 10), (0, 1));
    }

    #[test]
    fn null_or_empty_input_leaves_endptr_untouched() {
        let sentinel = 1usize as *mut u8;
        let mut end = sentinel;
        assert_eq!(unsafe { parse_i16_prefix(ptr::null(), &mut end, 10) }, 0);
        assert_eq!(end, sentinel);

        let input = [0u8];
        assert_eq!(unsafe { parse_i16_prefix(input.as_ptr(), &mut end, 10) }, 0);
        assert_eq!(end, sentinel);
    }

    #[test]
    fn permits_a_null_endptr() {
        let input = [b'4', b'2', 0];
        assert_eq!(unsafe { parse_i16_prefix(input.as_ptr(), ptr::null_mut(), 10) }, 42);
    }
}
