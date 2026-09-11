//! parse_u32_prefix — original: `FUN_08074c18` @ 0x08074c18.
//!
//! Raw decoding establishes a 144-byte instruction body followed by a 16-byte
//! literal pool; the separate next entry begins at 0x08074cb8, so this entry
//! occupies 160 bytes in total. Decoding every ARM B/BL immediate finds nine
//! direct inbound calls, all unconditional `bl` (none predicated): 0x0809897c,
//! 0x08098c8c, 0x08098ca8, 0x08098cc4, 0x0809fcdc, 0x0809fe90, 0x080a0130,
//! 0x080a0700, and 0x080a075c.
//!
//! Algorithm: reject a NULL or empty string; select radix 8 or 16 only when
//! requested (every other value means 10); force a `0x`/`0X` prefix to
//! hexadecimal; then accumulate the maximal matching ASCII digit prefix with
//! wrapping 32-bit multiply-add. When supplied, the ending cursor receives
//! the first rejected byte. The function neither skips whitespace nor accepts
//! signs.
//!
//! Deviation: the raw body indexes three digit bitmaps and one digit-value map
//! at 0x0890c464, 0x0890c4a4, 0x0890c484, and 0x0890c3e4. Those locations are
//! zero-filled runtime storage in `osos.dec` and their initializer is not
//! identified. This port expresses the implied C-locale ASCII sets directly:
//! `0..7`, `0..9`, and `0..9` plus `A..F`/`a..f`.

/// Parse the maximal unsigned 32-bit integer prefix of a NUL-terminated string.
///
/// Port of `FUN_08074c18` @ 0x08074c18. `endptr` receives the first byte not
/// accepted as a digit, except that NULL and empty inputs leave it untouched.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_u32_prefix(s: *const u8, endptr: *mut *mut u8, base: i32) -> u32 {
    if s.is_null() || s.read() == 0 {
        return 0;
    }

    let mut cursor = s;
    let mut radix: u32 = match base {
        8 => 8,
        16 => 16,
        _ => 10,
    };
    if cursor.read() == b'0' && matches!(cursor.add(1).read(), b'x' | b'X') {
        radix = 16;
        cursor = cursor.add(2);
    }

    let mut value: u32 = 0;
    while let Some(digit) = digit_for_radix(cursor.read(), radix) {
        cursor = cursor.add(1);
        value = value.wrapping_mul(radix).wrapping_add(digit);
    }

    if !endptr.is_null() {
        endptr.write(cursor as *mut u8);
    }
    value
}

#[inline(always)]
fn digit_for_radix(byte: u8, radix: u32) -> Option<u32> {
    let digit = match byte {
        b'0'..=b'9' => (byte - b'0') as u32,
        b'A'..=b'F' => (byte - b'A' + 10) as u32,
        b'a'..=b'f' => (byte - b'a' + 10) as u32,
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

    fn run(s: &[u8], base: i32) -> (u32, usize) {
        let mut input = Vec::from(s);
        input.push(0);
        let mut end = ptr::null_mut();
        let value = unsafe { parse_u32_prefix(input.as_ptr(), &mut end, base) };
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
    fn wraps_after_each_32_bit_multiply_add() {
        assert_eq!(run(b"4294967295", 10), (u32::MAX, 10));
        assert_eq!(run(b"4294967296", 10), (0, 10));
        assert_eq!(run(b"100000000", 16), (0, 9));
    }

    #[test]
    fn null_or_empty_input_leaves_endptr_untouched() {
        let sentinel = 1usize as *mut u8;
        let mut end = sentinel;
        assert_eq!(unsafe { parse_u32_prefix(ptr::null(), &mut end, 10) }, 0);
        assert_eq!(end, sentinel);

        let input = [0u8];
        assert_eq!(unsafe { parse_u32_prefix(input.as_ptr(), &mut end, 10) }, 0);
        assert_eq!(end, sentinel);
    }

    #[test]
    fn permits_a_null_endptr() {
        let input = [b'4', b'2', 0];
        assert_eq!(unsafe { parse_u32_prefix(input.as_ptr(), ptr::null_mut(), 10) }, 42);
    }
}
