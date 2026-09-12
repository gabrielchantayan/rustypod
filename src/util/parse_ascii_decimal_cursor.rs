//! `parse_ascii_decimal_cursor` — the cursor-advancing ASCII decimal reader.
//!
//! Original: `FUN_082d0ab4` at load address **0x082d0ab4**, 52 bytes
//! (`0x082d0ab4..0x082d0ae7`; the separate `ata_error_record` entry begins
//! at `0x082d0ae8`). Binary-decoding every ARM B/BL word in `osos.dec` finds
//! **7 direct `bl` call sites**, all unconditional, with no predicated calls
//! or tail branches.
//!
//! It reads consecutive ASCII `0` through `9` bytes from `*cursor`, computes
//! their unsigned base-10 value modulo 2^32, and stores the first non-digit
//! address back to `*cursor`. The raw `sub r3,r2,#0x30; cmp r3,#9` is an
//! unsigned range test, so every byte outside that exact range, including
//! high-bit bytes, terminates parsing. There is no NULL guard for either
//! pointer. Deliberate deviations: none.

/// `parse_ascii_decimal_cursor` — original `FUN_082d0ab4` at 0x082d0ab4.
///
/// # Safety
/// `cursor` must point to one readable/writable pointer word, and `*cursor`
/// must point to readable storage ending in a non-ASCII-decimal byte.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_ascii_decimal_cursor(cursor: *mut *const u8) -> u32 {
    let mut input = unsafe { cursor.read() };
    let mut value = 0u32;

    loop {
        let byte = unsafe { input.read() };
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            break;
        }
        value = value.wrapping_mul(10).wrapping_add(digit as u32);
        input = unsafe { input.add(1) };
    }

    unsafe { cursor.write(input) };
    value
}

#[cfg(test)]
mod tests {
    use super::parse_ascii_decimal_cursor;

    #[test]
    fn consumes_digits_and_stops_at_first_non_digit() {
        let text = b"12345x\0";
        let mut cursor = text.as_ptr();

        let value = unsafe { parse_ascii_decimal_cursor(&mut cursor) };

        assert_eq!(value, 12_345);
        assert_eq!(unsafe { cursor.read() }, b'x');
        assert_eq!(cursor as usize - text.as_ptr() as usize, 5);
    }

    #[test]
    fn preserves_cursor_when_first_byte_is_not_ascii_decimal() {
        for text in [b"x12\0".as_slice(), b"\xff12\0".as_slice(), b"\0".as_slice()] {
            let mut cursor = text.as_ptr();
            assert_eq!(unsafe { parse_ascii_decimal_cursor(&mut cursor) }, 0);
            assert_eq!(cursor, text.as_ptr());
        }
    }

    #[test]
    fn accepts_zeroes_and_wraps_overflow_at_u32_width() {
        let text = b"0004294967296!\0";
        let mut cursor = text.as_ptr();

        assert_eq!(unsafe { parse_ascii_decimal_cursor(&mut cursor) }, 0);
        assert_eq!(unsafe { cursor.read() }, b'!');
        assert_eq!(cursor as usize - text.as_ptr() as usize, 13);
    }
}
