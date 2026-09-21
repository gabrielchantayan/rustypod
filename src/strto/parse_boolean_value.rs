//! `parse_boolean_value` — original: `FUN_082d0960` @ 0x082d0960 (132 bytes).
//!
//! Raw `osos.dec` establishes the exact extent `0x082d0960..0x082d09e3`;
//! the literal pool follows and the next separately linked function begins at
//! `0x082d09f0`. Decoding the body finds **3 unconditional `bl` calls**, no
//! predicated `bl` calls, and one `beq` tail branch to `atoi_dead_sign`.
//!
//! The parser accepts the case-insensitive tokens `on`, `no`, `off`, `false`,
//! `yes`, `true`, and `full`, returning respectively 1, 0, 0, 0, 1, 1, and 2.
//! Its compact retail table overlaps those spellings in `"onoffalseyestruefull"`.
//! A first byte whose CTYPE entry is exactly `0x20` tail-calls
//! `atoi_dead_sign`; in the retail ASCII CTYPE table these are decimal digits.
//! There are no NULL or bounds guards. Deliberate deviation: the fixed CTYPE
//! table lookup is expressed as its verified ASCII-digit equivalent.

const TOKEN_OFFSETS: [usize; 7] = [0, 1, 2, 4, 9, 12, 16];
const TOKEN_LENGTHS: [usize; 7] = [2, 2, 3, 5, 3, 4, 4];
const TOKEN_VALUES: [u32; 7] = [1, 0, 0, 0, 1, 1, 2];
const TOKENS: &[u8] = b"onoffalseyestruefull";

/// Parse a retailOS boolean/configuration token from NUL-terminated `input`.
///
/// Decimal-leading input follows the stock tail path through
/// [`crate::strto::atoi_dead_sign`]. All other input is compared against the
/// seven overlapping case-insensitive token spellings; unknown input returns 1.
///
/// # Safety
/// `input` must point to readable NUL-terminated storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_boolean_value(input: *const u8) -> u32 {
    let first = unsafe { input.read() };
    if first.wrapping_sub(b'0') <= 9 {
        return unsafe { crate::strto::atoi_dead_sign::atoi_dead_sign(input) as u32 };
    }

    let input_length = unsafe { crate::libc::strlen::strlen(input) };
    for index in 0..TOKEN_VALUES.len() {
        let length = TOKEN_LENGTHS[index];
        if input_length != length {
            continue;
        }
        let token = &TOKENS[TOKEN_OFFSETS[index]..TOKEN_OFFSETS[index] + length];
        let mut offset = 0;
        while offset < length {
            let byte = unsafe { input.add(offset).read() };
            if byte == 0 || byte.to_ascii_lowercase() != token[offset] {
                break;
            }
            offset += 1;
        }
        if offset == length {
            return TOKEN_VALUES[index];
        }
    }

    1
}

#[cfg(test)]
mod tests {
    use super::parse_boolean_value;

    #[test]
    fn accepts_all_overlapping_tokens_case_insensitively() {
        for (input, expected) in [
            (b"on\0".as_slice(), 1),
            (b"NO\0".as_slice(), 0),
            (b"Off\0".as_slice(), 0),
            (b"FALSE\0".as_slice(), 0),
            (b"yes\0".as_slice(), 1),
            (b"TrUe\0".as_slice(), 1),
            (b"full\0".as_slice(), 2),
        ] {
            assert_eq!(unsafe { parse_boolean_value(input.as_ptr()) }, expected);
        }
    }

    #[test]
    fn rejects_prefixes_suffixes_and_unknown_tokens() {
        for input in [b"\0".as_slice(), b"o\0", b"only\0", b"truth\0", b"FULLY\0"] {
            assert_eq!(unsafe { parse_boolean_value(input.as_ptr()) }, 1);
        }
    }

    #[test]
    fn digit_leading_input_uses_dead_sign_atoi_path() {
        assert_eq!(unsafe { parse_boolean_value(b"123x\0".as_ptr()) }, 123);
        assert_eq!(unsafe { parse_boolean_value(b"2x\0".as_ptr()) }, 2);
        assert_eq!(unsafe { parse_boolean_value(b"-12\0".as_ptr()) }, 1);
    }
}
