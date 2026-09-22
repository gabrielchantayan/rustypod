//! Base64 character-to-value decoder.
//!
//! `base64_char_value` — original: `FUN_08274404` @ `0x08274404`, 84 bytes
//! (`0x08274404..0x08274457`). The next independently linked function begins
//! at `0x08274458`. Raw A32 decoding establishes three direct inbound plain
//! `bl` calls (`0x0812e948`, `0x081b1db4`, `0x082744a4`) and no predicated
//! `bl` calls.
//!
//! Maps ASCII Base64 alphabet characters to their six-bit values: uppercase
//! letters, lowercase letters, digits, `+`, and `/`; all other input words
//! yield `0xff`.
//!
//! # Deliberate deviations
//!
//! None.

/// Maps an ASCII Base64 character code to its six-bit value, or `0xff`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn base64_char_value(char_code: u32) -> u8 {
    if char_code.wrapping_sub(b'A' as u32) < 26 {
        char_code.wrapping_sub(b'A' as u32) as u8
    } else if char_code.wrapping_sub(b'a' as u32) < 26 {
        char_code.wrapping_sub(b'a' as u32).wrapping_add(26) as u8
    } else if char_code.wrapping_sub(b'0' as u32) < 10 {
        char_code.wrapping_sub(b'0' as u32).wrapping_add(52) as u8
    } else if char_code == b'+' as u32 {
        62
    } else if char_code == b'/' as u32 {
        63
    } else {
        0xff
    }
}

#[cfg(test)]
mod tests {
    use super::base64_char_value;

    #[test]
    fn maps_every_base64_alphabet_boundary() {
        assert_eq!(base64_char_value(b'A' as u32), 0);
        assert_eq!(base64_char_value(b'Z' as u32), 25);
        assert_eq!(base64_char_value(b'a' as u32), 26);
        assert_eq!(base64_char_value(b'z' as u32), 51);
        assert_eq!(base64_char_value(b'0' as u32), 52);
        assert_eq!(base64_char_value(b'9' as u32), 61);
        assert_eq!(base64_char_value(b'+' as u32), 62);
        assert_eq!(base64_char_value(b'/' as u32), 63);
    }

    #[test]
    fn rejects_gaps_and_non_ascii_words() {
        for char_code in [b'@' as u32, b'[' as u32, b'`' as u32, b'{' as u32, b'-' as u32, u32::MAX] {
            assert_eq!(base64_char_value(char_code), 0xff, "{char_code:#x}");
        }
    }
}
