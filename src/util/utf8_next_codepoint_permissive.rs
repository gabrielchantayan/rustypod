//! Permissive three-byte UTF-8 codepoint decoder.
//!
//! `utf8_next_codepoint_permissive` — original: `FUN_0807a0c8` @
//! **0x0807a0c8** (116 bytes, 0x0807a0c8..0x0807a13c; all code, followed by
//! the distinct next entry). A complete raw ARM B/BL scan finds **17 direct
//! call sites**: 14 plain `bl` instructions and three `blcc` instructions at
//! 0x08263010, 0x08263cec, and 0x0826400c.
//!
//! The decoder consumes one byte unconditionally. ASCII returns unchanged.
//! `0b110xxxxx` leads consume two bytes and `0b1110xxxx` leads consume three,
//! assembling their payload bits without checking continuation-byte form,
//! overlong encodings, or surrogates. Every other high-bit lead, including a
//! four-byte UTF-8 lead, consumes three bytes and returns zero. The ARM has no
//! NULL or bounds guard, so this port preserves its requirement that `cursor`
//! and every byte it reads are valid. No deliberate deviations.

/// Decode the codepoint at `*cursor`, advancing through at most three bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.utf8_next_codepoint_permissive_0807a0c8")]
#[inline(never)]
pub unsafe extern "C" fn utf8_next_codepoint_permissive(cursor: *mut *const u8) -> u32 {
    let sequence = *cursor;
    *cursor = sequence.add(1);

    let lead = *sequence as u32;
    if lead & 0x80 == 0 {
        return lead;
    }

    *cursor = sequence.add(2);
    let second_byte = *sequence.add(1) as u32;
    if lead & 0xe0 == 0xc0 {
        return second_byte & 0x3f | (lead & 0x1f) << 6;
    }

    *cursor = sequence.add(3);
    if lead & 0xf0 == 0xe0 {
        return (lead & 0x0f) << 12
            | (second_byte & 0x3f) << 6
            | (*sequence.add(2) as u32 & 0x3f);
    }

    0
}

#[cfg(test)]
mod tests {
    use super::utf8_next_codepoint_permissive;

    fn decode_next(bytes: &[u8]) -> (u32, usize) {
        let start = bytes.as_ptr();
        let mut cursor = start;
        let codepoint = unsafe { utf8_next_codepoint_permissive(&mut cursor) };
        let consumed = unsafe { cursor.offset_from(start) as usize };
        (codepoint, consumed)
    }

    #[test]
    fn consumes_one_ascii_byte_including_nul() {
        assert_eq!(decode_next(&[0]), (0, 1));
        assert_eq!(decode_next(&[0x7f]), (0x7f, 1));
    }

    #[test]
    fn decodes_two_bytes_without_validating_continuation() {
        assert_eq!(decode_next(&[0xc2, 0xa2]), (0x00a2, 2));
        assert_eq!(decode_next(&[0xdf, 0xff]), (0x07ff, 2));
    }

    #[test]
    fn decodes_three_bytes_without_validating_continuations() {
        assert_eq!(decode_next(&[0xe2, 0x82, 0xac]), (0x20ac, 3));
        assert_eq!(decode_next(&[0xef, 0xff, 0x80]), (0xffc0, 3));
    }

    #[test]
    fn unsupported_high_bit_leads_consume_three_bytes_and_return_zero() {
        for bytes in [
            [0x80, 0xaa, 0xbb],
            [0xbf, 0xaa, 0xbb],
            [0xf0, 0x9f, 0x92],
            [0xff, 0xaa, 0xbb],
        ] {
            assert_eq!(decode_next(&bytes), (0, 3), "lead byte {:#04x}", bytes[0]);
        }
    }
}
