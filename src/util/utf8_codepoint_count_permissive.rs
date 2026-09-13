//! Count codepoints in a permissive three-byte UTF-8 C string.
//!
//! `utf8_codepoint_count_permissive` — original: `FUN_080f0048` @
//! **0x080f0048** (72 bytes, 0x080f0048..0x080f008c; all code). The raw next
//! entry starts with `push {r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}` at
//! 0x080f0090. A whole-image ARM B/BL-immediate scan finds **seven direct
//! inbound call sites**, all unconditional `bl`: 0x0808f54c, 0x08187a08,
//! 0x082631c8, 0x08263408, 0x08263930, 0x08263e9c, and 0x0826406c; there are
//! no predicated forms.
//!
//! Algorithm: scan until a NUL byte. ASCII and `0xc0..=0xdf` lead bytes each
//! add one; `0xe0..=0xef` lead bytes also add one after consuming two following
//! bytes. Other high-bit leads consume two following bytes and add nothing.
//! Continuation-byte form, overlong encodings, and surrogates are not checked.
//! The ARM has no NULL or bounds guard: every high-bit lead reads enough bytes
//! to form a three-byte window, potentially past the terminator. No deliberate
//! deviations.

/// Counts the recognized one-, two-, and three-byte codepoints in `text`.
///
/// `text` must be non-NULL, NUL-terminated, and readable through the two bytes
/// following every high-bit lead byte, matching the retail routine's unchecked
/// reads.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.utf8_codepoint_count_permissive_080f0048")]
#[inline(never)]
pub unsafe extern "C" fn utf8_codepoint_count_permissive(mut text: *const u8) -> u32 {
    let mut count = 0u32;

    loop {
        let lead = unsafe { text.read() };
        text = unsafe { text.add(1) };
        if lead == 0 {
            return count;
        }

        if lead & 0x80 == 0 {
            count = count.wrapping_add(1);
            continue;
        }

        text = unsafe { text.add(1) };
        if lead & 0xe0 == 0xc0 {
            count = count.wrapping_add(1);
            continue;
        }

        text = unsafe { text.add(1) };
        if lead & 0xf0 == 0xe0 {
            count = count.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::utf8_codepoint_count_permissive;

    fn count(bytes: &[u8]) -> u32 {
        unsafe { utf8_codepoint_count_permissive(bytes.as_ptr()) }
    }

    #[test]
    fn counts_empty_and_ascii_c_strings() {
        assert_eq!(count(b"\0"), 0);
        assert_eq!(count(b"iPod Classic\0"), 12);
    }

    #[test]
    fn counts_one_two_and_three_byte_sequences() {
        assert_eq!(count(&[b'A', 0xc2, 0xa2, 0xe2, 0x82, 0xac, b'Z', 0]), 4);
        assert_eq!(count(&[0xdf, 0xff, 0xef, 0xff, 0x80, 0]), 2);
    }

    #[test]
    fn accepts_malformed_continuations_without_validation() {
        assert_eq!(count(&[0xc2, b'A', 0xe2, b'B', b'C', 0]), 2);
    }

    #[test]
    fn skips_unsupported_high_bit_leads_as_three_byte_windows() {
        assert_eq!(count(&[0x80, 0xaa, 0xbb, b'A', 0]), 1);
        assert_eq!(count(&[0xbf, 0xaa, 0xbb, b'A', 0]), 1);
        assert_eq!(count(&[0xf0, 0xaa, 0xbb, b'A', 0]), 1);
        assert_eq!(count(&[0xff, 0xaa, 0xbb, b'A', 0]), 1);
    }
}
