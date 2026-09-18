//! `xml_is_whitespace` — original: `FUN_081d6204` @ `0x081d6204`
//! (**28 bytes**, `0x081d6204..0x081d621f`; the next real function begins at
//! `0x081d6220` with `push {r4, r5, r6, lr}`). Decoding every A32 B/BL word
//! in osos.dec finds four plain unconditional `bl` call sites
//! (`0x0818bffc`, `0x0818c11c`, `0x0818c408`, and `0x08235920`) and no
//! predicated forms.
//!
//! Compares a codepoint against XML's four ASCII whitespace codepoints:
//! U+0020, U+0009, U+000D, and U+000A. It returns one for a match and zero
//! otherwise.
//!
//! ## Deliberate deviations
//!
//! None.

/// Returns whether `codepoint` is one of XML's four whitespace codepoints.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn xml_is_whitespace(codepoint: u32) -> u32 {
    u32::from(matches!(codepoint, 0x20 | 0x09 | 0x0d | 0x0a))
}

#[cfg(test)]
mod tests {
    use super::xml_is_whitespace;

    fn reference_xml_is_whitespace(codepoint: u32) -> u32 {
        u32::from(codepoint == 0x20 || codepoint == 0x09 || codepoint == 0x0d || codepoint == 0x0a)
    }

    #[test]
    fn recognizes_only_the_four_xml_ascii_whitespace_codepoints() {
        for codepoint in 0..=0xff {
            assert_eq!(xml_is_whitespace(codepoint), reference_xml_is_whitespace(codepoint), "codepoint {codepoint:#x}");
        }
    }

    #[test]
    fn rejects_non_ascii_and_out_of_range_values() {
        for codepoint in [0x00, 0x0b, 0x0c, 0x21, 0x85, 0xa0, 0x100, 0xffff, u32::MAX] {
            assert_eq!(xml_is_whitespace(codepoint), 0, "codepoint {codepoint:#x}");
        }
    }
}
