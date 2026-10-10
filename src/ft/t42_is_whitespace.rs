//! `t42_is_whitespace` — original: `FUN_0807d918` @ `0x0807d918`.
//! True extent: **36 bytes**, `[0x0807d918, 0x0807d93c)`; BX LR at
//! 0x0807d938 precedes the next function's PUSH. Whole-image A32 decoding
//! verifies two incoming plain BLs (0x080a9c70, 0x080c4ef4), zero incoming
//! predicated BLs, and zero outgoing BLs of either kind.
//!
//! Compare the full input word against space, TAB, CR, LF, FF, and NUL;
//! return exactly one for a match, zero otherwise. Type 42 encoding and
//! charstring parsers use this after `def` and `end` to reject longer tokens.
//! VT is deliberately excluded. No semantic deviations. Use a bounded
//! bit mask for values below space and handle space separately, keeping
//! a distinct BL target from the equivalent Type 1 predicate.

/// Classifies a full word without truncating it to a byte.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn t42_is_whitespace(character: u32) -> u32 {
    if character >= 32 {
        return u32::from(character == 32);
    }
    (0x3601u32 >> character) & 1
}

#[cfg(test)]
mod tests {
    use super::t42_is_whitespace;

    #[test]
    fn classifies_all_bytes_with_postscript_not_c_whitespace_rules() {
        let whitespace = [0, 9, 10, 12, 13, 32];
        for character in 0..=255 {
            assert_eq!(t42_is_whitespace(character), u32::from(whitespace.contains(&character)),
                "character {character:#x}");
        }
    }

    #[test]
    fn rejects_full_words_whose_low_byte_is_whitespace() {
        for character in [0x100, 0x109, 0x10a, 0x10c, 0x10d, 0x120,
            0x10000, 0x80000000, 0xffffff09, u32::MAX] {
            assert_eq!(t42_is_whitespace(character), 0, "character {character:#x}");
        }
    }
}
