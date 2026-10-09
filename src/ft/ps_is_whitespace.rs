//! `ps_is_whitespace` — original: `FUN_080ef4e8` @ `0x080ef4e8`.
//! True extent: **36 bytes**, `[0x080ef4e8, 0x080ef50c)`; BX LR at
//! 0x080ef508 precedes the next function's PUSH. Whole-image A32 decoding
//! verifies two incoming plain BLs (0x0808a634, 0x080a2afc), zero incoming
//! predicated BLs, and zero outgoing BLs of either kind.
//!
//! Compare the full input word against PostScript whitespace: space, TAB,
//! CR, LF, FF, and NUL. Return exactly one for a match, zero otherwise.
//! Type 1 encoding and charstring dictionary parsers use this predicate
//! after `def` and `end` to distinguish keywords from longer tokens.
//!
//! Deliberate deviations: none semantically; LLVM emits an unsigned bound
//! check and a 33-entry jump table instead of ADS's predicated comparisons.

/// Classifies a full word without truncating it to a byte.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ps_is_whitespace(character: u32) -> u32 {
    u32::from(matches!(character, 0x20 | 0x09 | 0x0d | 0x0a | 0x0c | 0))
}

#[cfg(test)]
mod tests {
    use super::ps_is_whitespace;

    #[test]
    fn classifies_every_byte_including_nul_and_vertical_tab() {
        let whitespace = [0, 9, 10, 12, 13, 32];
        for character in 0..=255 {
            assert_eq!(ps_is_whitespace(character), u32::from(whitespace.contains(&character)),
                "character {character:#x}");
        }
    }

    #[test]
    fn does_not_truncate_wide_or_negative_input_words() {
        for character in [0x100, 0x109, 0x10a, 0x10c, 0x10d, 0x120,
            0x10000, 0x80000000, 0xffffff09, u32::MAX] {
            assert_eq!(ps_is_whitespace(character), 0, "character {character:#x}");
        }
    }
}
