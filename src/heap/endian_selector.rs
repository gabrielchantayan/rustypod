//! Port of retailOS's selector-controlled 32-bit endian transform.
//!
//! `FUN_0802bad0` at 0x0802bad0 (40 bytes) selects one of the four byte
//! rotations used by its callers: identity, one-byte right rotation,
//! halfword swap, or one-byte left rotation. The original is a leaf with
//! two register arguments (`r0`: selector, `r1`: word) and its result in
//! `r0`; it implements each non-identity case as an ARM `ror`.

/// transform_word_endianness — original: `FUN_0802bad0` @ 0x0802bad0
/// (40 bytes).
///
/// Applies the exact selector-controlled 32-bit permutation. Selector 0
/// preserves `word`; selector 1 rotates it right by 8 bits; selector 2
/// rotates it right by 16 bits; every other selector rotates it right by 24
/// bits. Rotations preserve the original's wrapping bit behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn transform_word_endianness(selector: u32, word: u32) -> u32 {
    match selector {
        0 => word,
        1 => word.rotate_right(8),
        2 => word.rotate_right(16),
        _ => word.rotate_right(24),
    }
}

#[cfg(test)]
mod tests {
    use super::transform_word_endianness;

    const PATTERN: u32 = 0x0123_4567;

    #[test]
    fn selector_zero_preserves_every_bit() {
        for word in [0, 1, PATTERN, 0x8000_0001, u32::MAX] {
            assert_eq!(transform_word_endianness(0, word), word, "{word:#010x}");
        }
    }

    #[test]
    fn selector_one_rotates_right_one_byte() {
        assert_eq!(transform_word_endianness(1, PATTERN), 0x6701_2345);
        assert_eq!(
            transform_word_endianness(1, 0x8000_0001),
            0x0180_0000,
            "bits shifted out of the low end wrap into the high byte"
        );
    }

    #[test]
    fn selector_two_swaps_halfwords() {
        assert_eq!(transform_word_endianness(2, PATTERN), 0x4567_0123);
        assert_eq!(transform_word_endianness(2, 0xffff_0000), 0x0000_ffff);
    }

    #[test]
    fn all_other_selectors_rotate_left_one_byte() {
        for selector in [3, 4, 0x8000_0000, u32::MAX] {
            assert_eq!(
                transform_word_endianness(selector, PATTERN),
                0x2345_6701,
                "selector={selector:#010x}"
            );
        }
    }
}
