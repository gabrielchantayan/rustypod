//! signed_word_min — original: `FUN_083b4bdc` @ 0x083b4bdc (20 bytes; 2
//! plain `bl` call sites, no predicated calls).
//!
//! Raw A32 words establish the five-instruction extent
//! 0x083b4bdc..0x083b4bec: `bx lr` ends this function and the next separately
//! linked function begins at 0x083b4bf0. It reads both aligned signed words,
//! compares them, and returns the lesser value; equality returns the second
//! word, which is value-identical. Complete raw-firmware branch decoding finds
//! two inbound unconditional plain `bl` instructions (0x08252ea8 and
//! 0x08252ed8) and zero predicated `bl` instructions. No deliberate
//! deviations.

/// Returns the lesser of the two signed words.
///
/// Both pointers must be valid, word-aligned addresses readable as `i32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.signed_word_min")]
#[inline(never)]
pub unsafe extern "C" fn signed_word_min(left: *const i32, right: *const i32) -> i32 {
    let left = left.read();
    let right = right.read();
    if right <= left { right } else { left }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_signed_minimum_for_boundary_and_equal_values() {
        for (left, right, expected) in [
            (i32::MIN, i32::MAX, i32::MIN),
            (i32::MAX, i32::MIN, i32::MIN),
            (-1, 0, -1),
            (0, -1, -1),
            (0, 0, 0),
            (i32::MAX, i32::MAX, i32::MAX),
            (i32::MIN, i32::MIN, i32::MIN),
        ] {
            assert_eq!(unsafe { signed_word_min(&left, &right) }, expected);
        }
    }
}
