//! `signed_word_max` — original: `FUN_083b4bc8` @ 0x083b4bc8 (20 bytes; 2
//! plain `bl` call sites, no predicated calls).
//!
//! Raw A32 words establish the five-instruction extent
//! 0x083b4bc8..0x083b4bd8: `bx lr` ends this function and the next separately
//! linked function begins at 0x083b4bdc. It reads both aligned signed words,
//! compares them, and returns the greater value; equality selects the second
//! word, which is value-identical. Complete raw-firmware branch decoding finds
//! two inbound unconditional plain `bl` instructions (0x08252e68 and
//! 0x08252e78) and zero predicated `bl` instructions. No deliberate deviations.

/// Returns the greater of the two signed words.
///
/// Both pointers must be valid, word-aligned addresses readable as `i32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.signed_word_max")]
#[inline(never)]
pub unsafe extern "C" fn signed_word_max(left: *const i32, right: *const i32) -> i32 {
    let left = left.read();
    let right = right.read();
    if left <= right { right } else { left }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_signed_maximum_for_boundary_and_equal_values() {
        for (left, right, expected) in [
            (i32::MIN, i32::MAX, i32::MAX),
            (i32::MAX, i32::MIN, i32::MAX),
            (-1, 0, 0),
            (0, -1, 0),
            (0, 0, 0),
            (i32::MAX, i32::MAX, i32::MAX),
            (i32::MIN, i32::MIN, i32::MIN),
        ] {
            assert_eq!(unsafe { signed_word_max(&left, &right) }, expected);
        }
    }
}
