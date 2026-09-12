//! Indirect u32 equality — `FUN_083cf8d8` @ 0x083cf8d8 (24 bytes; 7 plain
//! `bl` call sites, no predicated calls).
//!
//! The raw function is six instructions: it loads one aligned u32 from each
//! input address, returns 1 when those loaded words are equal, and returns 0
//! otherwise. It has no NULL guard; callers provide readable, word-aligned
//! addresses. Its seven verified calls are all unconditional `bl` at
//! 0x081473b0, 0x0814752c, 0x083c858c, 0x083c89f8, 0x083c8a14, 0x083c8a98,
//! and 0x083c8b5c. Deliberate deviations: none.
//!
//! ```text
//! ldr   r0, [r0]
//! ldr   r1, [r1]
//! cmp   r0, r1
//! movne r0, #0
//! moveq r0, #1
//! bx    lr
//! ```

/// Returns 1 if the u32 values stored at `left_word` and `right_word` match.
///
/// Both pointers must be valid, word-aligned addresses readable as `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.u32_indirect_equal")]
#[inline(never)]
pub unsafe extern "C" fn u32_indirect_equal(left_word: *const u32, right_word: *const u32) -> u32 {
    u32::from(left_word.read() == right_word.read())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_values_in_distinct_words_match() {
        let left = 0x1234_5678;
        let right = 0x1234_5678;

        assert_eq!(unsafe { u32_indirect_equal(&left, &right) }, 1);
    }

    #[test]
    fn unequal_values_cover_zero_and_all_ones() {
        let zero = 0;
        let all_ones = u32::MAX;

        assert_eq!(unsafe { u32_indirect_equal(&zero, &all_ones) }, 0);
        assert_eq!(unsafe { u32_indirect_equal(&all_ones, &zero) }, 0);
    }

    #[test]
    fn comparison_uses_values_not_storage_identity() {
        let value = 0xa5a5_5a5a;

        assert_eq!(unsafe { u32_indirect_equal(&value, &value) }, 1);
    }
}
