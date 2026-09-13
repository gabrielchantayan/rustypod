//! Indirect u32 equality — `FUN_083cf728` @ 0x083cf728 (24 bytes; 6 plain
//! `bl` call sites, no predicated calls).
//!
//! The raw function is six instructions: it loads one aligned u32 from each
//! input address, returns 1 when those loaded words are equal, and returns 0
//! otherwise. It has no NULL guard; callers provide readable, word-aligned
//! addresses. Its six verified calls are all unconditional `bl` at
//! 0x083b7578, 0x083b79e4, 0x083b7a00, 0x083b7a84, 0x083b7b64, and
//! 0x083b7c54. Deliberate deviations: none.
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
#[cfg_attr(target_os = "none", link_section = ".text.u32_deref_equal")]
#[inline(never)]
pub unsafe extern "C" fn u32_deref_equal(left_word: *const u32, right_word: *const u32) -> u32 {
    u32::from(left_word.read() == right_word.read())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_zero_sentinel_values_match() {
        let left = 0;
        let right = 0;

        assert_eq!(unsafe { u32_deref_equal(&left, &right) }, 1);
    }

    #[test]
    fn distinct_pointer_values_do_not_match() {
        let left = 0x0800_0000;
        let right = 0x083c_f728;

        assert_eq!(unsafe { u32_deref_equal(&left, &right) }, 0);
    }

    #[test]
    fn equal_nonzero_values_match_across_storage() {
        let left = 0xa5a5_5a5a;
        let right = left;

        assert_eq!(unsafe { u32_deref_equal(&left, &right) }, 1);
    }
}
