//! Word-zero predicate — `FUN_08087480` @ 0x08087480 (16 bytes; 3 plain
//! `bl` call sites, no predicated calls).
//!
//! Raw ARM establishes the four-word extent 0x08087480..0x08087490: `ldr
//! r0,[r0]; rsbs r0,r0,#1; movcc r0,#0; bx lr`; the separately entered next
//! function begins at 0x08087490. Full-image A32 decoding finds the three
//! inbound unconditional calls at 0x08166dfc, 0x08166ed8, and 0x081670ac,
//! with no predicated `bl` callers and no calls in this leaf. It reads an
//! aligned 32-bit word and returns whether it is zero, normalized to zero or
//! one. Deliberate deviations: none.

/// Returns whether an aligned 32-bit word is zero.
///
/// # Safety
/// `word` must be valid to read an aligned `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_is_zero(word: *const u32) -> u32 {
    u32::from(word.read() == 0)
}

#[cfg(test)]
mod tests {
    use super::word_is_zero;

    #[test]
    fn normalizes_zero_and_all_nonzero_word_values() {
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            assert_eq!(unsafe { word_is_zero(&value) }, u32::from(value == 0));
        }
    }
}
