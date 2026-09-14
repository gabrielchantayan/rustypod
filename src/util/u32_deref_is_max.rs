//! Word maximum-sentinel predicate — `FUN_083b4788` @ 0x083b4788 (20 bytes; 5
//! plain `bl` call sites, no predicated calls).
//!
//! The raw function is five instructions: it loads one aligned u32 and returns
//! 1 exactly when that word is `0xffff_ffff`; it returns 0 for every other
//! value. It has no NULL guard; callers provide a readable, word-aligned
//! address. Decoding every ARM `B`/`BL` immediate in `osos.dec` finds five
//! inbound direct calls, all unconditional `bl` at 0x0824e238, 0x08256388,
//! 0x083b4870, 0x083b489c, and 0x083b48c4; there are no predicated or direct
//! tail-`b` callers. The callers use the maximum word as an absent-index
//! sentinel. Deliberate deviations: none.
//!
//! ```text
//! ldr   r0, [r0]
//! cmn   r0, #1
//! movne r0, #0
//! moveq r0, #1
//! bx    lr
//! ```

/// Returns 1 exactly when the u32 stored at `word` is `u32::MAX`.
///
/// `word` must be a valid, word-aligned address readable as `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.u32_deref_is_max")]
#[inline(never)]
pub unsafe extern "C" fn u32_deref_is_max(word: *const u32) -> u32 {
    u32::from(word.read() == u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_exactly_the_maximum_word_sentinel() {
        for (word, expected) in [
            (0u32, 0),
            (1, 0),
            (u32::MAX - 1, 0),
            (u32::MAX, 1),
        ] {
            assert_eq!(unsafe { u32_deref_is_max(&word) }, expected, "{word:#010x}");
        }
    }
}
