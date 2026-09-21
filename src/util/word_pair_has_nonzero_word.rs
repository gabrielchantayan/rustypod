//! `word_pair_has_nonzero_word` — retailOS `FUN_0829d858` at `0x0829d858`
//! (28 bytes).
//!
//! Raw `osos.dec` words establish the exact seven-instruction A32 body at
//! `0x0829d858..0x0829d870`; the next independently entered function begins
//! with `push {r1,r2,r3,r4,r5,lr}` at `0x0829d874`. It contains no outgoing
//! calls. Full-image ARM decoding finds three inbound unconditional plain `bl`
//! calls at `0x0815fb58`, `0x081dcb04`, and `0x0829b618`, zero predicated `bl`
//! calls, and one direct tail `b` at `0x0829b18c`.
//!
//! # Algorithm
//!
//! Read the first target word. Return one if it is nonzero; otherwise read and
//! test the second target word. The pair's concrete type is unrecovered, so it
//! remains two target-width words. Deliberate deviations: none.

/// Returns whether either target-width word in `pair` is nonzero.
///
/// # Safety
///
/// `pair` must point to two readable, aligned `u32` words. The retail helper
/// does not check it for NULL or alignment.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_pair_has_nonzero_word")]
pub unsafe extern "C" fn word_pair_has_nonzero_word(pair: *const u32) -> u32 {
    u32::from(unsafe { pair.read() != 0 || pair.add(1).read() != 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_zero_only_when_both_words_are_zero() {
        let pair = [0, 0];
        assert_eq!(unsafe { word_pair_has_nonzero_word(pair.as_ptr()) }, 0);
    }

    #[test]
    fn accepts_each_word_independently_at_full_width() {
        for pair in [[1, 0], [0, 1], [0x8000_0000, 0], [0, u32::MAX], [0x1234_5678, 0x9abc_def0]] {
            assert_eq!(unsafe { word_pair_has_nonzero_word(pair.as_ptr()) }, 1, "pair={pair:08x?}");
        }
    }
}
