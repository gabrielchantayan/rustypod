//! Encoded pair magic match — `FUN_08346f48` @ 0x08346f48 (72 bytes; 4 plain
//! `bl` call sites, no predicated calls).
//!
//! The ARM leaf reads a word followed by a target-width pointer to a second
//! word. It multiplies each word by its literal odd multiplier modulo 2^32,
//! returning one only if both products are one. Raw decoding establishes the
//! 68-byte instruction extent plus two 4-byte literals; the next function
//! begins at 0x08346f98. The four inbound direct calls are plain `bl`; there
//! are no predicated `bl` calls. Deliberate deviations: none.

/// Returns one when both target-layout words carry the expected encodings.
///
/// `words` points to two adjacent 32-bit target fields: the first encoded
/// value and a pointer, represented as `u32`, to the second encoded value.
/// Both addresses must be readable and word-aligned.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.encoded_pair_matches_magic")]
#[inline(never)]
pub unsafe extern "C" fn encoded_pair_matches_magic(words: *const u32) -> u32 {
    let first = words.read();
    let second = (words.add(1).read() as *const u32).read();

    u32::from(first.wrapping_mul(0x0a7e_377f) == 1 && second.wrapping_mul(0x76b4_197f) == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIRST_MAGIC: u32 = 0xed99_887f;
    const SECOND_MAGIC: u32 = 0xd561_a67f;

    fn fixture(first: u32, second: u32) -> Option<*mut u32> {
        let slab = try_map_u32_slab(hints::ENCODED_PAIR_MATCHES_MAGIC, 0x100)?;
        let words = slab.cast::<u32>();
        let second_word = unsafe { words.add(8) };
        unsafe {
            words.write(first);
            words.add(1).write(second_word as usize as u32);
            second_word.write(second);
        }
        Some(words)
    }

    #[test]
    fn accepts_the_two_decoded_magic_words() {
        let Some(words) = fixture(FIRST_MAGIC, SECOND_MAGIC) else {
            assert!(note_missing_u32_fixture("util/encoded_pair_matches_magic"));
            return;
        };

        assert_eq!(unsafe { encoded_pair_matches_magic(words) }, 1);
    }

    #[test]
    fn rejects_each_word_independently() {
        let Some(words) = fixture(FIRST_MAGIC.wrapping_add(1), SECOND_MAGIC) else {
            assert!(note_missing_u32_fixture("util/encoded_pair_matches_magic"));
            return;
        };
        assert_eq!(unsafe { encoded_pair_matches_magic(words) }, 0);

        unsafe { words.write(FIRST_MAGIC) };
        unsafe { words.add(8).write(SECOND_MAGIC.wrapping_sub(1)) };
        assert_eq!(unsafe { encoded_pair_matches_magic(words) }, 0);
    }
}
