//! `copy_encoded_word_block` — bounded copy for a word block whose count is
//! stored as a multiplicatively encoded signed value.
//!
//! Original: `FUN_0835443c` @ 0x0835443c (124-byte instruction body,
//! 0x0835443c..0x083544b8; trailing literal pool word at 0x083544b8; 38
//! unconditional `bl` call sites, no predicated calls or tail branches).
//!
//! The source header's encoded count is multiplied modulo 2^32 by
//! `0x0a7e377f`; its signed wrapping absolute value is the word count. Counts
//! greater than 28 return 1 without writing the destination. Otherwise, a
//! distinct destination receives the raw encoded count and words are copied
//! from last to first; an identical header pointer succeeds without writes.
//! This is deliberately structural: the enclosing object family is not
//! identified from the function and its callers.
//!
//! Deliberate deviation: none. In particular, `i32::MIN` retains the ARM
//! wrapping-negation behavior: it passes the signed range check and a distinct
//! destination attempts to copy 2^31 words.

/// A two-word firmware header for a bounded, encoded-count word block.
///
/// `encoded_count` is not a plain length. Multiply it modulo 2^32 by
/// [`ENCODED_COUNT_MULTIPLIER`] and take the signed wrapping absolute value to
/// obtain the number of elements.
#[repr(C)]
pub struct EncodedWordBlock {
    pub encoded_count: i32,
    pub words: *mut u32,
}

const ENCODED_COUNT_MULTIPLIER: i32 = 0x0a7e_377f;
const MAX_DECODED_WORD_COUNT: i32 = 28;

/// Copies a bounded encoded-count word block, returning 0 on success or 1
/// when the decoded count exceeds 28.
///
/// Original: `FUN_0835443c` @ 0x0835443c (124 bytes; 38 unconditional `bl`
/// call sites).
///
/// # Safety
/// `source` must point to a readable [`EncodedWordBlock`]. When it differs
/// from `destination` and its decoded count is accepted, `destination` must
/// be writable and both word arrays must contain that many readable/writable
/// elements. As in the firmware, words are copied in descending-index order.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn copy_encoded_word_block(
    destination: *mut EncodedWordBlock,
    source: *const EncodedWordBlock,
) -> u32 {
    let decoded_count = (*source).encoded_count.wrapping_mul(ENCODED_COUNT_MULTIPLIER);
    let word_count = if decoded_count < 0 {
        decoded_count.wrapping_neg()
    } else {
        decoded_count
    };

    if word_count > MAX_DECODED_WORD_COUNT {
        return 1;
    }

    if !core::ptr::eq(destination.cast_const(), source) {
        (*destination).encoded_count = (*source).encoded_count;
        let mut remaining = (word_count as u32) as usize;
        while remaining != 0 {
            remaining -= 1;
            *(*destination).words.add(remaining) = *(*source).words.add(remaining);
        }
    }

    0
}

/// Copies a bounded encoded-count word block with the source in the first
/// argument, returning 0 on success or 1 when the decoded count exceeds 28.
///
/// Original: `FUN_08322bcc` @ 0x08322bcc (124-byte extent
/// 0x08322bcc..0x08322c48: 120-byte instruction body, trailing literal-pool
/// multiplier `0x0a7e377f` at 0x08322c44; next function starts at
/// 0x08322c48. A complete B/BL decode of osos.dec finds exactly 33 direct
/// call sites, all unconditional `bl`; the address occurs in no data word,
/// so it is not dispatched virtually).
///
/// This is the same algorithm as [`copy_encoded_word_block`] with the
/// parameter order swapped: here `r0` is the source and `r1` is the
/// destination (`ldr ip, [r0]` reads the source header, `str ip, [r1]`
/// writes the destination header, the loop reads `*(r0 + 4)` and writes
/// `*(r1 + 4)`). The call sites confirm it: e.g. 0x082ebbcc copies six
/// consecutive blocks from an input array into a crypto context's
/// 0x50..0x70 slots, always passing the source first.
///
/// Deliberate deviation: none. The range check runs before the alias check
/// exactly as in the original, so an aliased out-of-range header still
/// returns 1, and `i32::MIN` retains the ARM wrapping-negation behavior.
///
/// # Safety
/// `source` must point to a readable [`EncodedWordBlock`]. When it differs
/// from `destination` and its decoded count is accepted, `destination` must
/// be writable and both word arrays must contain that many readable/writable
/// elements. As in the firmware, words are copied in descending-index order.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn copy_encoded_word_block_from(
    source: *const EncodedWordBlock,
    destination: *mut EncodedWordBlock,
) -> u32 {
    let decoded_count = (*source).encoded_count.wrapping_mul(ENCODED_COUNT_MULTIPLIER);
    let word_count = if decoded_count < 0 {
        decoded_count.wrapping_neg()
    } else {
        decoded_count
    };

    if word_count > MAX_DECODED_WORD_COUNT {
        return 1;
    }

    if !core::ptr::eq(source, destination.cast_const()) {
        (*destination).encoded_count = (*source).encoded_count;
        let mut remaining = (word_count as u32) as usize;
        while remaining != 0 {
            remaining -= 1;
            *(*destination).words.add(remaining) = *(*source).words.add(remaining);
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::{copy_encoded_word_block, copy_encoded_word_block_from, EncodedWordBlock};

    const ENCODED_COUNT_INVERSE: u32 = 0xed99_887f;

    fn encoded_count(decoded_count: i32) -> i32 {
        ((decoded_count as u32).wrapping_mul(ENCODED_COUNT_INVERSE)) as i32
    }

    #[test]
    fn copies_positive_and_negative_decoded_counts() {
        for decoded_count in [3, -3] {
            let mut source_words = [0x11, 0x22, 0x33, 0x44];
            let mut destination_words = [0xdead_beef; 4];
            let source = EncodedWordBlock {
                encoded_count: encoded_count(decoded_count),
                words: source_words.as_mut_ptr(),
            };
            let mut destination = EncodedWordBlock {
                encoded_count: encoded_count(1),
                words: destination_words.as_mut_ptr(),
            };

            assert_eq!(unsafe { copy_encoded_word_block(&mut destination, &source) }, 0);
            assert_eq!(destination.encoded_count, source.encoded_count);
            assert_eq!(&destination_words[..3], &source_words[..3]);
            assert_eq!(destination_words[3], 0xdead_beef);
        }
    }

    #[test]
    fn rejects_out_of_range_count_without_writes() {
        let mut source_words = [0x11, 0x22, 0x33, 0x44];
        let mut destination_words = [0xdead_beef; 4];
        let source = EncodedWordBlock {
            encoded_count: 1,
            words: source_words.as_mut_ptr(),
        };
        let mut destination = EncodedWordBlock {
            encoded_count: encoded_count(2),
            words: destination_words.as_mut_ptr(),
        };
        let original_header = destination.encoded_count;

        assert_eq!(unsafe { copy_encoded_word_block(&mut destination, &source) }, 1);
        assert_eq!(destination.encoded_count, original_header);
        assert_eq!(destination_words, [0xdead_beef; 4]);
    }

    #[test]
    fn copies_overlapping_words_in_descending_index_order() {
        let mut words = [0, 1, 2, 3, 4];
        let source = EncodedWordBlock {
            encoded_count: encoded_count(3),
            words: unsafe { words.as_mut_ptr().add(1) },
        };
        let mut destination = EncodedWordBlock {
            encoded_count: encoded_count(1),
            words: words.as_mut_ptr(),
        };

        assert_eq!(unsafe { copy_encoded_word_block(&mut destination, &source) }, 0);
        assert_eq!(words, [3, 3, 3, 3, 4]);
        assert_eq!(destination.encoded_count, source.encoded_count);
    }

    #[test]
    fn self_copy_preserves_wrapping_minimum_count_behavior() {
        let mut block = EncodedWordBlock {
            encoded_count: i32::MIN,
            words: core::ptr::null_mut(),
        };

        assert_eq!(unsafe { copy_encoded_word_block(&mut block, &block) }, 0);
        assert_eq!(block.encoded_count, i32::MIN);
    }

    #[test]
    fn from_copies_positive_and_negative_decoded_counts() {
        for decoded_count in [3, -3] {
            let mut source_words = [0x11, 0x22, 0x33, 0x44];
            let mut destination_words = [0xdead_beef; 4];
            let source = EncodedWordBlock {
                encoded_count: encoded_count(decoded_count),
                words: source_words.as_mut_ptr(),
            };
            let mut destination = EncodedWordBlock {
                encoded_count: encoded_count(1),
                words: destination_words.as_mut_ptr(),
            };

            assert_eq!(unsafe { copy_encoded_word_block_from(&source, &mut destination) }, 0);
            assert_eq!(destination.encoded_count, source.encoded_count);
            assert_eq!(&destination_words[..3], &source_words[..3]);
            assert_eq!(destination_words[3], 0xdead_beef);
        }
    }

    #[test]
    fn from_accepts_28_and_rejects_29_decoded_words() {
        for (decoded_count, expected) in [(28, 0), (-28, 0), (29, 1), (-29, 1)] {
            let mut source_words = [0x55; 29];
            let mut destination_words = [0xdead_beef; 29];
            let source = EncodedWordBlock {
                encoded_count: encoded_count(decoded_count),
                words: source_words.as_mut_ptr(),
            };
            let mut destination = EncodedWordBlock {
                encoded_count: encoded_count(2),
                words: destination_words.as_mut_ptr(),
            };
            let original_header = destination.encoded_count;

            assert_eq!(
                unsafe { copy_encoded_word_block_from(&source, &mut destination) },
                expected
            );
            if expected == 0 {
                assert_eq!(destination.encoded_count, source.encoded_count);
                assert_eq!(&destination_words[..28], &[0x55; 28]);
                assert_eq!(destination_words[28], 0xdead_beef);
            } else {
                assert_eq!(destination.encoded_count, original_header);
                assert_eq!(destination_words, [0xdead_beef; 29]);
            }
        }
    }

    #[test]
    fn from_rejects_out_of_range_aliased_header_without_writes() {
        // The range check runs before the alias check in the original
        // (return 1 beats the no-op self copy), so an aliased header whose
        // decoded count exceeds 28 still reports failure.
        let mut block = EncodedWordBlock {
            encoded_count: 1,
            words: core::ptr::null_mut(),
        };
        let block_ptr = &mut block as *mut EncodedWordBlock;

        assert_eq!(unsafe { copy_encoded_word_block_from(block_ptr, block_ptr) }, 1);
        assert_eq!(block.encoded_count, 1);
    }

    #[test]
    fn from_copies_overlapping_words_in_descending_index_order() {
        let mut words = [0, 1, 2, 3, 4];
        let source = EncodedWordBlock {
            encoded_count: encoded_count(3),
            words: unsafe { words.as_mut_ptr().add(1) },
        };
        let mut destination = EncodedWordBlock {
            encoded_count: encoded_count(1),
            words: words.as_mut_ptr(),
        };

        assert_eq!(unsafe { copy_encoded_word_block_from(&source, &mut destination) }, 0);
        assert_eq!(words, [3, 3, 3, 3, 4]);
        assert_eq!(destination.encoded_count, source.encoded_count);
    }

    #[test]
    fn from_self_copy_preserves_wrapping_minimum_count_behavior() {
        let mut block = EncodedWordBlock {
            encoded_count: i32::MIN,
            words: core::ptr::null_mut(),
        };
        let block_ptr = &mut block as *mut EncodedWordBlock;

        assert_eq!(unsafe { copy_encoded_word_block_from(block_ptr, block_ptr) }, 0);
        assert_eq!(block.encoded_count, i32::MIN);
    }
}
