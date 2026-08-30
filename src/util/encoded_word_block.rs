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

#[cfg(test)]
mod tests {
    use super::{copy_encoded_word_block, EncodedWordBlock};

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
}
