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

/// A one-word firmware header for an encoded-count word block with INLINE
/// storage: the word payload follows the header immediately at offset +4,
/// so the block occupies `4 + 4 * decoded_count` contiguous bytes.
///
/// `encoded_count` is not a plain length. Multiply it modulo 2^32 by
/// [`INLINE_ENCODED_COUNT_MULTIPLIER`] and take the signed wrapping absolute
/// value to obtain the number of inline words. The encoding constant differs
/// from [`EncodedWordBlock`]'s: its producer (`FUN_0833dbd0` @ 0x0833dbd0)
/// stores `count * 0xda8ebbff`, the multiplicative inverse of
/// `0x4b6143ff` modulo 2^32.
#[repr(C)]
pub struct InlineEncodedWordBlock {
    pub encoded_count: i32,
    // `decoded_count` u32 words follow inline at offset +4.
}

const INLINE_ENCODED_COUNT_MULTIPLIER: i32 = 0x4b61_43ff;

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

/// Copies an inline encoded-count word block: header verbatim, then the
/// decoded number of inline words from last to first. No bound check and
/// no return value; an identical source/destination pointer is a silent
/// no-op (the alias check runs BEFORE the header read, so no decode
/// happens at all in that case).
///
/// Original: `FUN_08309be0` @ 0x08309be0 (84-byte instruction body
/// 0x08309be0..0x08309c34; trailing literal-pool multiplier `0x4b6143ff`
/// at 0x08309c34; next function's `stmdb sp!, {...}` prologue starts at
/// 0x08309c38, so Ghidra's 84 bytes is the instruction body only. A
/// complete B/BL decode of osos.dec finds exactly 24 direct call sites,
/// all unconditional `bl`; the address occurs in no data word, so it is
/// not dispatched virtually).
///
/// ```text
/// mov   r2, r1            ; r2 = source
/// mov   r1, r0            ; r1 = destination
/// subs  r0, r2, r0        ; source == destination ?
/// movne r0, #1
/// cmp   r0, #0
/// bxeq  lr                ; aliased: return, nothing written
/// ldr   r3, [r2]          ; encoded_count = source->encoded_count
/// str   r3, [r1]          ; destination->encoded_count = encoded_count
/// ldr   r0, [pc, #44]     ; multiplier 0x4b6143ff
/// muls  r0, r3, r0        ; decoded = encoded_count * 0x4b6143ff (mod 2^32)
/// rsbmi r0, r0, #0        ; wrapping abs
/// ...loop...              ; while (r0 != 0) { dst[r0] = src[r0]; r0--; }
/// bx    lr
/// ```
///
/// Sibling of [`copy_encoded_word_block`] for the INLINE-storage block
/// family: the loop indexes `source + 4 + i*4` directly (`ldrne r3,
/// [r3, #4]` with `r3 = source + i*4`), not through a words pointer, and
/// there is no maximum-count rejection. The producer `FUN_0833dbd0` @
/// 0x0833dbd0 encodes the header as `count * 0xda8ebbff` (the inverse of
/// this function's `0x4b6143ff` literal, verified against both literal
/// pools), so the decoded count is the plain word count for well-formed
/// blocks. Callers (e.g. `FUN_083232d4` @ 0x083232d4) shuffle 0x10-byte
/// bignums produced by `FUN_0833dbd0` between stack slots inside the
/// modular-arithmetic loop of the firmware's signature math.
///
/// Deliberate deviation: none. `i32::MIN` retains the ARM
/// wrapping-negation behavior: it decodes to `0x80000000` and a distinct
/// destination attempts a 2^31-word copy.
///
/// # Safety
/// `source` must point to a readable [`InlineEncodedWordBlock`]. When it
/// differs from `destination`, `destination` must be writable and both
/// blocks must contain `1 + decoded_count` readable/writable words. Words
/// are copied in descending-index order after the header store, exactly
/// as in the firmware.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn copy_inline_encoded_word_block(
    destination: *mut InlineEncodedWordBlock,
    source: *const InlineEncodedWordBlock,
) {
    if core::ptr::eq(destination.cast_const(), source) {
        return;
    }
    let encoded_count = (*source).encoded_count;
    (*destination).encoded_count = encoded_count;
    let decoded_count = encoded_count.wrapping_mul(INLINE_ENCODED_COUNT_MULTIPLIER);
    let word_count = if decoded_count < 0 {
        decoded_count.wrapping_neg()
    } else {
        decoded_count
    };
    let mut remaining = word_count as u32;
    while remaining != 0 {
        *destination.cast::<u32>().add(remaining as usize) =
            *source.cast::<u32>().add(remaining as usize);
        remaining -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        copy_encoded_word_block, copy_encoded_word_block_from, copy_inline_encoded_word_block,
        EncodedWordBlock, InlineEncodedWordBlock,
    };

    const ENCODED_COUNT_INVERSE: u32 = 0xed99_887f;
    const INLINE_ENCODED_COUNT_INVERSE: u32 = 0xda8e_bbff;

    fn encoded_count(decoded_count: i32) -> i32 {
        ((decoded_count as u32).wrapping_mul(ENCODED_COUNT_INVERSE)) as i32
    }

    fn inline_encoded_count(decoded_count: i32) -> i32 {
        ((decoded_count as u32).wrapping_mul(INLINE_ENCODED_COUNT_INVERSE)) as i32
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

    #[test]
    fn inline_copies_header_and_words_for_decoded_counts() {
        for decoded_count in [0, 1, 3, 5] {
            let mut source = [0xdead_beef; 7];
            source[0] = inline_encoded_count(decoded_count) as u32;
            for (index, word) in source.iter_mut().enumerate().skip(1) {
                *word = 0x1000 + index as u32;
            }
            let mut destination = [0xdead_beef; 7];

            unsafe {
                copy_inline_encoded_word_block(
                    destination.as_mut_ptr().cast(),
                    source.as_ptr().cast(),
                );
            }
            let decoded = decoded_count as usize;
            assert_eq!(destination[0], source[0]);
            assert_eq!(&destination[1..=decoded], &source[1..=decoded]);
            assert_eq!(&destination[decoded + 1..], &[0xdead_beef; 7][decoded + 1..]);
        }
    }

    #[test]
    fn inline_negates_negative_decoded_counts() {
        // Encoded count whose product with 0x4b6143ff has bit 31 set,
        // exercising the rsbmi wrapping-absolute-value path.
        let mut source = [0u32; 5];
        source[0] = inline_encoded_count(-3) as u32;
        source[1] = 0xaa;
        source[2] = 0xbb;
        source[3] = 0xcc;
        let mut destination = [0xdead_beef; 5];

        unsafe {
            copy_inline_encoded_word_block(
                destination.as_mut_ptr().cast(),
                source.as_ptr().cast(),
            );
        }
        assert_eq!(destination[0], source[0]);
        assert_eq!(&destination[1..4], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(destination[4], 0xdead_beef);
    }

    #[test]
    fn inline_zero_count_copies_header_only() {
        let source = [0u32, 0xaa, 0xbb];
        let mut destination = [0xdead_beefu32; 3];

        unsafe {
            copy_inline_encoded_word_block(
                destination.as_mut_ptr().cast(),
                source.as_ptr().cast(),
            );
        }
        assert_eq!(destination, [0, 0xdead_beef, 0xdead_beef]);
    }

    #[test]
    fn inline_aliased_block_is_a_no_op_before_any_decode() {
        // The alias check runs first in the original (bxeq lr before the
        // header load), so an aliased header that would decode to an
        // enormous count is neither written nor copied.
        let mut block = [i32::MIN as u32, 0xaa, 0xbb];

        unsafe {
            copy_inline_encoded_word_block(
                block.as_mut_ptr().cast(),
                block.as_ptr().cast(),
            );
        }
        assert_eq!(block, [i32::MIN as u32, 0xaa, 0xbb]);
    }

    #[test]
    fn inline_copies_overlapping_words_in_descending_index_order() {
        // destination header at words[0], source header at words[2]: the
        // header store lands at words[0], then words descend index 2, 1.
        let encoded = inline_encoded_count(2) as u32;
        let mut words = [0xdead_beef, 0xdead_beef, encoded, 0xaa, 0xbb, 0xcc];
        let destination: *mut InlineEncodedWordBlock = words.as_mut_ptr().cast();
        let source: *const InlineEncodedWordBlock = unsafe { words.as_ptr().add(2).cast() };

        unsafe { copy_inline_encoded_word_block(destination, source) };
        assert_eq!(words, [encoded, 0xaa, 0xbb, 0xaa, 0xbb, 0xcc]);
    }
}
