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

// Producer-side keys (inverses modulo 2^32 of the reader-side keys):
// 0xed99887f * 0x0a7e377f == 1 and 0xd561a67f * 0x76b4197f == 1 (mod 2^32).
const ENCODED_COUNT_INVERSE: u32 = 0xed99_887f;
const ENCODED_WORD_MULTIPLIER: u32 = 0xd561_a67f;

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
const INLINE_ENCODED_WORD_COMPARE_MULTIPLIER: u32 = 0x3399_e27f;



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

/// Initializes an encoded-count word block from a plain signed 32-bit
/// integer: the producer half of the [`EncodedWordBlock`] family. Always
/// returns 0.
///
/// Original: `FUN_083555f8` @ 0x083555f8 (116-byte instruction body
/// 0x083555f8..0x0835566c, trailing literal-pool words `0xd561a67f` at
/// 0x0835566c and `0xed99887f` at 0x08355670; the next function's
/// `stmdb sp!, {...}` prologue starts at 0x08355674, so the full extent
/// is 124 bytes. Ghidra reports 116 and mislabels both pool words as the
/// globals `DAT_0835566c`/`DAT_08355670`; they are constants, referenced
/// from nowhere else. A complete B/BL decode of osos.dec finds exactly
/// 17 direct call sites, all unconditional `bl` (no predicated forms);
/// the address occurs in no data word, so it is not dispatched
/// virtually).
///
/// Algorithm: take the wrapping absolute value of `value`, then emit it
/// as base-2^32 limbs from low to high: each stored word is
/// `limb * 0xd561a67f` (mod 2^32). The header is then set to
/// `signed_limb_count * 0xed99887f`, the count negated when `value` was
/// negative. `0xed99887f` is the multiplicative inverse of
/// [`ENCODED_COUNT_MULTIPLIER`] modulo 2^32, and `0x76b4197f` (seen in
/// reader literal pools, e.g. at 0x082eafa0) inverts `0xd561a67f`, so a
/// block written here decodes back to `value` through the family's
/// readers. Word stores precede the header store, as in the original.
///
/// The limb loop is `while high != 0 || limb != 0 { store; limb = high;
/// high = 0; }` with `high = limb >> 31` (arithmetic), so every value in
/// `-2^31 < value < 2^31` emits exactly one limb (zero emits none), but
/// `i32::MIN` — whose wrapping absolute value stays `0x80000000` —
/// shifts out a `-1` high part and emits TWO limbs,
/// `[0x80000000 * key, 0xffffffff * key]` with count -2. That is a
/// faithful quirk of the original, not a general multi-limb conversion.
///
/// Deliberate deviation: none.
///
/// # Safety
/// `destination` must point to a writable [`EncodedWordBlock`] whose
/// `words` array has room for the emitted limbs: 0 words for `value == 0`,
/// 1 word otherwise, and 2 words for `i32::MIN`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn encoded_word_block_set_int(
    value: i32,
    destination: *mut EncodedWordBlock,
) -> u32 {
    let mut limb = if value < 0 { value.wrapping_neg() } else { value };
    let mut high = limb >> 31;
    let mut count: i32 = 0;
    while high != 0 || limb != 0 {
        *(*destination).words.add(count as usize) =
            (limb as u32).wrapping_mul(ENCODED_WORD_MULTIPLIER);
        count += 1;
        limb = high;
        high = 0;
    }
    if value < 0 {
        count = count.wrapping_neg();
    }
    (*destination).encoded_count =
        (count as u32).wrapping_mul(ENCODED_COUNT_INVERSE) as i32;
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
/// Compares two inline encoded-count word blocks as signed magnitudes.
///
/// Original: `FUN_082f5364` @ 0x082f5364 (204 bytes; 21 unconditional `bl`
/// call sites). The raw body runs 0x082f5364..0x082f5434, with the two
/// literal-pool words at 0x082f5430 and 0x082f5434; the next function starts
/// at 0x082f5438.
///
/// Algorithm: decode both headers with `0x4b6143ff`, compare the decoded
/// signed headers first, and return immediately if they differ. When the
/// headers match, treat the decoded header sign as the result sign and compare
/// payload words 1..count from high to low after multiplying each word by
/// `0x3399e27f`; unsigned ordering on those products decides whether the
/// result is `sign`, `-sign`, or zero when every word matches.
///
/// Deliberate deviations: none.
///
/// # Safety
/// `left` and `right` must point at readable inline encoded-word blocks whose
/// inline payloads contain at least the decoded number of words named by their
/// headers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inline_encoded_word_block_compare(
    left: *const InlineEncodedWordBlock,
    right: *const InlineEncodedWordBlock,
) -> i32 {
    let mut left_count = (*left).encoded_count.wrapping_mul(INLINE_ENCODED_COUNT_MULTIPLIER);
    let right_count = (*right).encoded_count.wrapping_mul(INLINE_ENCODED_COUNT_MULTIPLIER);

    if left_count > right_count {
        return 1;
    }
    if left_count < right_count {
        return -1;
    }

    let sign = if left_count < 0 { -1 } else { 1 };
    if left_count < 0 {
        left_count = left_count.wrapping_neg();
    }
    left_count = left_count.wrapping_sub(1);
    if left_count < 0 {
        return 0;
    }

    let left_words = left.cast::<u32>();
    let right_words = right.cast::<u32>();
    let mut index = left_count as usize + 1;
    loop {
        let left_word =
            unsafe { *left_words.add(index) }.wrapping_mul(INLINE_ENCODED_WORD_COMPARE_MULTIPLIER);
        let right_word =
            unsafe { *right_words.add(index) }.wrapping_mul(INLINE_ENCODED_WORD_COMPARE_MULTIPLIER);
        if left_word > right_word {
            return sign;
        }
        if left_word < right_word {
            return -sign;
        }

        index -= 1;
        if index == 0 {
            return 0;
        }
    }
}


#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::{
        copy_encoded_word_block, copy_encoded_word_block_from, copy_inline_encoded_word_block,
        encoded_word_block_set_int, inline_encoded_word_block_compare, EncodedWordBlock,
        InlineEncodedWordBlock,
    };


    const ENCODED_COUNT_INVERSE: u32 = 0xed99_887f;
    const ENCODED_WORD_MULTIPLIER: u32 = 0xd561_a67f;
    const ENCODED_WORD_INVERSE: u32 = 0x76b4_197f;
    const INLINE_ENCODED_COUNT_INVERSE: u32 = 0xda8e_bbff;

    fn encoded_count(decoded_count: i32) -> i32 {
        ((decoded_count as u32).wrapping_mul(ENCODED_COUNT_INVERSE)) as i32
    }

    fn inline_encoded_count(decoded_count: i32) -> i32 {
        ((decoded_count as u32).wrapping_mul(INLINE_ENCODED_COUNT_INVERSE)) as i32
    }

    fn inline_block(decoded_count: i32, payload: &[u32]) -> Vec<u32> {
        let mut block = Vec::with_capacity(payload.len() + 1);
        block.push(inline_encoded_count(decoded_count) as u32);
        block.extend_from_slice(payload);
        block
    }

    unsafe fn compare(left: &[u32], right: &[u32]) -> i32 {
        inline_encoded_word_block_compare(left.as_ptr().cast(), right.as_ptr().cast())
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
    fn compares_headers_before_payload_words() {
        let left = inline_block(2, &[5, 1]);
        let right = inline_block(1, &[1]);

        assert_eq!(unsafe { compare(&left, &right) }, 1);
        assert_eq!(unsafe { compare(&right, &left) }, -1);
    }

    #[test]
    fn compares_payload_words_from_high_to_low() {
        let left = inline_block(2, &[1, 1]);
        let right = inline_block(2, &[5, 1]);

        assert_eq!(unsafe { compare(&left, &right) }, 1);
        assert_eq!(unsafe { compare(&right, &left) }, -1);
    }

    #[test]
    fn flips_payload_order_for_negative_blocks() {
        let left = inline_block(-2, &[1, 1]);
        let right = inline_block(-2, &[5, 1]);

        assert_eq!(unsafe { compare(&left, &right) }, -1);
        assert_eq!(unsafe { compare(&right, &left) }, 1);
    }

    #[test]
    fn returns_zero_for_equal_or_empty_blocks() {
        let equal = inline_block(3, &[7, 8, 9]);
        let empty_left = inline_block(0, &[0xdead_beef, 0xfeed_face]);
        let empty_right = inline_block(0, &[0xcafe_babe, 0x0123_4567]);

        assert_eq!(unsafe { compare(&equal, &equal) }, 0);
        assert_eq!(unsafe { compare(&empty_left, &empty_right) }, 0);
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

    #[test]
    fn set_int_zero_writes_header_only() {
        let mut words = [0xdead_beef; 2];
        let mut block = EncodedWordBlock {
            encoded_count: encoded_count(5),
            words: words.as_mut_ptr(),
        };

        assert_eq!(unsafe { encoded_word_block_set_int(0, &mut block) }, 0);
        assert_eq!(block.encoded_count, 0);
        assert_eq!(words, [0xdead_beef; 2]);
    }

    #[test]
    fn set_int_stores_single_wrapped_limb_and_signed_count() {
        for value in [1, 7, 0x1234_5678, i32::MAX, -1, -7, i32::MAX.wrapping_neg()] {
            let mut words = [0xdead_beef; 2];
            let mut block = EncodedWordBlock {
                encoded_count: 0,
                words: words.as_mut_ptr(),
            };

            assert_eq!(unsafe { encoded_word_block_set_int(value, &mut block) }, 0);
            let magnitude = (value as i64).unsigned_abs() as u32;
            assert_eq!(words[0], magnitude.wrapping_mul(ENCODED_WORD_MULTIPLIER));
            // Readers invert both keys modulo 2^32 and recover the value.
            assert_eq!(words[0].wrapping_mul(ENCODED_WORD_INVERSE), magnitude);
            let decoded_count = block
                .encoded_count
                .wrapping_mul(super::ENCODED_COUNT_MULTIPLIER);
            assert_eq!(decoded_count, if value < 0 { -1 } else { 1 });
            assert_eq!(words[1], 0xdead_beef);
        }
    }

    #[test]
    fn set_int_min_emits_two_limbs_from_wrapping_negation() {
        // i32::MIN's wrapping absolute value stays 0x80000000, so the
        // arithmetic `>> 31` yields -1 and the original's loop emits a
        // second limb: [0x80000000 * key, 0xffffffff * key], count -2.
        let mut words = [0xdead_beef; 3];
        let mut block = EncodedWordBlock {
            encoded_count: 0,
            words: words.as_mut_ptr(),
        };

        assert_eq!(unsafe { encoded_word_block_set_int(i32::MIN, &mut block) }, 0);
        assert_eq!(words[0], 0x8000_0000u32.wrapping_mul(ENCODED_WORD_MULTIPLIER));
        assert_eq!(words[1], 0xffff_ffffu32.wrapping_mul(ENCODED_WORD_MULTIPLIER));
        let decoded_count = block
            .encoded_count
            .wrapping_mul(super::ENCODED_COUNT_MULTIPLIER);
        assert_eq!(decoded_count, -2);
        assert_eq!(words[2], 0xdead_beef);
    }

    #[test]
    fn set_int_result_decodes_through_copy_reader() {
        // A block produced here must round-trip through the family's
        // copy reader: same header, same words, count accepted (<= 28).
        let mut produced_words = [0; 2];
        let mut produced = EncodedWordBlock {
            encoded_count: 0,
            words: produced_words.as_mut_ptr(),
        };
        unsafe { encoded_word_block_set_int(-0x0bad_f00d, &mut produced) };

        let mut copied_words = [0; 2];
        let mut copied = EncodedWordBlock {
            encoded_count: 0,
            words: copied_words.as_mut_ptr(),
        };
        assert_eq!(unsafe { copy_encoded_word_block(&mut copied, &produced) }, 0);
        assert_eq!(copied.encoded_count, produced.encoded_count);
        assert_eq!(copied_words[0], produced_words[0]);
        assert_eq!(
            copied_words[0].wrapping_mul(ENCODED_WORD_INVERSE),
            0x0bad_f00d
        );
    }

}
