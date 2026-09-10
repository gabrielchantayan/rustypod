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

// Reader-side word key: 0x76b4197f * 0xd561a67f == 1 (mod 2^32), so it
// decodes a stored limb back to its plain value. Being odd it is
// invertible, so `word * key == 0` iff `word == 0` — the limb-zero scan
// at 0x082fc770 relies on exactly that.
static ENCODED_WORD_DECODE_MULTIPLIER: u32 = 0x76b4_197f;

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
/// Copies a bounded encoded-count word block, returning 0 on success or 1
/// when the decoded count exceeds 28.
///
/// Original: `FUN_0833e83c` @ 0x0833e83c (124-byte full extent:
/// 120-byte instruction body at 0x0833e83c..0x0833e8b4, trailing literal-pool
/// multiplier `0x0a7e377f` at 0x0833e8b4, and the next separately linked
/// function beginning at 0x0833e8b8). A complete decode of every ARM B/BL
/// word in osos.dec finds exactly 11 direct call sites, all unconditional
/// `bl`; no predicated forms, tail branches, or DATA-word references to this
/// address exist.
///
/// The signed low word of `source->encoded_count * 0x0a7e377f` supplies the
/// decoded count. Its wrapping absolute value must be at most 28 before the
/// destination is touched. A distinct destination then receives the raw
/// header and the decoded word count copied in descending-index order; an
/// identical block pointer instead returns success without writes.
///
/// Deliberate deviation: none. This separately linked sibling has the same
/// behavior and ABI as [`copy_encoded_word_block`] but keeps a target-only
/// unique section so LLVM cannot coalesce the two required firmware symbols.
///
/// # Safety
/// `source` must point to a readable [`EncodedWordBlock`]. When it differs
/// from `destination` and its decoded count is accepted, `destination` must
/// be writable and both word arrays must contain that many readable/writable
/// elements. As in the firmware, words are copied in descending-index order.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_encoded_word_block_checked")]
pub unsafe extern "C" fn copy_encoded_word_block_checked(
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

/// Returns 1 when every decoded limb is zero, otherwise 0.
///
/// Original: `FUN_082fc770` @ 0x082fc770 (84-byte instruction body,
/// 0x082fc770..0x082fc7c4; trailing literal-pool words
/// `0x0a7e377f`/`0x76b4197f` at 0x082fc7c4..0x082fc7cc; next separately
/// linked function starts at 0x082fc7cc, for a 92-byte full extent).
/// Decoding every ARM B/BL word in osos.dec finds exactly 11 direct inbound
/// call sites, all unconditional `bl` and zero predicated forms; there are no
/// direct tail branches or aligned DATA-word references to this entry.
///
/// It decodes the signed word count with `0x0a7e377f`, takes its wrapping
/// absolute value, and examines words from the highest index down. A decoded
/// word is tested by multiplying it with `0x76b4197f`; that odd key is
/// invertible modulo 2^32, so this is equivalent to a raw nonzero test.
/// A zero decoded count and `i32::MIN` return 1 without reading `words`;
/// negative non-minimum counts are scanned by their absolute value.
///
/// Deliberate deviation: none.
///
/// # Safety
/// `block` must point to a readable [`EncodedWordBlock`]. If its decoded
/// count has a positive wrapping absolute value, `block.words` must name at
/// least that many readable words. RetailOS has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.encoded_word_block_is_zero")]
pub unsafe extern "C" fn encoded_word_block_is_zero(block: *const EncodedWordBlock) -> u32 {
    let decoded_count = (*block).encoded_count.wrapping_mul(ENCODED_COUNT_MULTIPLIER);
    let mut remaining = if decoded_count < 0 {
        decoded_count.wrapping_neg()
    } else {
        decoded_count
    };
    loop {
        if remaining < 1 {
            return 1;
        }
        remaining -= 1;
        let decoded_word = core::ptr::read_volatile(&ENCODED_WORD_DECODE_MULTIPLIER);
        if (*(*block).words.add(remaining as usize))
            .wrapping_mul(decoded_word)
            != 0
        {
            return 0;
        }
    }
}

/// Returns the sign of an encoded-count word block viewed as a signed
/// multi-limb integer: 0 when every decoded limb is zero, +1 when the
/// decoded header count is positive, -1 otherwise.
///
/// Original: `FUN_083544bc` @ 0x083544bc (76-byte instruction body
/// 0x083544bc..0x08354508; trailing literal-pool multiplier `0x0a7e377f`
/// at 0x08354508; the next function's `push {r0, r4, ...}` prologue starts
/// at 0x0835450c, so the full extent is 80 bytes. Ghidra reports 76 and
/// mislabels the pool word as the global `DAT_08354508`; it is a constant,
/// referenced from nowhere else. A complete B/BL decode of osos.dec finds
/// exactly 12 direct call sites, all unconditional `bl` (no predicated
/// forms or tail branches); the address occurs in no data word, so it is
/// not dispatched virtually).
///
/// ```text
/// push  {r4, r5, lr}
/// mov   r5, r0             @ block
/// mov   r4, #0
/// bl    0x082fc770         @ limb-zero scan
/// cmp   r0, #0 / movne r0, #1 / cmp r0, #0
/// bne   0x08354500         @ ANY nonzero scan result -> return 0
/// ldr   r0, [r5]           @ encoded_count, reloaded after the call
/// ldr   r1, [pc, #32]      @ 0x0a7e377f
/// mul   r0, r1, r0         @ decoded signed count
/// cmp   r0, #0 / movle r0, #0 / movgt r0, #1 / cmp r0, #0
/// mvneq r4, #0             @ decoded <= 0 -> -1
/// movne r4, #1             @ decoded  > 0 -> +1
/// mov   r0, r4
/// pop   {r4, r5, pc}
/// ```
///
/// The callee [`encoded_word_block_is_zero`] is the family's all-limbs-zero
/// scan. It is a direct Rust call on both host and target; the header is
/// re-read after it returns, exactly like the original's post-call
/// `ldr r0, [r5]`.
///
/// `block` must point to a readable [`EncodedWordBlock`]. When the scan
/// reads limbs (the decoded count's wrapping absolute value is at least 1),
/// the `words` array must contain at least that many readable words; retailOS
/// has no NULL guard on either field.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn encoded_word_block_sign(block: *const EncodedWordBlock) -> i32 {
    if encoded_word_block_is_zero(block) != 0 {
        return 0;
    }
    let decoded_count = (*block).encoded_count.wrapping_mul(ENCODED_COUNT_MULTIPLIER);
    if decoded_count > 0 {
        1
    } else {
        -1
    }
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
        copy_encoded_word_block, copy_encoded_word_block_checked, copy_encoded_word_block_from,
        copy_inline_encoded_word_block, encoded_word_block_is_zero, encoded_word_block_set_int,
        encoded_word_block_sign, inline_encoded_word_block_compare, EncodedWordBlock,
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
    fn checked_copies_positive_and_negative_decoded_counts() {
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

            assert_eq!(unsafe { copy_encoded_word_block_checked(&mut destination, &source) }, 0);
            assert_eq!(destination.encoded_count, source.encoded_count);
            assert_eq!(&destination_words[..3], &source_words[..3]);
            assert_eq!(destination_words[3], 0xdead_beef);
        }
    }

    #[test]
    fn checked_accepts_28_and_rejects_29_before_destination_writes() {
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
                unsafe { copy_encoded_word_block_checked(&mut destination, &source) },
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
    fn checked_copies_overlapping_words_in_descending_index_order() {
        let mut words = [10, 20, 30, 0];
        let source = EncodedWordBlock {
            encoded_count: encoded_count(3),
            words: words.as_mut_ptr(),
        };
        let mut destination = EncodedWordBlock {
            encoded_count: encoded_count(1),
            words: unsafe { words.as_mut_ptr().add(1) },
        };

        assert_eq!(unsafe { copy_encoded_word_block_checked(&mut destination, &source) }, 0);
        assert_eq!(words, [10, 10, 20, 30]);
        assert_eq!(destination.encoded_count, source.encoded_count);
    }

    #[test]
    fn checked_self_copy_preserves_wrapping_minimum_count_behavior() {
        let mut block = EncodedWordBlock {
            encoded_count: i32::MIN,
            words: core::ptr::null_mut(),
        };
        let block_ptr = &mut block as *mut EncodedWordBlock;

        assert_eq!(unsafe { copy_encoded_word_block_checked(block_ptr, block_ptr) }, 0);
        assert_eq!(block.encoded_count, i32::MIN);
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


    fn sign_of(block: &EncodedWordBlock) -> i32 {
        unsafe { encoded_word_block_sign(block) }
    }

    #[test]
    fn sign_of_zero_count_is_zero_without_reading_words() {
        // Decoded count 0: the limb scan returns 1 before touching
        // `words`, so a NULL words pointer must be safe.
        let block = EncodedWordBlock {
            encoded_count: 0,
            words: core::ptr::null_mut(),
        };
        assert_eq!(sign_of(&block), 0);
    }

    #[test]
    fn sign_of_all_zero_limbs_is_zero_regardless_of_header() {
        // Nonzero decoded counts, but every stored limb is raw zero; the
        // decode multiplier is invertible, so zero limbs decode to zero
        // and the block reads as the value 0 under either header sign.
        let mut words = [0u32; 3];
        for decoded_count in [3, -2] {
            let block = EncodedWordBlock {
                encoded_count: encoded_count(decoded_count),
                words: words.as_mut_ptr(),
            };
            assert_eq!(sign_of(&block), 0, "decoded_count {decoded_count}");
        }
    }

    #[test]
    fn sign_follows_the_header_of_a_nonzero_block() {
        for (value, expected) in [
            (1, 1),
            (7, 1),
            (0x1234_5678, 1),
            (i32::MAX, 1),
            (-1, -1),
            (-0x0bad_f00d, -1),
            (i32::MAX.wrapping_neg(), -1),
            (i32::MIN, -1),
        ] {
            let mut words = [0u32; 2];
            let mut block = EncodedWordBlock {
                encoded_count: 0,
                words: words.as_mut_ptr(),
            };
            assert_eq!(unsafe { encoded_word_block_set_int(value, &mut block) }, 0);
            assert_eq!(sign_of(&block), expected, "value {value:#x}");
        }
    }

    #[test]
    fn sign_scans_limbs_high_to_low_and_stops_at_the_first_nonzero() {
        // A nonzero limb at ANY scanned index makes the block nonzero;
        // the header's sign then decides, not the limb's position.
        let mut words = [0u32; 3];
        for nonzero_index in [0usize, 1, 2] {
            words = [0; 3];
            words[nonzero_index] = 9u32.wrapping_mul(ENCODED_WORD_MULTIPLIER);
            for (decoded_count, expected) in [(3, 1), (-3, -1)] {
                let block = EncodedWordBlock {
                    encoded_count: encoded_count(decoded_count),
                    words: words.as_mut_ptr(),
                };
                assert_eq!(
                    sign_of(&block),
                    expected,
                    "nonzero_index {nonzero_index}, decoded_count {decoded_count}"
                );
            }
        }
    }

    #[test]
    fn sign_of_min_decoded_count_is_zero_without_reading_words() {
        // Header chosen so encoded_count * 0x0a7e377f == i32::MIN: its
        // wrapping absolute value stays negative, the scan returns 1 and
        // `words` is never read.
        let header = (i32::MIN as u32).wrapping_mul(ENCODED_COUNT_INVERSE) as i32;
        assert_eq!(
            header.wrapping_mul(super::ENCODED_COUNT_MULTIPLIER),
            i32::MIN
        );
        let block = EncodedWordBlock {
            encoded_count: header,
            words: core::ptr::null_mut(),
        };
        assert_eq!(sign_of(&block), 0);
    }
    #[test]
    fn zero_scan_handles_zero_and_minimum_counts_without_reading_words() {
        let minimum_header =
            (i32::MIN as u32).wrapping_mul(ENCODED_COUNT_INVERSE) as i32;
        for encoded_count in [0, minimum_header] {
            let block = EncodedWordBlock {
                encoded_count,
                words: core::ptr::null_mut(),
            };
            assert_eq!(unsafe { encoded_word_block_is_zero(&block) }, 1);
        }
    }

    #[test]
    fn zero_scan_checks_absolute_count_descending_and_ignores_trailing_words() {
        for decoded_count in [3, -3] {
            let mut words = [0u32, 0, 0, 0xfeed_face];
            let block = EncodedWordBlock {
                encoded_count: encoded_count(decoded_count),
                words: words.as_mut_ptr(),
            };
            assert_eq!(unsafe { encoded_word_block_is_zero(&block) }, 1);

            for index in 0..3 {
                words = [0, 0, 0, 0xfeed_face];
                words[index] = 9u32.wrapping_mul(ENCODED_WORD_MULTIPLIER);
                assert_eq!(
                    unsafe { encoded_word_block_is_zero(&block) },
                    0,
                    "decoded_count {decoded_count}, nonzero index {index}"
                );
            }
        }
    }


}
