//! `inline_encoded_word_block_to_bytes` — expand an inline encoded-word block
//! into scaled bytes, writing from the end of the destination.
//!
//! Original: `FUN_0831fff0` @ 0x0831fff0 (184-byte full extent:
//! 168-byte instruction body at 0x0831fff0..0x08320098, followed by the
//! four-word literal pool at 0x0832009c..0x083200a4; next real function
//! starts at 0x083200a8). Raw ARM decoding finds no outbound plain or predicated
//! `bl` instructions. Complete-image ARM decoding finds two inbound plain
//! `bl` instructions at 0x0830a8e0 and 0x083192f8; neither is predicated.
//! The signed inline count is decoded with `0x4b6143ff`, then its wrapping
//! absolute value sets the required four bytes per payload word. A destination
//! shorter than that is left untouched and returns `0xffff5bde`. Otherwise
//! payload words are decoded with `0x3399e27f`; their low-to-high bytes are
//! multiplied modulo 256 by `0xb7` and placed from the destination end toward
//! its start. Extra destination bytes become zero. The final encoded payload
//! word read (or zero for padding/an empty output) remains in r0.
//!
//! Deliberate deviation: the source is typed as word-addressable rather than
//! `InlineEncodedWordBlock`, because its payload is inline and the target ABI
//! only requires a pointer to its first word.

const ENCODED_COUNT_MULTIPLIER: i32 = 0x4b61_43ff;
const ENCODED_WORD_MULTIPLIER: u32 = 0x3399_e27f;
const OUTPUT_BYTE_MULTIPLIER: u8 = 0xb7;
const OUTPUT_TOO_SHORT: u32 = 0xffff_5bde;

/// Expands an inline encoded-word block into a reverse-filled scaled byte buffer.
///
/// # Safety
/// `source` must address an encoded count followed by enough readable payload
/// words for its decoded count. `destination` must address `destination_len`
/// writable bytes when the length check succeeds.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn inline_encoded_word_block_to_bytes(
    source: *const u32,
    destination: *mut u8,
    destination_len: u32,
) -> u32 {
    let decoded_count = (*source as i32).wrapping_mul(ENCODED_COUNT_MULTIPLIER);
    let word_count = if decoded_count < 0 {
        decoded_count.wrapping_neg()
    } else {
        decoded_count
    };

    if destination_len < (word_count as u32).wrapping_shl(2) {
        return OUTPUT_TOO_SHORT;
    }

    let mut remaining = destination_len;
    let mut byte_shift = 32u32;
    let mut word_index = 0i32;
    let mut encoded_word = 0u32;

    while remaining != 0 {
        if byte_shift == 32 {
            encoded_word = 0;
            if word_index < word_count {
                word_index = word_index.wrapping_add(1);
                encoded_word = (*source.add(word_index as usize)).wrapping_mul(ENCODED_WORD_MULTIPLIER);
            }
            byte_shift = 0;
        }

        remaining -= 1;
        let output_byte = ((encoded_word >> byte_shift) as u8).wrapping_mul(OUTPUT_BYTE_MULTIPLIER);
        *destination.add(remaining as usize) = output_byte;
        byte_shift += 8;
    }

    encoded_word
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED_COUNT_INVERSE: u32 = 0xda8e_bbff;
    const ENCODED_WORD_INVERSE: u32 = 0xff5f_dd7f;
    fn encoded_count(count: i32) -> u32 {
        (count as u32).wrapping_mul(ENCODED_COUNT_INVERSE)
    }

    fn encoded_word(word: u32) -> u32 {
        word.wrapping_mul(ENCODED_WORD_INVERSE)
    }

    #[test]
    fn expands_words_low_byte_first_at_destination_end() {
        let source = [encoded_count(2), encoded_word(0x4433_2211), encoded_word(0x8877_6655)];
        let mut destination = [0xa5; 12];

        let result = unsafe {
            inline_encoded_word_block_to_bytes(source.as_ptr(), destination.as_mut_ptr(), destination.len() as u32)
        };

        assert_eq!(result, 0);
        assert_eq!(destination, [0, 0, 0, 0, 0x38, 0x11, 0xea, 0xc3, 0x9c, 0x75, 0x4e, 0x27]);
    }

    #[test]
    fn rejects_a_short_destination_without_writing() {
        let source = [encoded_count(-2), encoded_word(0x4433_2211), encoded_word(0x8877_6655)];
        let mut destination = [0xa5; 7];

        let result = unsafe {
            inline_encoded_word_block_to_bytes(source.as_ptr(), destination.as_mut_ptr(), destination.len() as u32)
        };

        assert_eq!(result, OUTPUT_TOO_SHORT);
        assert_eq!(destination, [0xa5; 7]);
    }

    #[test]
    fn minimum_count_wraps_to_an_empty_source_and_zero_fills() {
        let source = [encoded_count(i32::MIN)];
        let mut destination = [0xa5; 3];

        let result = unsafe {
            inline_encoded_word_block_to_bytes(source.as_ptr(), destination.as_mut_ptr(), destination.len() as u32)
        };

        assert_eq!(result, 0);
        assert_eq!(destination, [0; 3]);
    }
}
