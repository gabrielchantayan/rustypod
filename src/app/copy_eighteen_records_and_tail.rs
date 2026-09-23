//! `copy_eighteen_records_and_tail` — original: `FUN_081d6034` @ `0x081d6034`
//! (84 bytes, `0x081d6034..0x081d6087`; the next real function begins at
//! `0x081d6088`). Raw A32 decoding finds three inbound unconditional plain
//! `bl` sites (`0x08208210`, `0x0821462c`, and `0x0822aaf0`), no predicated
//! inbound `bl` sites, and one outbound plain `bl` at `0x081d6064` through
//! the IRAM memcpy veneer to `memcpy_forward_words`.
//!
//! It preserves the destination's leading word, then copies 18 consecutive
//! 36-byte records beginning at +4. Each record's final word is assigned
//! before the preceding 32 bytes are copied through the aligned ADS memcpy
//! body. It then copies the two trailing words at +0x28c and +0x290.
//!
//! # Deliberate deviations
//!
//! The IRAM veneer is represented by the already-ported `memcpy_forward_words`
//! body; its returned advanced destination is not observable here and is
//! discarded exactly as the ARM caller discards r0.

use crate::libc::memcpy::memcpy_forward_words;

const RECORD_COUNT: usize = 18;
const RECORD_SIZE: usize = 36;
const RECORD_PAYLOAD_OFFSET: usize = 4;
const RECORD_PAYLOAD_SIZE: usize = 32;
const FIRST_TRAILING_WORD_OFFSET: usize = 0x28c;
const SECOND_TRAILING_WORD_OFFSET: usize = 0x290;

/// Copy the fixed 18-record region and two trailing words, preserving `dst + 0`.
///
/// # Safety
///
/// `dst` and `src` must be four-byte aligned and valid for 0x294 readable and
/// writable bytes respectively. The copied ranges must satisfy the forward-copy
/// overlap requirements of `memcpy_forward_words`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_eighteen_records_and_tail(dst: *mut u8, src: *const u8) -> *mut u8 {
    for record in 0..RECORD_COUNT {
        let record_offset = record * RECORD_SIZE;
        dst.add(record_offset + RECORD_SIZE).cast::<u32>().write(
            src.add(record_offset + RECORD_SIZE).cast::<u32>().read(),
        );
        memcpy_forward_words(
            dst.add(record_offset + RECORD_PAYLOAD_OFFSET),
            src.add(record_offset + RECORD_PAYLOAD_OFFSET),
            RECORD_PAYLOAD_SIZE,
        );
    }

    dst.add(FIRST_TRAILING_WORD_OFFSET).cast::<u32>().write(
        src.add(FIRST_TRAILING_WORD_OFFSET).cast::<u32>().read(),
    );
    dst.add(SECOND_TRAILING_WORD_OFFSET).cast::<u32>().write(
        src.add(SECOND_TRAILING_WORD_OFFSET).cast::<u32>().read(),
    );
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const WORD_COUNT: usize = (SECOND_TRAILING_WORD_OFFSET + 4) / 4;

    fn words(seed: u32) -> [u32; WORD_COUNT] {
        core::array::from_fn(|index| seed.wrapping_add((index as u32).wrapping_mul(0x0101_0101)))
    }

    #[test]
    fn preserves_leading_word_and_copies_every_subsequent_word() {
        let src = words(0x1020_3040);
        let mut dst = words(0xa0b0_c0d0);
        let leading_destination_word = dst[0];

        let result = unsafe {
            copy_eighteen_records_and_tail(dst.as_mut_ptr().cast(), src.as_ptr().cast())
        };

        assert_eq!(result, dst.as_mut_ptr().cast());
        assert_eq!(dst[0], leading_destination_word);
        assert_eq!(&dst[1..], &src[1..]);
    }

    #[test]
    fn copies_record_boundaries_and_trailing_words() {
        let mut src = [0u32; WORD_COUNT];
        let mut dst = [0xffff_ffffu32; WORD_COUNT];
        for record in 0..RECORD_COUNT {
            let first = 1 + record * (RECORD_SIZE / 4);
            src[first] = 0x1000 + record as u32;
            src[first + 7] = 0x2000 + record as u32;
            src[first + 8] = 0x3000 + record as u32;
        }
        src[FIRST_TRAILING_WORD_OFFSET / 4] = 0xfeed_beef;
        src[SECOND_TRAILING_WORD_OFFSET / 4] = 0xcafe_babe;

        unsafe { copy_eighteen_records_and_tail(dst.as_mut_ptr().cast(), src.as_ptr().cast()) };

        assert_eq!(dst[0], 0xffff_ffff);
        for record in 0..RECORD_COUNT {
            let first = 1 + record * (RECORD_SIZE / 4);
            assert_eq!(dst[first], 0x1000 + record as u32);
            assert_eq!(dst[first + 7], 0x2000 + record as u32);
            assert_eq!(dst[first + 8], 0x3000 + record as u32);
        }
        assert_eq!(dst[FIRST_TRAILING_WORD_OFFSET / 4], 0xfeed_beef);
        assert_eq!(dst[SECOND_TRAILING_WORD_OFFSET / 4], 0xcafe_babe);
    }
}
