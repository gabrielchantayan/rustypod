//! Narrow six record words to halfwords: `FUN_08056234` at **0x08056234**.
//!
//! Raw A32 establishes the 60-byte extent `[0x08056234, 0x08056270)`;
//! the next function is `mov r0,#0; bx lr` at 0x08056270. Whole-image
//! aligned BL decoding finds two plain incoming calls (0x0804762c and
//! 0x0806c9c0), zero predicated incoming calls, and zero outgoing calls.
//!
//! Read six aligned u32 words in order, immediately storing each low u16
//! into the corresponding output halfword, and return status zero. Both
//! filesystem callers use a 12-byte output buffer in their 0x4244 path.
//! The precise record-format identity is not established. No deliberate
//! behavioral deviations; ordered volatile accesses preserve overlapping
//! buffers and prevent combining loads across intervening stores.

/// # Safety
/// `words` must allow six aligned u32 reads and `halfwords` six aligned
/// u16 writes. Buffers may overlap; all accessed bytes must be initialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_words_to_halfwords(words: *const u32, halfwords: *mut u16) -> u32 {
    for index in 0..6 {
        let word = words.add(index).read_volatile();
        halfwords.add(index).write_volatile(word as u16);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_without_saturation_and_preserves_output_bounds() {
        for words in [
            [0; 6],
            [u32::MAX; 6],
            [0x12340000, 0xabcdffff, 0x80008000, 0x7fff7fff, 0x00010001, 0xffff1234],
        ] {
            let mut output = [0xa55au16; 8];
            let status = unsafe { record_words_to_halfwords(words.as_ptr(), output.as_mut_ptr().add(1)) };
            assert_eq!(status, 0);
            assert_eq!(output[0], 0xa55a);
            assert_eq!(output[7], 0xa55a);
            for index in 0..6 {
                assert_eq!(output[index + 1], (words[index] & 0xffff) as u16);
            }
        }
    }

    #[test]
    fn overlapping_buffers_follow_sequential_load_store_order() {
        // Reference the original's little-endian memory accesses, including
        // writes that change words not yet read. Cover both overlap directions.
        for source_start in [0usize, 8] {
            for destination_start in (0usize..=32).step_by(2) {
                let mut storage = [0x11223344u32, 0x55667788, 0x99aabbcc, 0xddeeff00,
                    0x12345678, 0xabcdef01, 0x87654321, 0x10203040,
                    0x50607080, 0x90a0b0c0, 0xd0e0f001];
                let mut expected = [0u8; 44];
                for (index, word) in storage.iter().enumerate() {
                    expected[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                for index in 0..6 {
                    let source = source_start + index * 4;
                    let low = [expected[source], expected[source + 1]];
                    let destination = destination_start + index * 2;
                    expected[destination..destination + 2].copy_from_slice(&low);
                }
                unsafe {
                    let bytes = storage.as_mut_ptr().cast::<u8>();
                    assert_eq!(record_words_to_halfwords(bytes.add(source_start).cast(),
                        bytes.add(destination_start).cast()), 0);
                }
                for (index, word) in storage.iter().enumerate() {
                    assert_eq!(word.to_le_bytes(), expected[index * 4..index * 4 + 4]);
                }
            }
        }
    }
}
