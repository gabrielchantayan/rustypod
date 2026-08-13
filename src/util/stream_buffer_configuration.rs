//! Initial stream-buffer word configuration — `stream_buffer_configure_words` @ 0x08006b48.
//!
//! The sole recovered caller is the RAM stream-buffer constructor at 0x080073f0.
//! That constructor clears its counters and its 32 per-page bookkeeping words, then
//! invokes this leaf with 0x400.  The surrounding producer/consumer helpers show
//! that +0x1c is a word-scaled capacity used for byte arithmetic, +0x20 is the
//! initial free-word count, and +0x30 retains the configured word count.
//!
//! The original is a three-store leaf: retain `word_count` at +0x30, store its
//! wrapping `word_count << 2` byte capacity at +0x1c, clear +0x20, then return
//! zero.  Byte-addressed `u32` fields preserve the retailOS offsets on both the
//! 32-bit target and 64-bit host.

/// stream_buffer_configure_words — original: `FUN_08006b48` @ 0x08006b48
/// (28 bytes).
///
/// Configures a stream buffer's word capacity. Stores `word_count` at +0x30,
/// its wrapping byte equivalent at +0x1c, clears the free-word count at +0x20,
/// and returns zero.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_buffer_configure_words(
    stream_buffer: *mut u8,
    word_count: u32,
) -> u32 {
    const BYTE_CAPACITY_OFFSET: usize = 0x1c;
    const FREE_WORD_COUNT_OFFSET: usize = 0x20;
    const WORD_COUNT_OFFSET: usize = 0x30;

    stream_buffer
        .add(WORD_COUNT_OFFSET)
        .cast::<u32>()
        .write_volatile(word_count);
    stream_buffer
        .add(BYTE_CAPACITY_OFFSET)
        .cast::<u32>()
        .write_volatile(word_count.wrapping_shl(2));
    stream_buffer
        .add(FREE_WORD_COUNT_OFFSET)
        .cast::<u32>()
        .write_volatile(0);
    0
}

#[cfg(test)]
mod tests {
    use super::stream_buffer_configure_words;

    const BYTE_CAPACITY_OFFSET: usize = 0x1c;
    const FREE_WORD_COUNT_OFFSET: usize = 0x20;
    const WORD_COUNT_OFFSET: usize = 0x30;

    #[repr(align(4))]
    struct StreamBuffer([u8; 0x40]);

    impl StreamBuffer {
        fn poisoned() -> Self {
            StreamBuffer([0xa5; 0x40])
        }

        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
        }
    }

    #[test]
    fn configures_word_and_byte_capacities_and_clears_free_words() {
        let mut stream_buffer = StreamBuffer::poisoned();

        assert_eq!(
            unsafe { stream_buffer_configure_words(stream_buffer.0.as_mut_ptr(), 0x400) },
            0
        );

        assert_eq!(stream_buffer.word(WORD_COUNT_OFFSET), 0x400);
        assert_eq!(stream_buffer.word(BYTE_CAPACITY_OFFSET), 0x1000);
        assert_eq!(stream_buffer.word(FREE_WORD_COUNT_OFFSET), 0);
    }

    #[test]
    fn byte_capacity_uses_the_arm_logical_left_shift_width() {
        for word_count in [0, 1, 0x3fff_ffff, 0x4000_0000, u32::MAX] {
            let mut stream_buffer = StreamBuffer::poisoned();

            assert_eq!(
                unsafe {
                    stream_buffer_configure_words(stream_buffer.0.as_mut_ptr(), word_count)
                },
                0,
                "word count {word_count:#x}"
            );
            assert_eq!(stream_buffer.word(WORD_COUNT_OFFSET), word_count);
            assert_eq!(
                stream_buffer.word(BYTE_CAPACITY_OFFSET),
                word_count.wrapping_shl(2),
                "word count {word_count:#x}"
            );
            assert_eq!(stream_buffer.word(FREE_WORD_COUNT_OFFSET), 0);
        }
    }

    #[test]
    fn leaves_every_other_byte_untouched() {
        let mut stream_buffer = StreamBuffer::poisoned();
        unsafe { stream_buffer_configure_words(stream_buffer.0.as_mut_ptr(), 0x1234_5678) };

        for offset in 0..stream_buffer.0.len() {
            if (BYTE_CAPACITY_OFFSET..BYTE_CAPACITY_OFFSET + 4).contains(&offset)
                || (FREE_WORD_COUNT_OFFSET..FREE_WORD_COUNT_OFFSET + 4).contains(&offset)
                || (WORD_COUNT_OFFSET..WORD_COUNT_OFFSET + 4).contains(&offset)
            {
                continue;
            }
            assert_eq!(stream_buffer.0[offset], 0xa5, "byte +{offset:#x}");
        }
    }
}
