//! Stream-buffer producer-page counter reset.
//!
//! `stream_buffer_reset_producer_page_count` — original: `FUN_08007284`
//! @ 0x08007284 (16 bytes; one recovered `bl` call site, in the media
//! startup path at 0x080056d0).
//!
//! The caller first obtains the RAM stream buffer from its lazy initializer
//! at 0x08006e88, which returns that object in `r0`, then calls this leaf.
//! The word at `StreamBuffer + 0x28` is initialized to zero by the buffer
//! constructor at 0x080073f0 and incremented by the producer path at
//! 0x08006b64 when it reaches an exhausted page. This function resets that
//! producer-page count after the media setup succeeds. It performs exactly
//! one aligned word store and returns zero; no other object byte is read or
//! written.

/// Byte offset of the stream buffer's producer-page count.
const PRODUCER_PAGE_COUNT_OFFSET: usize = 0x28;

/// stream_buffer_reset_producer_page_count — original: `FUN_08007284`
/// @ 0x08007284 (16 bytes; one recovered `bl` call site).
///
/// Clears the stream buffer's producer-page count and returns the retailOS
/// success value, zero. `stream_buffer` must identify an aligned, writable
/// stream-buffer object, as it does after 0x08006e88 returns it in `r0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_reset_producer_page_count(
    stream_buffer: *mut u8,
) -> u32 {
    (stream_buffer.add(PRODUCER_PAGE_COUNT_OFFSET) as *mut u32).write(0);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sized beyond the reset word and word-aligned like the retail object.
    #[repr(align(4))]
    struct StreamBuffer([u8; 0x40]);

    #[test]
    fn clears_only_the_producer_page_count_and_returns_zero() {
        let mut stream_buffer = StreamBuffer([0xa5; 0x40]);
        stream_buffer.0[PRODUCER_PAGE_COUNT_OFFSET..PRODUCER_PAGE_COUNT_OFFSET + 4]
            .copy_from_slice(&0xdead_beefu32.to_le_bytes());

        let result = unsafe {
            stream_buffer_reset_producer_page_count(stream_buffer.0.as_mut_ptr())
        };

        assert_eq!(result, 0);
        for (offset, &byte) in stream_buffer.0.iter().enumerate() {
            let expected = if (PRODUCER_PAGE_COUNT_OFFSET..PRODUCER_PAGE_COUNT_OFFSET + 4)
                .contains(&offset)
            {
                0
            } else {
                0xa5
            };
            assert_eq!(byte, expected, "byte +{offset:#x}");
        }
    }
}
