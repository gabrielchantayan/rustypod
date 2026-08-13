//! Page-context initialization for the RAM stream buffer.
//!
//! The surrounding buffer initialization routines establish a 32-page,
//! 0x20000-byte circular buffer.  Per-page context words occupy +0x34..+0xb0;
//! the current-page lookup at 0x0800722c falls back to the context word at
//! +0x13c when its event-loop callback is active.

/// Kept in addressable storage so the fixed retailOS trip count remains a
/// loop in the freestanding ARM code rather than being unrolled into 32 stores.
static PAGE_CONTEXT_COUNT: usize = 32;


/// stream_buffer_set_page_contexts — original: `FUN_080071b0` @ 0x080071b0
/// (32 bytes).
///
/// Stores `page_context` as the stream buffer's fallback context at +0x13c,
/// then fills all 32 per-page context words at +0x34 through +0xb0 inclusive.
/// Callers use this during buffer initialization, and the producer records the
/// supplied context in the entry for every page it writes.  The byte-addressed
/// layout preserves the retailOS 32-bit offsets on both ARM and 64-bit hosts.
///
/// Deliberate deviation: volatile stores prevent LLVM from recognizing the
/// fill as a libc call, which the freestanding ARM payload cannot link. The
/// volatile trip count also retains the original's loop rather than unrolling
/// its 32 independent stores.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_buffer_set_page_contexts(
    stream_buffer: *mut u8,
    page_context: u32,
) {
    const PAGE_CONTEXTS_OFFSET: usize = 0x34;
    let page_context_count = core::ptr::read_volatile(&PAGE_CONTEXT_COUNT);
    const FALLBACK_CONTEXT_OFFSET: usize = 0x13c;

    stream_buffer
        .add(FALLBACK_CONTEXT_OFFSET)
        .cast::<u32>()
        .write_volatile(page_context);

    for page_index in 0..page_context_count {
        stream_buffer
            .add(PAGE_CONTEXTS_OFFSET + page_index * core::mem::size_of::<u32>())
            .cast::<u32>()
            .write_volatile(page_context);
    }
}

#[cfg(test)]
mod tests {
    use super::stream_buffer_set_page_contexts;

    const PAGE_CONTEXTS_OFFSET: usize = 0x34;
    const PAGE_CONTEXT_COUNT: usize = 32;
    const FALLBACK_CONTEXT_OFFSET: usize = 0x13c;

    #[repr(align(4))]
    struct StreamBuffer([u8; 0x140]);

    impl StreamBuffer {
        fn new(fill: u8) -> Self {
            Self([fill; 0x140])
        }

        fn word_at(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.0[offset..offset + core::mem::size_of::<u32>()].try_into().unwrap())
        }
    }

    #[test]
    fn initializes_every_page_context_and_the_fallback_context() {
        let mut buffer = StreamBuffer::new(0xa5);
        let context = 0x38c4_1e72;

        unsafe { stream_buffer_set_page_contexts(buffer.0.as_mut_ptr(), context) };

        assert_eq!(buffer.word_at(FALLBACK_CONTEXT_OFFSET), context);
        for page_index in 0..PAGE_CONTEXT_COUNT {
            assert_eq!(
                buffer.word_at(PAGE_CONTEXTS_OFFSET + page_index * core::mem::size_of::<u32>()),
                context,
                "page {page_index}",
            );
        }
    }

    #[test]
    fn overwrites_old_contexts_without_touching_adjacent_layout_fields() {
        let mut buffer = StreamBuffer::new(0xa5);
        for page_index in 0..PAGE_CONTEXT_COUNT {
            let offset = PAGE_CONTEXTS_OFFSET + page_index * core::mem::size_of::<u32>();
            buffer.0[offset..offset + 4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        }
        buffer.0[FALLBACK_CONTEXT_OFFSET..FALLBACK_CONTEXT_OFFSET + 4]
            .copy_from_slice(&0xdead_beefu32.to_le_bytes());

        unsafe { stream_buffer_set_page_contexts(buffer.0.as_mut_ptr(), 0) };

        for page_index in 0..PAGE_CONTEXT_COUNT {
            assert_eq!(
                buffer.word_at(PAGE_CONTEXTS_OFFSET + page_index * core::mem::size_of::<u32>()),
                0,
            );
        }
        assert_eq!(buffer.word_at(FALLBACK_CONTEXT_OFFSET), 0);

        for (offset, byte) in buffer.0.iter().copied().enumerate() {
            let in_page_contexts = (PAGE_CONTEXTS_OFFSET..PAGE_CONTEXTS_OFFSET + PAGE_CONTEXT_COUNT * 4)
                .contains(&offset);
            let in_fallback_context = (FALLBACK_CONTEXT_OFFSET..FALLBACK_CONTEXT_OFFSET + 4).contains(&offset);
            if !in_page_contexts && !in_fallback_context {
                assert_eq!(byte, 0xa5, "unexpected write at +{offset:#x}");
            }
        }
    }
}
