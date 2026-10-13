//! Reset auxiliary page state and replace RAM stream-buffer contexts.
//!
//! Original: `FUN_08007294` @ 0x08007294, 44 bytes, ending at 0x080072c0.
//! Verified raw call count: one plain BL to 0x080071b0, zero predicated BLs;
//! two incoming plain BLs at 0x080054f8 and 0x08005590.
//! Clears 32 auxiliary page words at +0xb8..+0x134, then sets all page
//! contexts and the fallback context using the unchanged incoming r1.
//! Returns zero. Ghidra omits that second argument; raw ARM preserves it.
//!
//! Deliberate deviations: volatile stores prevent libc fill substitution;
//! a volatile trip count retains the stock loop, following the context setter.
//! LLVM inlines the existing Rust context setter in place of the firmware BL;
//! ARM codegen retains both fill loops, the fallback store, and zero return.

use crate::kernel::stream_buffer_page_contexts::stream_buffer_set_page_contexts;

static PAGE_COUNT: usize = 32;

/// # Safety
/// `stream_buffer` must reference writable, four-byte-aligned storage through
/// offset +0x13f, with exclusive access to the fields written here.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_reset_page_state(
    stream_buffer: *mut u8,
    page_context: u32,
) -> u32 {
    let page_count = core::ptr::read_volatile(&PAGE_COUNT);
    for page_index in 0..page_count {
        stream_buffer.add(0xb8 + page_index * 4).cast::<u32>().write_volatile(0);
    }
    stream_buffer_set_page_contexts(stream_buffer, page_context);
    0
}

#[cfg(test)]
mod tests {
    use super::stream_buffer_reset_page_state;

    #[test]
    fn resets_auxiliary_words_and_replaces_contexts_without_other_writes() {
        for context in [0, 0x38c4_1e72, u32::MAX] {
            // Word layout is identical on the host and ARM; include sentinels
            // before and after the complete object and distinct old values.
            let mut storage = [0u32; 0x150 / 4];
            for (index, word) in storage.iter_mut().enumerate() {
                *word = 0xa500_0000 | index as u32;
            }
            let before = storage;
            let object_start = 1;
            let result = unsafe {
                stream_buffer_reset_page_state(
                    storage.as_mut_ptr().add(object_start).cast::<u8>(), context,
                )
            };
            assert_eq!(result, 0);
            for (index, word) in storage.iter().copied().enumerate() {
                let offset = index.checked_sub(object_start).map(|word| word * 4);
                let expected = match offset {
                    Some(0xb8..=0x134) => 0,
                    Some(0x34..=0xb0) | Some(0x13c) => context,
                    _ => before[index],
                };
                assert_eq!(word, expected, "word {index}, context {context:#x}");
            }
        }
    }
}
