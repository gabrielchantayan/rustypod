//! vector_copy_range_elem16 — original: `FUN_083e8934` @ 0x083e8934
//! (52 bytes, `0x083e8934..0x083e8968`; the next independently linked
//! function starts at 0x083e8968). Raw A32 decoding finds two inbound plain
//! `bl` sites (0x083e04a4 and 0x083e04e0), zero inbound predicated `bl` sites,
//! and no body calls.
//!
//! Algorithm: copies each aligned 16-byte record in `[first, last)` to
//! `output`, but only while the current output cursor is non-null. Each
//! iteration loads all four source words before storing any destination word,
//! then advances both cursors by 16 bytes and returns the advanced output
//! cursor. A null initial output skips only the first record; its wrapped
//! advance makes later iterations write through address 0x10. Deliberate
//! deviations: none; `wrapping_add` represents the ARM cursor advance without
//! imposing host in-bounds pointer-arithmetic requirements.

/// Copies a half-open range of 16-byte trivially copyable vector records.
///
/// # Safety
///
/// `first` and `last` must delimit a range reachable in positive 16-byte
/// steps. When `output` is non-null, source and destination records must be
/// four-byte aligned and valid for every copied element. The original is a
/// forward copy with no overlap guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_copy_range_elem16")]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_range_elem16(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            let source = first.cast::<u32>();
            let word0 = source.read();
            let word1 = source.add(1).read();
            let word2 = source.add(2).read();
            let word3 = source.add(3).read();
            let destination = output.cast::<u32>();
            destination.write(word0);
            destination.add(1).write(word1);
            destination.add(2).write(word2);
            destination.add(3).write(word3);
        }
        first = first.wrapping_add(16);
        output = output.wrapping_add(16);
    }
    output
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::vector_copy_range_elem16;

    #[test]
    fn empty_range_returns_output_without_accessing_input() {
        let mut output = [0xa5u8; 16];
        let first = core::ptr::NonNull::<u8>::dangling().as_ptr();
        let result = unsafe { vector_copy_range_elem16(first, first, output.as_mut_ptr()) };
        assert_eq!(result, output.as_mut_ptr());
        assert_eq!(output, [0xa5; 16]);
    }

    #[test]
    fn copies_complete_records_and_returns_advanced_output() {
        let mut input = [0u32; 12];
        for (index, word) in input.iter_mut().enumerate() {
            *word = 0x1100_0000 | index as u32;
        }
        let mut output = [0u32; 12];
        let result = unsafe {
            vector_copy_range_elem16(
                input.as_ptr().cast(),
                input.as_ptr().cast::<u8>().add(48),
                output.as_mut_ptr().cast(),
            )
        };
        assert_eq!(output, input);
        assert_eq!(result, unsafe { output.as_mut_ptr().cast::<u8>().add(48) });
    }

    #[test]
    fn null_output_skips_exactly_one_record_without_reading_input() {
        let first = core::ptr::NonNull::<u8>::dangling().as_ptr();
        let last = first.wrapping_add(16);
        let result = unsafe { vector_copy_range_elem16(first, last, core::ptr::null_mut()) };
        assert_eq!(result.addr(), 16);
    }

    #[test]
    fn preserves_per_record_grouped_load_before_store_overlap() {
        let mut words = [0u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            *word = index as u32;
        }
        let mut expected = words;
        for record in 0..2 {
            let source_word = record * 4;
            let output_word = source_word + 2;
            let copied = [
                expected[source_word],
                expected[source_word + 1],
                expected[source_word + 2],
                expected[source_word + 3],
            ];
            expected[output_word..output_word + 4].copy_from_slice(&copied);
        }
        let base = words.as_mut_ptr().cast::<u8>();
        unsafe {
            vector_copy_range_elem16(base, base.add(32), base.add(8));
        }
        assert_eq!(words, expected);
    }
}
