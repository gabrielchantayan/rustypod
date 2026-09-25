//! vector_uninitialized_copy_elem24 — original: `FUN_083e8c74` @ 0x083e8c74
//! (60 bytes, `0x083e8c74..0x083e8caf`; the next real function starts at
//! 0x083e8cb0). Raw A32 decoding finds two inbound unconditional plain `bl`
//! sites (0x083e1fa8 and 0x083e20a4), zero inbound predicated `bl` sites, and
//! one outbound predicated `blne` to the IRAM memcpy veneer at 0x08037df8.
//!
//! Algorithm: for each aligned 24-byte record in `[first, last)`, copy it to
//! `output` only when `output` is non-null, then advance both cursors. Return
//! the advanced output cursor. A null output suppresses only that iteration's
//! copy; after the mandatory 24-byte advance, later iterations copy through
//! the non-null wrapped cursor. The fourth ABI argument is retained but unread.
//! Deliberate deviation: Rust calls the already-ported memcpy body rather than
//! the IRAM veneer, preserving its grouped forward-copy behavior and return
//! value. A target-only unique text section prevents LLVM from folding this
//! separate retail BL target into a byte-identical range-copy port.

use crate::libc::memcpy::memcpy_forward_words;

/// Uninitialized-copy a half-open range of 24-byte vector elements.
///
/// # Safety
///
/// `first` and `last` must delimit a range reachable in positive 24-byte
/// steps. When `output` is non-null, source and destination records must be
/// four-byte aligned and valid for every copied element. Overlap has
/// `memcpy_forward_words`' forward grouped-load-before-store behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_uninitialized_copy_elem24")]
#[inline(never)]
pub unsafe extern "C" fn vector_uninitialized_copy_elem24(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
    _owner: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            output = memcpy_forward_words(output, first, 24);
        } else {
            output = output.wrapping_add(24);
        }
        first = first.wrapping_add(24);
    }
    output
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::vector_uninitialized_copy_elem24;

    #[test]
    fn empty_range_returns_output_without_accessing_input() {
        let mut output = [0xa5u8; 24];
        let first = core::ptr::NonNull::<u8>::dangling().as_ptr();
        let result = unsafe {
            vector_uninitialized_copy_elem24(first, first, output.as_mut_ptr(), core::ptr::null_mut())
        };
        assert_eq!(result, output.as_mut_ptr());
        assert_eq!(output, [0xa5; 24]);
    }

    #[test]
    fn copies_complete_records_and_returns_advanced_output() {
        let mut input = [0u32; 18];
        for (index, word) in input.iter_mut().enumerate() {
            *word = 0x1100_0000 | index as u32;
        }
        let mut output = [0u32; 18];
        let result = unsafe {
            vector_uninitialized_copy_elem24(
                input.as_ptr().cast(),
                input.as_ptr().cast::<u8>().add(72),
                output.as_mut_ptr().cast(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(output, input);
        assert_eq!(result, unsafe { output.as_mut_ptr().cast::<u8>().add(72) });
    }

    #[test]
    fn null_output_skips_exactly_one_record_without_reading_input() {
        let first = core::ptr::NonNull::<u8>::dangling().as_ptr();
        let last = first.wrapping_add(24);
        let result = unsafe {
            vector_uninitialized_copy_elem24(first, last, core::ptr::null_mut(), core::ptr::null_mut())
        };
        assert_eq!(result.addr(), 24);
    }

    #[test]
    fn preserves_per_record_forward_grouped_overlap() {
        let mut words = [0u32; 24];
        for (index, word) in words.iter_mut().enumerate() {
            *word = index as u32;
        }
        let mut expected = words;
        for record in 0..2 {
            let source_word = record * 6;
            let output_word = source_word + 2;
            for (offset, width) in [(0, 4), (4, 2)] {
                let copied = [
                    expected[source_word + offset], expected[source_word + offset + 1],
                    expected[source_word + offset + 2], expected[source_word + offset + 3],
                ];
                expected[output_word + offset..output_word + offset + width]
                    .copy_from_slice(&copied[..width]);
            }
        }
        let base = words.as_mut_ptr().cast::<u8>();
        unsafe {
            vector_uninitialized_copy_elem24(base, base.add(48), base.add(8), core::ptr::null_mut());
        }
        assert_eq!(words, expected);
    }
}
