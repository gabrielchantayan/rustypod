//! vector_record24_copy_assign — original: `FUN_083e9c00` @ 0x083e9c00 (60 bytes).
//!
//! Raw `osos.dec` words establish the exact 15-instruction extent
//! 0x083e9c00..0x083e9c3b: the final `pop {r4,r5,r6,pc}` is at 0x083e9c38,
//! and 0x083e9c3c starts a separate `push {r4,r5,r6,lr}` function. Full-image
//! A32 branch decoding finds two inbound unconditional plain `bl` sites
//! (0x083e2028 and 0x083e2078), zero inbound predicated `bl` sites, and one
//! unconditional internal `bl` to the IRAM memcpy veneer at 0x08037df8.
//!
//! Algorithm: copy consecutive aligned 24-byte records from `source` up to
//! `source_end` into `destination`, advancing both pointers one record at a
//! time, then return the advanced destination. Deliberate deviation: calls the
//! already-ported memcpy body directly rather than the IRAM veneer; this keeps
//! its grouped forward-copy behavior and return value. A target-only unique text
//! section prevents LLVM from folding this separate retail BL target into the
//! byte-identical `fixed_record_range_copy` and `vector_record24_copy` ports.

use crate::libc::memcpy::memcpy_forward_words;

/// Copy the half-open range of 24-byte records into consecutive destination storage.
///
/// # Safety
///
/// `source` and `destination` must be four-byte aligned. `source_end` must be
/// reachable from `source` in positive 24-byte steps, and both ranges must be
/// valid for every copied record. Overlap has `memcpy_forward_words`' forward,
/// grouped-load-before-store behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_record24_copy_assign")]
#[inline(never)]
pub unsafe extern "C" fn vector_record24_copy_assign(
    mut source: *const u8,
    source_end: *const u8,
    mut destination: *mut u8,
) -> *mut u8 {
    while source != source_end {
        destination = memcpy_forward_words(destination, source, 24);
        source = source.add(24);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::vector_record24_copy_assign;

    #[test]
    fn empty_range_returns_destination_without_accessing_source() {
        let mut destination = [0xa5u8; 24];
        let source = core::ptr::NonNull::<u8>::dangling().as_ptr();
        let result = unsafe { vector_record24_copy_assign(source, source, destination.as_mut_ptr()) };
        assert_eq!(result, destination.as_mut_ptr());
        assert_eq!(destination, [0xa5; 24]);
    }

    #[test]
    fn copies_multiple_complete_records_and_returns_end() {
        let mut source = [0u32; 18];
        for (index, word) in source.iter_mut().enumerate() {
            *word = 0x1100_0000 | index as u32;
        }
        let mut destination = [0u32; 18];
        let result = unsafe {
            vector_record24_copy_assign(
                source.as_ptr().cast(),
                source.as_ptr().cast::<u8>().add(72),
                destination.as_mut_ptr().cast(),
            )
        };
        assert_eq!(destination, source);
        assert_eq!(result, unsafe { destination.as_mut_ptr().cast::<u8>().add(72) });
    }

    #[test]
    fn preserves_per_record_forward_grouped_overlap() {
        let mut bytes = [0u32; 24];
        for (index, word) in bytes.iter_mut().enumerate() {
            *word = index as u32;
        }
        let mut expected = bytes;
        for record in 0..2 {
            let source_word = record * 6;
            let destination_word = source_word + 2;
            for (offset, width) in [(0, 4), (4, 2)] {
                let copied = [
                    expected[source_word + offset],
                    expected[source_word + offset + 1],
                    expected[source_word + offset + 2],
                    expected[source_word + offset + 3],
                ];
                expected[destination_word + offset..destination_word + offset + width]
                    .copy_from_slice(&copied[..width]);
            }
        }
        let base = bytes.as_mut_ptr().cast::<u8>();
        unsafe {
            vector_record24_copy_assign(base, base.add(48), base.add(8));
        }
        assert_eq!(bytes, expected);
    }
}
