//! vector_record24_copy_backward — original: `FUN_083e8154` @ 0x083e8154 (60 bytes).
//!
//! Raw `osos.dec` words establish the exact 15-instruction extent
//! `0x083e8154..0x083e818f`: the final `pop {r4,r5,r6,pc}` is at
//! `0x083e818c`, and the next independently linked function starts with
//! `push {r2-r9,sl,lr}` at `0x083e8190`. Full-image A32 branch decoding finds
//! two inbound unconditional plain `bl` sites, zero inbound predicated `bl`
//! sites, and one unconditional internal `bl` to the IRAM memcpy veneer at
//! `0x08037df8`.
//!
//! Algorithm: copy consecutive aligned 24-byte records from `source_end`
//! backwards to `source`, placing them backwards from `destination_end`, then
//! return the resulting destination start. Deliberate deviation: calls the
//! already-ported memcpy body directly rather than the IRAM veneer; this keeps
//! its grouped forward-copy behavior and return value. A target-only unique text
//! section prevents LLVM from folding this separate retail BL target into a
//! byte-identical record-copy port.

use crate::libc::memcpy::memcpy_forward_words;

/// Copy a half-open range of 24-byte records into preceding destination storage.
///
/// # Safety
///
/// `source_end` must be reachable from `source` in positive 24-byte steps, and
/// both ranges must be four-byte aligned and valid for every copied record.
/// Overlap has the original reverse-record ordering and
/// `memcpy_forward_words`' forward grouped-load-before-store behavior within
/// each record.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_record24_copy_backward")]
#[inline(never)]
pub unsafe extern "C" fn vector_record24_copy_backward(
    source: *const u8,
    mut source_end: *const u8,
    mut destination_end: *mut u8,
) -> *mut u8 {
    while source != source_end {
        source_end = unsafe { source_end.sub(24) };
        destination_end = unsafe { destination_end.sub(24) };
        unsafe {
            memcpy_forward_words(destination_end, source_end, 24);
        }
    }
    destination_end
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::vector_record24_copy_backward;

    #[test]
    fn empty_range_returns_destination_end_without_accessing_source() {
        let destination_end = core::ptr::dangling_mut();
        let result = unsafe {
            vector_record24_copy_backward(core::ptr::dangling(), core::ptr::dangling(), destination_end)
        };
        assert_eq!(result, destination_end);
    }

    #[test]
    fn copies_complete_records_in_reverse_and_returns_destination_start() {
        let source = [
            0x0302_0100u32, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c, 0x1312_1110, 0x1716_1514,
            0x1b1a_1918, 0x1f1e_1c1d, 0x2322_2120, 0x2726_2524, 0x2b2a_2928, 0x2f2e_2d2c,
        ];
        let mut destination = [0u32; 12];
        let result = unsafe {
            vector_record24_copy_backward(
                source.as_ptr() as *const u8,
                unsafe { (source.as_ptr() as *const u8).add(48) },
                unsafe { (destination.as_mut_ptr() as *mut u8).add(48) },
            )
        };
        assert_eq!(destination, source);
        assert_eq!(result, destination.as_mut_ptr() as *mut u8);
    }

    #[test]
    fn preserves_reverse_record_order_for_overlapping_ranges() {
        let mut words = [
            0x0302_0100u32, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c, 0x1312_1110, 0x1716_1514,
            0x1b1a_1918, 0x1f1e_1d1c, 0x2322_2120, 0x2726_2524, 0x2b2a_2928, 0x2f2e_2d2c,
            0x3332_3130, 0x3736_3534, 0x3b3a_3938, 0x3f3e_3d3c, 0x4342_4140, 0x4746_4544,
        ];
        let original = words;
        let base = words.as_mut_ptr() as *mut u8;
        let result = unsafe { vector_record24_copy_backward(base, base.add(48), base.add(72)) };
        assert_eq!(result, unsafe { base.add(24) });
        assert_eq!(&words[6..18], &original[..12]);
    }
}
