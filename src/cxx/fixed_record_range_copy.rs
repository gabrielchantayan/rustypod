//! fixed_record_range_copy — original: `FUN_083e9b68` @ 0x083e9b68 (60 bytes).
//!
//! Raw `osos.dec` words establish the exact extent 0x083e9b68..0x083e9ba3:
//! the next independently linked function starts with `push {r4-r6,lr}` at
//! 0x083e9ba4. The body has one plain `bl` to the memcpy veneer @ 0x08037df8
//! per 24-byte record. Whole-image ARM decoding finds three incoming direct
//! BL calls: two plain (`0x080596b0`, `0x083e1d74`) and one predicated
//! `blne` (`0x080540e8`).
//!
//! Algorithm: copy consecutive 24-byte records from `src` until it reaches
//! `end`, advancing `dst` by one record after each forward memcpy, then return
//! the advanced destination. Deliberate deviation: the stock call enters the
//! IRAM memcpy veneer, while this port calls its already-ported body directly;
//! both preserve the target's grouped forward-copy behavior and return value.

use crate::libc::memcpy::memcpy_forward_words;

/// Copy `[src, end)` as 24-byte records into `dst`, returning the destination
/// immediately after the last copied record.
///
/// # Safety
///
/// `src..end` must describe a forward range whose length is a multiple of 24;
/// all source records and the corresponding destination range must be valid,
/// four-byte aligned memory. Overlap follows `memcpy_forward_words`' forward
/// grouped-load/store semantics rather than `memmove` semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_record_range_copy(
    mut src: *const u8,
    end: *const u8,
    mut dst: *mut u8,
) -> *mut u8 {
    while src != end {
        dst = memcpy_forward_words(dst, src, 24);
        src = src.add(24);
    }
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn pattern(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect()
    }

    #[test]
    fn copies_empty_and_multiple_fixed_records() {
        for records in 0..=5usize {
            let mut buffer = pattern(320);
            let before = buffer.clone();
            let src_offset = 24;
            let dst_offset = 160;
            let returned = unsafe {
                fixed_record_range_copy(
                    buffer.as_ptr().add(src_offset),
                    buffer.as_ptr().add(src_offset + records * 24),
                    buffer.as_mut_ptr().add(dst_offset),
                )
            };

            assert_eq!(returned, unsafe { buffer.as_mut_ptr().add(dst_offset + records * 24) });
            assert_eq!(
                &buffer[dst_offset..dst_offset + records * 24],
                &before[src_offset..src_offset + records * 24],
                "records={records}"
            );
            assert_eq!(&buffer[..dst_offset], &before[..dst_offset], "records={records}");
        }
    }

    #[test]
    fn preserves_each_memcpy_group_for_overlapping_records() {
        let mut buffer = pattern(160);
        let mut expected = buffer.clone();
        let src_offset = 0;
        let dst_offset = 4;
        let records = 2;

        for record in 0..records {
            let source = src_offset + record * 24;
            let destination = dst_offset + record * 24;
            let first = [
                expected[source], expected[source + 1], expected[source + 2], expected[source + 3],
                expected[source + 4], expected[source + 5], expected[source + 6], expected[source + 7],
                expected[source + 8], expected[source + 9], expected[source + 10], expected[source + 11],
                expected[source + 12], expected[source + 13], expected[source + 14], expected[source + 15],
            ];
            expected[destination..destination + 16].copy_from_slice(&first);
            let second = [
                expected[source + 16], expected[source + 17], expected[source + 18], expected[source + 19],
                expected[source + 20], expected[source + 21], expected[source + 22], expected[source + 23],
            ];
            expected[destination + 16..destination + 24].copy_from_slice(&second);
        }

        unsafe {
            fixed_record_range_copy(
                buffer.as_ptr().add(src_offset),
                buffer.as_ptr().add(src_offset + records * 24),
                buffer.as_mut_ptr().add(dst_offset),
            );
        }
        assert_eq!(buffer, expected);
    }
}
