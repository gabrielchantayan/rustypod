//! 20-byte record-range copy with a nullable destination — retailOS
//! `FUN_083e88cc` at load address `0x083e88cc` (60 bytes).
//!
//! Raw `osos.dec` words establish the exact extent `0x083e88cc..0x083e8907`:
//! `push {r4,r5,r6,lr}`, a loop containing `movs r0,r4; movne r2,#20;
//! movne r1,r5; blne 0x08037df8`, and `pop {r4,r5,r6,pc}`. The next
//! independently linked function begins at `0x083e8908`. Raw A32 decoding
//! finds two inbound plain `bl` calls (`0x083e01e4` and `0x083e0234`), zero
//! inbound predicated `bl` calls, zero outbound plain `bl` calls, and one
//! outbound predicated `blne` to the IRAM memcpy veneer at `0x08037df8`.
//!
//! The loop forward-copies each aligned 20-byte record in `[source,
//! source_end)` when `destination` is non-null, advances both cursors after
//! every record, and returns the advanced destination cursor. Deliberate
//! deviation: the IRAM veneer is represented by the already-ported
//! `memcpy_forward_words` body through a volatile function pointer, retaining
//! the call and its word-aligned forward-copy behavior instead of allowing an
//! inline or libc copy substitution.

use crate::libc::memcpy::memcpy_forward_words;

/// Copies aligned 20-byte records from `source` through `source_end` to
/// `destination` when it is non-null.
///
/// # Safety
///
/// `source` and `source_end` must delimit a range whose length is a multiple
/// of 20. When `destination` is non-null, both ranges must be word-aligned and
/// valid for that many bytes. Like retailOS, overlapping ranges copy forward.
/// For exactly one record, a null destination is supported and leaves `source`
/// unread; each skipped record still advances the null cursor by 20 bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record20_range_copy_if_destination")]
#[inline(never)]
pub unsafe extern "C" fn record20_range_copy_if_destination(
    mut source: *const u8,
    source_end: *const u8,
    mut destination: *mut u8,
) -> *mut u8 {
    while source != source_end {
        if !destination.is_null() {
            let copy = core::ptr::read_volatile(
                &(memcpy_forward_words as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8),
            );
            unsafe { copy(destination, source, 20) };
        }
        source = source.wrapping_add(20);
        destination = destination.wrapping_add(20);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::record20_range_copy_if_destination;

    #[test]
    fn copies_complete_records_and_returns_advanced_destination() {
        let source = [
            0x0102_0304_u32, 0x1112_1314, 0x2122_2324, 0x3132_3334, 0x4142_4344,
            0x5152_5354, 0x6162_6364, 0x7172_7374, 0x8182_8384, 0x9192_9394,
        ];
        let mut destination = [0_u32; 10];
        let output = destination.as_mut_ptr().cast::<u8>();
        let first = source.as_ptr().cast::<u8>();

        let returned = unsafe { record20_range_copy_if_destination(first, first.add(40), output) };

        assert_eq!(destination, source);
        assert_eq!(returned, unsafe { output.add(40) });
    }

    #[test]
    fn empty_range_leaves_destination_unchanged() {
        let source = [1_u32; 5];
        let mut destination = [9_u32; 5];
        let first = source.as_ptr().cast::<u8>();
        let output = destination.as_mut_ptr().cast::<u8>();

        let returned = unsafe { record20_range_copy_if_destination(first, first, output) };

        assert_eq!(destination, [9; 5]);
        assert_eq!(returned, output);
    }

    #[test]
    fn null_destination_skips_one_record_without_reading_source() {
        let returned = unsafe {
            record20_range_copy_if_destination(
                core::ptr::null(),
                20_usize as *const u8,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(returned, 20_usize as *mut u8);
    }

    #[test]
    fn preserves_memcpy_grouped_forward_overlap() {
        let mut words = [1_u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let source = words.as_ptr().cast::<u8>();
        let output = unsafe { words.as_mut_ptr().add(5).cast::<u8>() };

        unsafe { record20_range_copy_if_destination(source, source.add(40), output) };

        assert_eq!(words, [1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5]);
    }
}
