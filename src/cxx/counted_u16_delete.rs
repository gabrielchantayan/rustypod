//! Delete a range from a counted u16 string.
//!
//! Original: `FUN_08048750` @ 0x08048750, 92 bytes through 0x080487ac,
//! where the next function starts with `push {r4,lr}`. Raw A32 decoding
//! verifies two inbound plain BL calls (0x08044a10, 0x080b4b8c), one outbound
//! plain BL (0x08048798 -> 0x0805d0f4), and no predicated BL calls.
//! NULL returns immediately. Only index zero checks whether count - 1 exceeds
//! the prefix. Move the remaining code units left, then reload the prefix and
//! subtract count modulo 65536. Indices include the prefix at index zero;
//! ordinary callers use one-based payload indices. Negative signed byte
//! lengths skip the move but still update the prefix.
//!
//! Deliberate deviation: call the existing Rust `bcopy_guarded` directly
//! rather than the stock function. All arithmetic retains ARM u32 wrapping.

use crate::libc::bcopy_guarded::bcopy_guarded;

/// # Safety
/// A non-NULL `text` must be aligned and readable/writable at its prefix.
/// When the computed signed byte length is nonnegative, both computed spans
/// must be valid for that length, including any overlap. No general range
/// validation is performed, matching the firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_u16_delete(text: *mut u16, start: u32, count: u32) {
    if text.is_null() {
        return;
    }
    let end = start.wrapping_add(count);
    if start == 0 && end.wrapping_sub(1) > text.read() as u32 {
        return;
    }
    let bytes = (text.read() as u32).wrapping_sub(start)
        .wrapping_sub(count).wrapping_add(1).wrapping_mul(2) as i32;
    let source = text.cast::<u8>().wrapping_add(end.wrapping_mul(2) as usize);
    let destination = text.cast::<u8>().wrapping_add(start.wrapping_mul(2) as usize);
    bcopy_guarded(source, destination, bytes);
    text.write(text.read().wrapping_sub(count as u16));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_valid_range_matches_reference_including_empty_and_full_deletion() {
        for length in 0..=16usize {
            for start in 1..=length + 1 {
                for count in 0..=length + 1 - start {
                    let mut actual = [0xbeefu16; 20];
                    actual[0] = length as u16;
                    for i in 1..=length {
                        actual[i] = 0xd800 + i as u16;
                    }
                    let mut expected = actual;
                    expected.copy_within(start + count..length + 1, start);
                    expected[0] -= count as u16;
                    unsafe { counted_u16_delete(actual.as_mut_ptr(), start as u32, count as u32) };
                    assert_eq!(actual, expected, "length={length}, start={start}, count={count}");
                }
            }
        }
    }

    #[test]
    fn zero_index_guard_and_post_copy_prefix_reload() {
        let mut text = [4, 10, 20, 30, 40];
        unsafe { counted_u16_delete(text.as_mut_ptr(), 0, 0) };
        assert_eq!(text, [4, 10, 20, 30, 40]);
        unsafe { counted_u16_delete(text.as_mut_ptr(), 0, 6) };
        assert_eq!(text, [4, 10, 20, 30, 40]);
        unsafe { counted_u16_delete(text.as_mut_ptr(), 0, 1) };
        assert_eq!(text, [9, 20, 30, 40, 40]);
    }

    #[test]
    fn negative_copy_length_still_updates_prefix_and_null_returns() {
        let mut text = [4, 10, 20, 30, 40];
        unsafe {
            counted_u16_delete(core::ptr::null_mut(), u32::MAX, u32::MAX);
            counted_u16_delete(text.as_mut_ptr(), 6, 1);
        }
        assert_eq!(text, [3, 10, 20, 30, 40]);
        let mut empty = [0u16, 0xbeef];
        unsafe { counted_u16_delete(empty.as_mut_ptr(), 1, 1) };
        assert_eq!(empty, [u16::MAX, 0xbeef]);
    }
}
