//! Strided cursor advance from retailOS.
//!
//! `advance_strided_cursor_with_start` — original: `FUN_0802b954` @
//! 0x0802b954 (32 bytes), recovered from
//! `decomp/c/001/0802b954_FUN_0802b954.c` and its raw ARM body. The parser
//! layout callers reserve `count` entries of `stride` bytes: read the current
//! cursor, compute `cursor + count * stride` with ARM's modulo-2^32 multiply
//! accumulate, store the advanced cursor through both cursor outputs, then
//! store the pre-advance cursor as the range start. The ordered raw-pointer
//! stores deliberately preserve the firmware's observable result when output
//! pointers alias. No deviations.

/// Advances a cursor by `count * stride` and reports both the new cursor and
/// the range's original start.
///
/// # Safety
///
/// `cursor`, `cursor_mirror`, and `range_start` must be valid, aligned,
/// writable `u32` pointers. They may alias; the firmware's store order is
/// preserved exactly.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn advance_strided_cursor_with_start(
    cursor: *mut u32,
    cursor_mirror: *mut u32,
    range_start: *mut u32,
    stride: u32,
    count: u32,
) {
    let old_cursor = cursor.read();
    let advanced_cursor = old_cursor.wrapping_add(count.wrapping_mul(stride));

    cursor.write(advanced_cursor);
    cursor_mirror.write(advanced_cursor);
    range_start.write(old_cursor);
}

#[cfg(test)]
mod tests {
    use super::advance_strided_cursor_with_start;

    #[test]
    fn advances_by_the_requested_strided_range() {
        let mut cursor = 0x0000_1200u32;
        let mut cursor_mirror = 0;
        let mut range_start = 0;

        unsafe {
            advance_strided_cursor_with_start(
                &mut cursor,
                &mut cursor_mirror,
                &mut range_start,
                0x10,
                0x100,
            );
        }

        assert_eq!(cursor, 0x0000_2200);
        assert_eq!(cursor_mirror, 0x0000_2200);
        assert_eq!(range_start, 0x0000_1200);
    }

    #[test]
    fn multiply_accumulate_wraps_at_word_width() {
        let mut cursor = 0xffff_fff0u32;
        let mut cursor_mirror = 0;
        let mut range_start = 0;

        unsafe {
            advance_strided_cursor_with_start(
                &mut cursor,
                &mut cursor_mirror,
                &mut range_start,
                0x8000_0000,
                3,
            );
        }

        assert_eq!(cursor, 0x7fff_fff0);
        assert_eq!(cursor_mirror, 0x7fff_fff0);
        assert_eq!(range_start, 0xffff_fff0);
    }

    #[test]
    fn output_aliasing_observes_the_arm_store_order() {
        let initial = 0x24u32;
        let expected_advanced = 0x44u32;

        let mut cursor = initial;
        let mut range_start = 0;
        unsafe {
            advance_strided_cursor_with_start(
                &mut cursor,
                &mut cursor,
                &mut range_start,
                8,
                4,
            );
        }
        assert_eq!(cursor, expected_advanced, "p1/p2 writes both precede p3");
        assert_eq!(range_start, initial);

        let mut cursor = initial;
        let mut cursor_mirror = 0;
        unsafe {
            advance_strided_cursor_with_start(
                &mut cursor,
                &mut cursor_mirror,
                &mut cursor,
                8,
                4,
            );
        }
        assert_eq!(cursor, initial, "final p3 write overwrites p1");
        assert_eq!(cursor_mirror, expected_advanced);

        let mut cursor = initial;
        let mut cursor_mirror_and_start = 0;
        unsafe {
            advance_strided_cursor_with_start(
                &mut cursor,
                &mut cursor_mirror_and_start,
                &mut cursor_mirror_and_start,
                8,
                4,
            );
        }
        assert_eq!(cursor, expected_advanced);
        assert_eq!(cursor_mirror_and_start, initial, "final p3 write overwrites p2");
    }
}
