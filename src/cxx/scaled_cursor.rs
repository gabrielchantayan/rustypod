//! Scaled word-cursor advancement used by FreeType parser-layout builders.
//!
//! `ft_advance_scaled_word_cursor` — original: `FUN_0802b974` @ 0x0802b974
//! (36 bytes). Reference: `decomp/c/001/0802b974_FUN_0802b974.c`; definitive
//! sequence: `decomp/osos.asm:39159-39167`.
//!
//! Algorithm: load the old cursor from `cursor_mirror`, calculate
//! `old_cursor + count * stride * 4` with 32-bit ARM wrapping arithmetic,
//! then store the result to `next_cursor` and `cursor_mirror` in that order.
//! Finally, store the old cursor to `range_start`. The ordered raw-pointer
//! writes deliberately preserve the firmware's observable output aliasing.
//! No deviations.

/// Advances a scaled word cursor and records its starting position.
///
/// The fifth ARM ABI argument, `count`, is multiplied by `stride` and scaled
/// to four-byte words. All arithmetic is modulo $2^{32}$, as in the original
/// `mul` followed by `add ..., lsl #2` instruction sequence.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_advance_scaled_word_cursor(
    next_cursor: *mut u32,
    cursor_mirror: *mut u32,
    range_start: *mut u32,
    stride: u32,
    count: u32,
) {
    let old_cursor = unsafe { cursor_mirror.read() };
    let advanced_cursor = old_cursor.wrapping_add(count.wrapping_mul(stride).wrapping_shl(2));

    unsafe {
        next_cursor.write(advanced_cursor);
        cursor_mirror.write(advanced_cursor);
        range_start.write(old_cursor);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::ft_advance_scaled_word_cursor;

    #[test]
    fn advances_by_count_stride_words_and_records_the_old_cursor() {
        let mut next_cursor = 0;
        let mut cursor_mirror = 0x1000_0000;
        let mut range_start = 0;

        unsafe {
            ft_advance_scaled_word_cursor(
                &mut next_cursor,
                &mut cursor_mirror,
                &mut range_start,
                4,
                0x100,
            );
        }

        assert_eq!(next_cursor, 0x1000_1000);
        assert_eq!(cursor_mirror, 0x1000_1000);
        assert_eq!(range_start, 0x1000_0000);
    }

    #[test]
    fn multiplication_shift_and_add_wrap_at_arm_word_width() {
        let mut next_cursor = 0;
        let mut cursor_mirror = 0xffff_fffc;
        let mut range_start = 0;

        unsafe {
            ft_advance_scaled_word_cursor(
                &mut next_cursor,
                &mut cursor_mirror,
                &mut range_start,
                0x8000_0001,
                3,
            );
        }

        // ARM: `(3 * 0x8000_0001) << 2 == 12`, then `0xffff_fffc + 12 == 8`.
        assert_eq!(next_cursor, 8);
        assert_eq!(cursor_mirror, 8);
        assert_eq!(range_start, 0xffff_fffc);
    }

    #[test]
    fn ordered_writes_preserve_all_output_alias_combinations() {
        let old_cursor = 0x0123_4567u32;
        let advanced_cursor = old_cursor.wrapping_add(5 * 7 * 4);

        let mut next_cursor = 0;
        let mut cursor_mirror = old_cursor;
        let mut range_start = 0;
        unsafe {
            ft_advance_scaled_word_cursor(
                &mut next_cursor,
                &mut cursor_mirror,
                &mut range_start,
                7,
                5,
            );
        }
        assert_eq!((next_cursor, cursor_mirror, range_start), (advanced_cursor, advanced_cursor, old_cursor));

        let mut first_and_start = old_cursor;
        let mut second = old_cursor;
        unsafe {
            ft_advance_scaled_word_cursor(
                &mut first_and_start,
                &mut second,
                &mut first_and_start,
                7,
                5,
            );
        }
        assert_eq!((first_and_start, second), (old_cursor, advanced_cursor));

        let mut first = 0;
        let mut second_and_start = old_cursor;
        unsafe {
            ft_advance_scaled_word_cursor(
                &mut first,
                &mut second_and_start,
                &mut second_and_start,
                7,
                5,
            );
        }
        assert_eq!((first, second_and_start), (advanced_cursor, old_cursor));

        let mut every_output = old_cursor;
        unsafe {
            ft_advance_scaled_word_cursor(
                &mut every_output,
                &mut every_output,
                &mut every_output,
                7,
                5,
            );
        }
        assert_eq!(every_output, old_cursor);
    }
}
