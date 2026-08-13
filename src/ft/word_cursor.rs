//! FreeType word-cursor allocation helpers.

/// Advances a shared word cursor and exposes the reserved range's start.
///
/// `ft_advance_word_cursor` — original: `FUN_0802b93c` @ `0x0802b93c`
/// (24 bytes).
///
/// Reads the current cursor from `cursor`, computes `cursor + word_count * 4`
/// with ARM's wrapping shift/add arithmetic, then stores the new cursor through
/// `next_cursor` and `cursor` before storing the original cursor through
/// `range_start`. FreeType's parser builders use the three output cells to
/// reserve a word range while advancing their running allocation cursor.
///
/// # Safety
/// Each pointer must be valid for a `u32` read or write as applicable. The
/// output pointers may alias: stores occur in the original ARM order.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_advance_word_cursor(
    next_cursor: *mut u32,
    cursor: *mut u32,
    range_start: *mut u32,
    word_count: u32,
) {
    let old_cursor = core::ptr::read(cursor);
    let advanced_cursor = old_cursor.wrapping_add(word_count.wrapping_shl(2));

    core::ptr::write(next_cursor, advanced_cursor);
    core::ptr::write(cursor, advanced_cursor);
    core::ptr::write(range_start, old_cursor);
}

#[cfg(test)]
mod tests {
    use super::ft_advance_word_cursor;

    #[test]
    fn reserves_words_and_advances_both_cursor_outputs() {
        let mut next_cursor = 0;
        let mut cursor = 0x1000;
        let mut range_start = 0;

        unsafe {
            ft_advance_word_cursor(&mut next_cursor, &mut cursor, &mut range_start, 3);
        }

        assert_eq!(next_cursor, 0x100c);
        assert_eq!(cursor, 0x100c);
        assert_eq!(range_start, 0x1000);
    }

    #[test]
    fn wrapping_word_shift_and_add_match_arm_arithmetic() {
        let mut next_cursor = 0;
        let mut cursor = 0xffff_fffc;
        let mut range_start = 0;

        unsafe {
            ft_advance_word_cursor(&mut next_cursor, &mut cursor, &mut range_start, 1);
        }

        assert_eq!(next_cursor, 0);
        assert_eq!(cursor, 0);
        assert_eq!(range_start, 0xffff_fffc);

        unsafe {
            ft_advance_word_cursor(&mut next_cursor, &mut cursor, &mut range_start, 0x4000_0000);
        }

        assert_eq!(next_cursor, 0);
        assert_eq!(cursor, 0);
        assert_eq!(range_start, 0);
    }

    #[test]
    fn aliased_next_cursor_and_cursor_remain_advanced() {
        let mut next_cursor_and_cursor = 0x40;
        let mut range_start = 0;

        unsafe {
            ft_advance_word_cursor(
                &mut next_cursor_and_cursor,
                &mut next_cursor_and_cursor,
                &mut range_start,
                2,
            );
        }

        assert_eq!(next_cursor_and_cursor, 0x48);
        assert_eq!(range_start, 0x40);
    }

    #[test]
    fn aliased_cursor_and_range_start_preserve_store_order() {
        let mut next_cursor = 0;
        let mut cursor_and_range_start = 0x40;

        unsafe {
            ft_advance_word_cursor(
                &mut next_cursor,
                &mut cursor_and_range_start,
                &mut cursor_and_range_start,
                2,
            );
        }

        assert_eq!(next_cursor, 0x48);
        assert_eq!(cursor_and_range_start, 0x40);
    }

    #[test]
    fn aliased_next_cursor_and_range_start_receive_final_old_cursor() {
        let mut next_cursor_and_range_start = 0;
        let mut cursor = 0x40;

        unsafe {
            ft_advance_word_cursor(
                &mut next_cursor_and_range_start,
                &mut cursor,
                &mut next_cursor_and_range_start,
                2,
            );
        }

        assert_eq!(next_cursor_and_range_start, 0x40);
        assert_eq!(cursor, 0x48);
    }
}
