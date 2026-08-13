//! `advance_triple_scaled_cursor_with_start` — original: `FUN_0802b998` @
//! `0x0802b998` (40 bytes).
//!
//! # Algorithm
//!
//! Reads the current cursor, advances it by `factor_3 * factor_2 * factor_1`
//! with the ARM's wrapping 32-bit arithmetic, then stores the advanced cursor
//! to the cursor and mirror outputs before storing the original cursor to the
//! range-start output. The deliberately ordered raw-pointer stores preserve
//! the retail helper's observable behavior when output pointers alias. No
//! deviations.

/// Advances a cursor by three scaling factors and records its original value —
/// original: `FUN_0802b998` @ `0x0802b998` (40 bytes).
///
/// # Safety
///
/// `cursor`, `cursor_mirror`, and `range_start` must each be valid for a
/// writable `u32`. They may alias; stores occur in the retail order: cursor,
/// cursor mirror, then range start.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn advance_triple_scaled_cursor_with_start(
    cursor: *mut u32,
    cursor_mirror: *mut u32,
    range_start: *mut u32,
    factor_1: u32,
    factor_2: u32,
    factor_3: u32,
) {
    let old_cursor = cursor.read();
    let advanced_cursor = old_cursor.wrapping_add(
        factor_3
            .wrapping_mul(factor_2)
            .wrapping_mul(factor_1),
    );

    cursor.write(advanced_cursor);
    cursor_mirror.write(advanced_cursor);
    range_start.write(old_cursor);
}

#[cfg(test)]
mod tests {
    use super::advance_triple_scaled_cursor_with_start;

    #[test]
    fn advances_and_records_the_original_cursor() {
        let mut cursor = 100u32;
        let mut cursor_mirror = 0u32;
        let mut range_start = 0u32;

        unsafe {
            advance_triple_scaled_cursor_with_start(
                &mut cursor,
                &mut cursor_mirror,
                &mut range_start,
                3,
                5,
                7,
            );
        }

        assert_eq!(cursor, 205);
        assert_eq!(cursor_mirror, 205);
        assert_eq!(range_start, 100);
    }

    #[test]
    fn wraps_each_multiply_and_the_final_addition() {
        let mut cursor = u32::MAX - 1;
        let mut cursor_mirror = 0u32;
        let mut range_start = 0u32;

        unsafe {
            advance_triple_scaled_cursor_with_start(
                &mut cursor,
                &mut cursor_mirror,
                &mut range_start,
                1,
                2,
                u32::MAX,
            );
        }

        assert_eq!(cursor, u32::MAX - 3);
        assert_eq!(cursor_mirror, u32::MAX - 3);
        assert_eq!(range_start, u32::MAX - 1);
    }

    #[test]
    fn output_aliases_observe_the_retail_store_order() {
        let mut cursor_and_mirror = 11u32;
        let mut range_start = 0u32;
        unsafe {
            advance_triple_scaled_cursor_with_start(
                &mut cursor_and_mirror,
                &mut cursor_and_mirror,
                &mut range_start,
                2,
                3,
                4,
            );
        }
        assert_eq!(cursor_and_mirror, 35, "the first two stores agree");
        assert_eq!(range_start, 11);

        let mut cursor_and_start = 11u32;
        let mut cursor_mirror = 0u32;
        unsafe {
            advance_triple_scaled_cursor_with_start(
                &mut cursor_and_start,
                &mut cursor_mirror,
                &mut cursor_and_start,
                2,
                3,
                4,
            );
        }
        assert_eq!(cursor_mirror, 35, "the second store receives the advanced cursor");
        assert_eq!(cursor_and_start, 11, "the final range-start store wins an alias");

        let mut cursor = 11u32;
        let mut mirror_and_start = 0u32;
        unsafe {
            advance_triple_scaled_cursor_with_start(
                &mut cursor,
                &mut mirror_and_start,
                &mut mirror_and_start,
                2,
                3,
                4,
            );
        }
        assert_eq!(cursor, 35);
        assert_eq!(mirror_and_start, 11, "the third store overwrites the mirror alias");

        let mut every_output = 11u32;
        unsafe {
            advance_triple_scaled_cursor_with_start(
                &mut every_output,
                &mut every_output,
                &mut every_output,
                2,
                3,
                4,
            );
        }
        assert_eq!(every_output, 11, "the final range-start store wins all aliases");
    }
}
