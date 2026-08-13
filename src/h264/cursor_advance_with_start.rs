//! H.264 parse-cursor advancement with old-position output.
//!
//! `h264_cursor_advance_with_start` — original: `FUN_0802b924` @
//! 0x0802b924 (24 bytes; leaf function).
//!
//! H.264 syntax-header parsers at 0x08028838 and 0x08028b08 keep paired
//! local parse cursors. When a flag selects a direct displacement, this
//! helper snapshots the first cursor, advances it with ARM's wrapping signed
//! word addition, mirrors the advanced value, and exposes the snapshot as the
//! displacement's start. The ARM order is load `cursor`, then stores to
//! `cursor`, `cursor_mirror`, and `start`; preserving that order matters when
//! output pointers alias. No deviations.

/// Advance `cursor` by `delta`, mirror the result, and report its old value.
///
/// All pointers must designate valid, aligned writable `i32` words. The
/// addition wraps at the signed 32-bit boundary, exactly as ARM `add` does.
/// Stores occur in the original order: `cursor`, `cursor_mirror`, then
/// `start`, so callers that alias output words observe the retail result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn h264_cursor_advance_with_start(
    cursor: *mut i32,
    cursor_mirror: *mut i32,
    start: *mut i32,
    delta: i32,
) {
    let old_cursor = cursor.read();
    let advanced_cursor = old_cursor.wrapping_add(delta);
    cursor.write(advanced_cursor);
    cursor_mirror.write(advanced_cursor);
    start.write(old_cursor);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_mirrors_and_reports_the_original_cursor() {
        let mut cursor = 0x1234_5678i32;
        let mut cursor_mirror = -1i32;
        let mut start = -1i32;

        unsafe {
            h264_cursor_advance_with_start(
                &mut cursor,
                &mut cursor_mirror,
                &mut start,
                0x100,
            );
        }

        assert_eq!(cursor, 0x1234_5778);
        assert_eq!(cursor_mirror, 0x1234_5778);
        assert_eq!(start, 0x1234_5678);
    }

    #[test]
    fn addition_wraps_like_the_arm_word_add() {
        let mut cursor = i32::MAX;
        let mut cursor_mirror = 0;
        let mut start = 0;

        unsafe {
            h264_cursor_advance_with_start(&mut cursor, &mut cursor_mirror, &mut start, 1);
        }

        assert_eq!(cursor, i32::MIN);
        assert_eq!(cursor_mirror, i32::MIN);
        assert_eq!(start, i32::MAX);
    }

    #[test]
    fn aliases_observe_the_original_store_order() {
        // cursor == cursor_mirror: the first two stores agree, then start is
        // independent.
        let mut cursor_and_mirror = 10;
        let mut start = -1;
        let shared = core::ptr::addr_of_mut!(cursor_and_mirror);
        unsafe {
            h264_cursor_advance_with_start(shared, shared, &mut start, 3);
        }
        assert_eq!(cursor_and_mirror, 13);
        assert_eq!(start, 10);

        // cursor == start: the final start store overwrites the advance.
        let mut cursor_and_start = 10;
        let mut mirror = -1;
        let shared = core::ptr::addr_of_mut!(cursor_and_start);
        unsafe {
            h264_cursor_advance_with_start(shared, &mut mirror, shared, 3);
        }
        assert_eq!(cursor_and_start, 10);
        assert_eq!(mirror, 13);

        // cursor_mirror == start: the final store overwrites the mirror.
        let mut cursor = 10;
        let mut mirror_and_start = -1;
        let shared = core::ptr::addr_of_mut!(mirror_and_start);
        unsafe {
            h264_cursor_advance_with_start(&mut cursor, shared, shared, 3);
        }
        assert_eq!(cursor, 13);
        assert_eq!(mirror_and_start, 10);

        // All outputs alias: the final old-value store wins.
        let mut every_output = 10;
        let shared = core::ptr::addr_of_mut!(every_output);
        unsafe {
            h264_cursor_advance_with_start(shared, shared, shared, 3);
        }
        assert_eq!(every_output, 10);
    }
}
