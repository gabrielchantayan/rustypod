//! MPEG audio frame scanner — `FUN_082815d4` @ `0x082815d4`.
//!
//! True extent: 168 bytes (`0x082815d4..0x0828167b`); the next separately
//! entered function starts at `0x0828167c`. Full-image A32 decoding finds
//! three inbound plain `bl` call sites (`0x0828171c`, `0x0828184c`, and
//! `0x08281934`), zero predicated inbound `bl` call sites, and two plain
//! outgoing `bl` calls: `mpeg_audio_header_matches_context` @ `0x08281d48`
//! and `mpeg_audio_frame_size` @ `0x08281af4`; no predicated outgoing calls.
//!
//! # Algorithm
//!
//! Examine each byte position before `scan_limit` as a big-endian MPEG header.
//! A candidate must match the context's saved header and have a valid frame
//! size. On success, store its address and frame size and return zero; on
//! exhaustion, store the number of examined positions and return status 3.
//! Deliberate deviations: none.

use crate::util::mpeg_audio_frame_size::mpeg_audio_frame_size;
use crate::util::mpeg_audio_header_matches_context::mpeg_audio_header_matches_context;

const STATUS_NOT_FOUND: u32 = 3;

#[inline(always)]
unsafe fn read_be_u32(bytes: *const u8) -> u32 {
    (bytes.read() as u32) << 24
        | (bytes.add(1).read() as u32) << 16
        | (bytes.add(2).read() as u32) << 8
        | bytes.add(3).read() as u32
}

/// Locates the first context-compatible MPEG audio frame header.
///
/// # Safety
///
/// `cursor_out`, `frame_size_out`, and `skipped_out` must be writable. The
/// buffer beginning at `*cursor_out` must contain at least `scan_limit + 3`
/// bytes, and `context` must meet both MPEG helper functions' contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mpeg_audio_frame_find(
    context: *const u8,
    cursor_out: *mut *const u8,
    frame_size_out: *mut u32,
    scan_limit: u32,
    skipped_out: *mut u32,
) -> u32 {
    let mut cursor = cursor_out.read();
    let mut skipped = 0;

    while skipped < scan_limit {
        let header = read_be_u32(cursor);
        if mpeg_audio_header_matches_context(context, header) == 0 {
            let mut bitrate = 0;
            let mut frame_size = 0;
            if mpeg_audio_frame_size(context, header, &mut bitrate, &mut frame_size) == 0 {
                cursor_out.write(cursor);
                frame_size_out.write(frame_size);
                skipped_out.write(skipped);
                return 0;
            }
        }
        cursor = cursor.add(1);
        skipped += 1;
    }

    skipped_out.write(skipped);
    STATUS_NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIVISOR_OFFSET: usize = 0x18;
    const SAMPLE_RATE_SCALE_OFFSET: usize = 0x24;
    const SAVED_HEADER_OFFSET: usize = 0x38;
    const FREE_BITRATE_HEADER: u32 = 0xfffb_0000;

    fn context_for(header: u32) -> [u32; 16] {
        let mut context = [0u32; 16];
        context[DIVISOR_OFFSET / 4] = 1_000;
        context[SAMPLE_RATE_SCALE_OFFSET / 4] = 8;
        context[SAVED_HEADER_OFFSET / 4] = header;
        context
    }

    #[test]
    fn finds_first_valid_header_after_nonmatching_bytes() {
        let context = context_for(FREE_BITRATE_HEADER);
        let bytes = [0, 0, 0xff, 0xfb, 0, 0, 0, 0];
        let mut cursor = bytes.as_ptr();
        let mut frame_size = 0;
        let mut skipped = u32::MAX;

        assert_eq!(unsafe {
            mpeg_audio_frame_find(
                context.as_ptr().cast(),
                &mut cursor,
                &mut frame_size,
                3,
                &mut skipped,
            )
        }, 0);
        assert_eq!(cursor, unsafe { bytes.as_ptr().add(2) });
        assert_eq!(frame_size, 128);
        assert_eq!(skipped, 2);
    }

    #[test]
    fn reports_exhaustion_without_changing_candidate_outputs() {
        let context = context_for(FREE_BITRATE_HEADER);
        let bytes = [0u8; 7];
        let original_cursor = bytes.as_ptr();
        let mut cursor = original_cursor;
        let mut frame_size = 0xa5a5_a5a5;
        let mut skipped = u32::MAX;

        assert_eq!(unsafe {
            mpeg_audio_frame_find(
                context.as_ptr().cast(),
                &mut cursor,
                &mut frame_size,
                4,
                &mut skipped,
            )
        }, STATUS_NOT_FOUND);
        assert_eq!(cursor, original_cursor);
        assert_eq!(frame_size, 0xa5a5_a5a5);
        assert_eq!(skipped, 4);
    }

    #[test]
    fn scan_limit_excludes_a_header_at_its_endpoint() {
        let context = context_for(FREE_BITRATE_HEADER);
        let bytes = [0, 0xff, 0xfb, 0, 0, 0];
        let mut cursor = bytes.as_ptr();
        let mut frame_size = 0;
        let mut skipped = 0;

        assert_eq!(unsafe {
            mpeg_audio_frame_find(
                context.as_ptr().cast(),
                &mut cursor,
                &mut frame_size,
                1,
                &mut skipped,
            )
        }, STATUS_NOT_FOUND);
        assert_eq!(cursor, bytes.as_ptr());
        assert_eq!(skipped, 1);
    }
}
