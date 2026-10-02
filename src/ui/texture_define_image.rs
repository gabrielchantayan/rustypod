//! Texture image definition — retailOS `FUN_08281208` @ 0x08281208.
//!
//! True size: 188 bytes (164 executable bytes and 24 literal bytes), ending
//! before the independent prologue at 0x082812c4. Raw aligned A32 decoding
//! finds two plain inbound BLs (0x08281200, 0x0828141c), one plain outbound
//! BL (0x082812a0 -> 0x082d229c), and no predicated BLs.
//!
//! Select source/output descriptors for pixel formats 0..5, then submit an
//! image definition with command 0xde1, index zero, the supplied dimensions,
//! and the pixel address as the completion word. Unknown formats do nothing.
//! Deliberate deviations: reuse the ported video-engine wrapper; incoming
//! stack words are ignored, exactly as in the raw function. Host addresses
//! passed to the engine remain opaque target-width words, never dereferenced.

use crate::util::video_engine::video_engine_submit_frame;

fn descriptors(pixel_format: u32) -> Option<(u32, u32)> {
    match pixel_format {
        0 => Some((0x1907, 0x8363)),
        1 => Some((0x1908, 0x8033)),
        2 => Some((0x1908, 0x8034)),
        3 => Some((0x1906, 0x1401)),
        4 => Some((0x1907, 0x1401)),
        5 => Some((0x1908, 0x1401)),
        _ => None,
    }
}

/// Define an image for the currently bound texture.
///
/// # Safety
/// `pixels` must satisfy the resident video engine's format/dimension contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn texture_define_image(
    width: u32,
    height: u32,
    pixel_format: u32,
    pixels: *const u8,
) {
    if let Some((source, output)) = descriptors(pixel_format) {
        video_engine_submit_frame(0xde1, 0, source, width, height, 0,
            source, output, pixels as usize as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixel_formats_select_the_exact_image_encodings() {
        let expected = [(0x1907, 0x8363), (0x1908, 0x8033),
            (0x1908, 0x8034), (0x1906, 0x1401),
            (0x1907, 0x1401), (0x1908, 0x1401)];
        for (format, encoding) in expected.into_iter().enumerate() {
            assert_eq!(descriptors(format as u32), Some(encoding));
        }
        for format in [6, 255, 256, 0x8000_0000, u32::MAX] {
            assert_eq!(descriptors(format), None);
            // No dispatcher is installed: a submission would fail here.
            unsafe { texture_define_image(u32::MAX, 0, format, core::ptr::null()) };
        }
    }
}

