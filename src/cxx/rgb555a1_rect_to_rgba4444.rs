//! `rgb555a1_rect_to_rgba4444` — original: `FUN_083b4fc0` @ `0x083b4fc0`
//! (208 bytes; **2 unconditional `bl` call sites**, no predicated `bl` call
//! sites, binary-scanned by decoding every ARM B/BL-immediate word in
//! `osos.dec`).
//!
//! The raw body starts with `push {r0-r11,lr}` and ends with `pop
//! {r4-r11,pc}` at 0x083b508c; 0x083b5090 starts a distinct function, with no
//! literal pool. It converts a nonempty rectangle of RGB555A1 source pixels to
//! RGBA4444 destination pixels. Both row strides are the row width in bytes,
//! rounded up to their supplied alignment. It positions each cursor at the
//! requested x/y offset, then converts pixels through the existing RGB555A1
//! unpacker and RGBA4444 packer before advancing to the next row.
//!
//! # Deliberate deviations
//!
//! The original calls its two cursor helpers with stack-local cursors and an
//! RGBA8 record. This port calls their existing Rust seams; it retains the
//! original do-while behavior, wrapping arithmetic, cursor order, and no NULL,
//! alignment, bounds, or zero-dimension guards.

use crate::cxx::color_unpack::rgb555a1_cursor_read_rgba8;
use crate::cxx::rgba8_cursor_write_rgba4444::rgba8_cursor_write_rgba4444;
use crate::util::align::align_up;

/// Converts a nonempty RGB555A1 rectangle to RGBA4444 using aligned source and
/// destination row strides.
///
/// # Safety
///
/// `source` and `destination` must address sufficiently large, aligned pixel
/// buffers for the requested nonzero rectangle and their rounded-up strides.
/// The original has no validation for any argument.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb555a1_rect_to_rgba4444(
    source: *const u16,
    source_width: u32,
    _source_format: u32,
    source_x: u32,
    source_y: u32,
    width: u32,
    height: u32,
    destination: *mut u16,
    destination_width: u32,
    _destination_format: u32,
    destination_x: u32,
    destination_y: u32,
    _unused_13: u32,
    _unused_14: u32,
    source_row_alignment: u32,
    destination_row_alignment: u32,
) {
    let source_stride = align_up(source_width.wrapping_mul(2), source_row_alignment);
    let destination_stride = align_up(destination_width.wrapping_mul(2), destination_row_alignment);
    let mut source_cursor = source.cast::<u8>().wrapping_add(
        source_stride
            .wrapping_mul(source_y)
            .wrapping_add(source_x.wrapping_mul(2)) as usize,
    ).cast::<u16>();
    let mut destination_cursor = destination.cast::<u8>().wrapping_add(
        destination_stride
            .wrapping_mul(destination_y)
            .wrapping_add(destination_x.wrapping_mul(2)) as usize,
    ).cast::<u16>();
    let mut remaining_rows = height;

    loop {
        let mut remaining_columns = width;
        loop {
            let mut components = [0; 4];
            rgb555a1_cursor_read_rgba8(components.as_mut_ptr(), 0, &mut source_cursor);
            rgba8_cursor_write_rgba4444(0, &mut destination_cursor, components.as_ptr());
            remaining_columns = remaining_columns.wrapping_sub(1);
            if remaining_columns == 0 {
                break;
            }
        }
        source_cursor = source_cursor.cast::<u8>().wrapping_add(
            source_stride.wrapping_sub(width.wrapping_mul(2)) as usize,
        ).cast::<u16>();
        destination_cursor = destination_cursor.cast::<u8>().wrapping_add(
            destination_stride.wrapping_sub(width.wrapping_mul(2)) as usize,
        ).cast::<u16>();
        remaining_rows = remaining_rows.wrapping_sub(1);
        if remaining_rows == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rgb555a1_rect_to_rgba4444;

    fn reference_rgba4444(pixel: u16) -> u16 {
        ((pixel >> 12) << 12)
            | (((pixel >> 7) & 0xf) << 8)
            | (((pixel >> 2) & 0xf) << 4)
            | if pixel & 1 == 0 { 0 } else { 0xf }
    }

    #[test]
    fn converts_one_offset_pixel_without_touching_neighbors() {
        let source = [0xaaaa, 0x8c43, 0x5555];
        let mut destination = [0xa5a5, 0x5a5a, 0xc3c3];

        unsafe {
            rgb555a1_rect_to_rgba4444(
                source.as_ptr(), 3, 0xffff_ffff, 1, 0, 1, 1,
                destination.as_mut_ptr(), 3, 0, 1, 0, 0, 0, 2, 2,
            );
        }

        assert_eq!(destination, [0xa5a5, reference_rgba4444(source[1]), 0xc3c3]);
    }

    #[test]
    fn honors_offsets_and_independent_padded_row_strides() {
        let source = [
            0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
            0xdead, 0x8c43, 0x07ff, 0xf801, 0x1234, 0xabcd, 0xdef1, 0x0f0f,
            0xbeef, 0x5555, 0xaaaa, 0xf0f1,
        ];
        let mut destination = [0xa5a5; 24];

        unsafe {
            rgb555a1_rect_to_rgba4444(
                source.as_ptr(), 5, 0, 1, 1, 3, 2,
                destination.as_mut_ptr(), 7, 0, 2, 1, 0, 0, 8, 16,
            );
        }

        assert_eq!(destination[10], reference_rgba4444(source[9]));
        assert_eq!(destination[11], reference_rgba4444(source[10]));
        assert_eq!(destination[12], reference_rgba4444(source[11]));
        assert_eq!(destination[18], reference_rgba4444(source[17]));
        assert_eq!(destination[19], reference_rgba4444(source[18]));
        assert_eq!(destination[20], reference_rgba4444(source[19]));
        for index in [0, 9, 13, 17, 21, 23] {
            assert_eq!(destination[index], 0xa5a5, "destination[{index}]");
        }
    }
}
