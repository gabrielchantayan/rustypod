//! `rgb555a1_rect_to_rgba8` — original: `FUN_083b4ef4` @ `0x083b4ef4`
//! (204 bytes; **four unconditional outbound `bl` instructions** at two helper
//! sites, no predicated `bl` forms; exactly two inbound direct unconditional
//! `bl` sites, binary-scanned from `osos.dec`).
//!
//! The complete 51-word body starts with `push {r0-r11,lr}` and ends with `pop
//! {r4-r11,pc}` at 0x083b4fbc; 0x083b4fc0 starts a separately linked function,
//! with no literal pool. It converts a nonempty rectangle of RGB555A1 source
//! pixels to RGBA8 destination pixels. Both row strides are their row width in
//! bytes rounded up to their supplied alignment. It positions each cursor at
//! the requested x/y offset, then converts pixels through the existing RGB555A1
//! unpacker and RGBA8 writer before advancing to the next row.
//!
//! # Deliberate deviations
//!
//! The original calls its two cursor helpers with stack-local cursors and an
//! RGBA8 record. This port calls their existing Rust seams; it retains the
//! original do-while behavior, wrapping arithmetic, cursor order, and no NULL,
//! alignment, bounds, or zero-dimension guards.

use crate::cxx::color_unpack::rgb555a1_cursor_read_rgba8;
use crate::cxx::rgba8_cursor_write::rgba8_cursor_write;
use crate::util::align::align_up;

/// Converts a nonempty RGB555A1 rectangle to RGBA8 using aligned source and
/// destination row strides.
///
/// # Safety
///
/// `source` and `destination` must address sufficiently large, aligned pixel
/// buffers for the requested nonzero rectangle and their rounded-up strides.
/// The original has no validation for any argument.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb555a1_rect_to_rgba8(
    source: *const u16,
    source_width: u32,
    _source_format: u32,
    source_x: u32,
    source_y: u32,
    width: u32,
    height: u32,
    destination: *mut u8,
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
    let destination_stride = align_up(destination_width.wrapping_mul(4), destination_row_alignment);
    let mut source_cursor = source.cast::<u8>().wrapping_add(
        source_stride
            .wrapping_mul(source_y)
            .wrapping_add(source_x.wrapping_mul(2)) as usize,
    ).cast::<u16>();
    let mut destination_cursor = destination.wrapping_add(
        destination_stride
            .wrapping_mul(destination_y)
            .wrapping_add(destination_x.wrapping_mul(4)) as usize,
    );
    let mut remaining_rows = height;

    loop {
        let mut remaining_columns = width;
        loop {
            let mut components = [0; 4];
            rgb555a1_cursor_read_rgba8(components.as_mut_ptr(), 0, &mut source_cursor);
            rgba8_cursor_write(0, &mut destination_cursor, components.as_ptr());
            remaining_columns = remaining_columns.wrapping_sub(1);
            if remaining_columns == 0 {
                break;
            }
        }
        source_cursor = source_cursor.cast::<u8>().wrapping_add(
            source_stride.wrapping_sub(width.wrapping_mul(2)) as usize,
        ).cast::<u16>();
        destination_cursor = destination_cursor.wrapping_add(
            destination_stride.wrapping_sub(width.wrapping_mul(4)) as usize,
        );
        remaining_rows = remaining_rows.wrapping_sub(1);
        if remaining_rows == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rgb555a1_rect_to_rgba8;

    fn reference_rgba8(pixel: u16) -> [u8; 4] {
        let expand = |component: u8| (component << 3) | (component >> 2);
        [
            expand((pixel >> 11) as u8 & 0x1f),
            expand((pixel >> 6) as u8 & 0x1f),
            expand((pixel >> 1) as u8 & 0x1f),
            if pixel & 1 == 0 { 0 } else { 0xff },
        ]
    }

    #[test]
    fn converts_one_offset_pixel_without_touching_neighbors() {
        let source = [0xaaaa, 0x8c43, 0x5555];
        let mut destination = [0xa5; 16];

        unsafe {
            rgb555a1_rect_to_rgba8(
                source.as_ptr(), 3, 0xffff_ffff, 1, 0, 1, 1,
                destination.as_mut_ptr(), 3, 0, 1, 0, 0, 0, 2, 4,
            );
        }

        assert_eq!(&destination[4..8], &reference_rgba8(source[1]));
        assert_eq!(&destination[..4], &[0xa5; 4]);
        assert_eq!(&destination[8..], &[0xa5; 8]);
    }

    #[test]
    fn honors_offsets_and_independent_padded_row_strides() {
        let source = [
            0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
            0xdead, 0x8c43, 0x07ff, 0xf801, 0x1234, 0xabcd, 0xdef1, 0x0f0f,
            0xbeef, 0x5555, 0xaaaa, 0xf0f1,
        ];
        let mut destination = [0xa5; 96];

        unsafe {
            rgb555a1_rect_to_rgba8(
                source.as_ptr(), 5, 0, 1, 1, 3, 2,
                destination.as_mut_ptr(), 7, 0, 2, 1, 0, 0, 8, 16,
            );
        }

        assert_eq!(&destination[40..44], &reference_rgba8(source[9]));
        assert_eq!(&destination[44..48], &reference_rgba8(source[10]));
        assert_eq!(&destination[48..52], &reference_rgba8(source[11]));
        assert_eq!(&destination[72..76], &reference_rgba8(source[17]));
        assert_eq!(&destination[76..80], &reference_rgba8(source[18]));
        assert_eq!(&destination[80..84], &reference_rgba8(source[19]));
        for range in [0..40, 52..72, 84..96] {
            assert!(destination[range].iter().all(|&byte| byte == 0xa5));
        }
    }
}
