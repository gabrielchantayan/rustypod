//! Port of the retailOS hash-glyph-cell rasterizer at `0x082924d4`.
//!
//! `hash_glyph_cells_to_rgb565` — original: `FUN_082924d4` @ `0x082924d4`
//! (116 bytes; `0x082924d4..0x08292548`; the next function starts at
//! `0x08292548`). Raw ARM decoding finds exactly five direct call sites, all
//! unconditional `bl` at `0x082923a4`, `0x082923cc`, `0x082923e0`,
//! `0x08292408`, and `0x0829248c`; there are no predicated calls.
//!
//! # Algorithm
//!
//! The source is a row-major sequence of 3-by-5 glyph cells, with four source
//! bytes reserved per glyph per row (the fourth byte is padding). Starting
//! with the rightmost glyph, the function turns `'#'` cells into RGB565
//! `0x0821` and every other byte into `0xffff`. It writes each three-pixel row
//! at `destination`, advances by `destination_stride_pixels`, then moves four
//! pixels left for the next glyph. The five callers in `FUN_082922fc` use it to
//! render fixed status text into a display buffer.
//!
//! The retail function decrements its now-dead destination register four extra
//! pixels after the final glyph. This port omits that unobservable decrement,
//! avoiding formation of an out-of-bounds Rust pointer.

const HASH_CELL_COLOR: u16 = 0x0821;
const OTHER_CELL_COLOR: u16 = 0xffff;
const GLYPH_WIDTH: usize = 3;
const GLYPH_SOURCE_STRIDE: usize = 4;
const GLYPH_HEIGHT: usize = 5;

/// Converts packed `'#'` glyph cells to RGB565 display pixels.
///
/// `destination` points at the first (rightmost) glyph's left pixel; every
/// preceding glyph begins four pixels earlier. `source` contains
/// `glyph_count * GLYPH_HEIGHT` four-byte rows.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_glyph_cells_to_rgb565(
    mut destination: *mut u16,
    source: *const u8,
    glyph_count: usize,
    destination_stride_pixels: usize,
) {
    for glyph in (0..glyph_count).rev() {
        for row in 0..GLYPH_HEIGHT {
            let source_row = source.add((row * glyph_count + glyph) * GLYPH_SOURCE_STRIDE);
            for column in 0..GLYPH_WIDTH {
                let color = if *source_row.add(column) == b'#' {
                    HASH_CELL_COLOR
                } else {
                    OTHER_CELL_COLOR
                };
                *destination.add(column) = color;
            }
            destination = destination.add(destination_stride_pixels);
        }
        if glyph != 0 {
            destination = destination.sub(GLYPH_HEIGHT * destination_stride_pixels + 4);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(
        destination: &mut [u16],
        start: usize,
        source: &[u8],
        glyph_count: usize,
        stride: usize,
    ) {
        for glyph in (0..glyph_count).rev() {
            let glyph_start = start - (glyph_count - 1 - glyph) * 4;
            for row in 0..GLYPH_HEIGHT {
                for column in 0..GLYPH_WIDTH {
                    destination[glyph_start + row * stride + column] =
                        if source[(row * glyph_count + glyph) * GLYPH_SOURCE_STRIDE + column] == b'#' {
                            HASH_CELL_COLOR
                        } else {
                            OTHER_CELL_COLOR
                        };
                }
            }
        }
    }

    #[test]
    fn converts_three_glyphs_without_reading_padding() {
        const GLYPH_COUNT: usize = 3;
        let glyph_count = GLYPH_COUNT;
        let stride = 16;
        let start = 12;
        let mut source = [b'.'; GLYPH_HEIGHT * GLYPH_COUNT * GLYPH_SOURCE_STRIDE];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = if index % 5 == 0 { b'#' } else { b'.' };
        }
        for row in 0..GLYPH_HEIGHT {
            for glyph in 0..glyph_count {
                source[(row * glyph_count + glyph) * GLYPH_SOURCE_STRIDE + 3] = b'#';
            }
        }

        let mut actual = [0xa55a; 96];
        let mut expected = actual;
        reference(&mut expected, start, &source, glyph_count, stride);
        unsafe {
            hash_glyph_cells_to_rgb565(
                actual.as_mut_ptr().add(start),
                source.as_ptr(),
                glyph_count,
                stride,
            );
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn zero_glyphs_leaves_destination_untouched() {
        let mut destination = [0x5aa5; 12];
        unsafe {
            hash_glyph_cells_to_rgb565(destination.as_mut_ptr(), core::ptr::null(), 0, 4);
        }
        assert_eq!(destination, [0x5aa5; 12]);
    }
}
