//! Port of the `0x1010` masked 16-bit rectangle fill helper `FUN_082565b4` @
//! `0x082565b4`.
//!
//! `masked_u16_rectangle_fill` — original: `FUN_082565b4` @ **0x082565b4**
//! (156 bytes; `0x082565b4..0x0825664f`; the next function begins at
//! `0x08256650`). Raw A32 decoding finds four direct inbound `bl` call sites:
//! `0x08256740`, `0x082568f8`, `0x08256b0c`, and `0x08256b34`; all are plain,
//! unconditional `bl`, with zero predicated inbound `bl` calls. The body has
//! one plain, unconditional outbound `bl` to `0x08038988` and no predicated
//! outbound `bl` calls.
//!
//! The context's words at offsets `0x90`, `0x94`, and `0x98` give the bitmap
//! row offset, row width, and full-fill row count. A `0xffff` mask delegates to
//! the retail 16-bit fill path over the entire bitmap; every other mask applies
//! `(old & !mask) | (value & mask)` to each pixel in the requested rectangle.
//!
//! # Deliberate deviations
//!
//! The retail full-fill branch calls the unported `0x08038988` helper. This
//! port emits its verified 16-bit fill loop directly; its word count is the
//! same `width * row_count >> 1` passed as the helper's byte count. Volatile
//! pixel accesses preserve the original read-modify-write order and prevent
//! LLVM bulk-memory substitution.

/// Fills masked 16-bit pixels in a bitmap described by a retailOS context.
///
/// # Safety
///
/// `context` must provide u32 words through offset `0x98`; `pixels` must be
/// writable for the full bitmap; and `rectangle` must provide four u32 words:
/// column, row, width, and height.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn masked_u16_rectangle_fill(
    context: *const u32,
    pixels: *mut u16,
    value: u16,
    mask: u16,
    rectangle: *const u32,
) {
    let row_offset = *context.add(0x94 / 4);

    if mask == u16::MAX {
        let full_fill_offset = *context.add(0x90 / 4);
        let row_count = *context.add(0x98 / 4);
        let pixel_count = row_offset.wrapping_mul(row_count) >> 1;
        let mut pixel = pixels.add(full_fill_offset.wrapping_mul(row_offset) as usize);
        let value = value as u32 | (value as u32) << 16;

        for _ in 0..pixel_count {
            core::ptr::write_volatile(pixel.cast::<u32>(), value);
            pixel = pixel.add(2);
        }
        return;
    }

    let column = *rectangle;
    let first_row = *rectangle.add(1);
    let rectangle_width = *rectangle.add(2);
    let rectangle_height = *rectangle.add(3);
    let mut pixel = pixels.add(row_offset.wrapping_mul(first_row).wrapping_add(column) as usize);
    let row_skip = row_offset.wrapping_sub(rectangle_width);
    let replacement = value & mask;

    for _ in 0..rectangle_height {
        for _ in 0..rectangle_width {
            let old = core::ptr::read_volatile(pixel);
            core::ptr::write_volatile(pixel, (old & !mask) | replacement);
            pixel = pixel.add(1);
        }
        pixel = pixel.add(row_skip as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::masked_u16_rectangle_fill;

    const ROW_WIDTH: usize = 6;

    fn context(full_fill_offset: u32, row_count: u32) -> [u32; 39] {
        let mut context = [0; 39];
        context[0x90 / 4] = full_fill_offset;
        context[0x94 / 4] = ROW_WIDTH as u32;
        context[0x98 / 4] = row_count;
        context
    }

    #[test]
    fn masks_only_the_requested_rectangle() {
        let context = context(0, 3);
        let rectangle = [1, 1, 3, 2];
        let mut pixels = [0xa5a5; ROW_WIDTH * 4];

        unsafe {
            masked_u16_rectangle_fill(
                context.as_ptr(),
                pixels.as_mut_ptr(),
                0x0c3c,
                0x0ff0,
                rectangle.as_ptr(),
            );
        }

        for row in 0..4 {
            for column in 0..ROW_WIDTH {
                let expected = if (1..3).contains(&row) && (1..4).contains(&column) {
                    0xac35
                } else {
                    0xa5a5
                };
                assert_eq!(pixels[row * ROW_WIDTH + column], expected);
            }
        }
    }

    #[test]
    fn full_mask_fills_context_bitmap_and_ignores_rectangle() {
        let context = context(1, 2);
        let rectangle = [4, 3, 0, 0];
        let mut pixels = [0xdead; ROW_WIDTH * 4];

        unsafe {
            masked_u16_rectangle_fill(
                context.as_ptr(),
                pixels.as_mut_ptr(),
                0x1234,
                u16::MAX,
                rectangle.as_ptr(),
            );
        }

        assert_eq!(&pixels[..ROW_WIDTH], &[0xdead; ROW_WIDTH]);
        assert_eq!(&pixels[ROW_WIDTH..ROW_WIDTH * 3], &[0x1234; ROW_WIDTH * 2]);
        assert_eq!(&pixels[ROW_WIDTH * 3..], &[0xdead; ROW_WIDTH]);
    }

    #[test]
    fn zero_sized_rectangle_is_a_no_op() {
        let context = context(0, 3);
        let rectangle = [2, 1, 0, 7];
        let mut pixels = [0x5a5a; ROW_WIDTH * 3];

        unsafe {
            masked_u16_rectangle_fill(
                context.as_ptr(),
                pixels.as_mut_ptr(),
                0xffff,
                0x00ff,
                rectangle.as_ptr(),
            );
        }

        assert_eq!(pixels, [0x5a5a; ROW_WIDTH * 3]);
    }
}
