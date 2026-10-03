//! Masked u32 bitmap fill — `FUN_08256650` @ **0x08256650**.
//!
//! True size: 140 bytes, ending at 0x082566dc (independent setter follows).
//! Raw A32: two incoming plain BLs (0x08256794, 0x082568e0), zero
//! predicated incoming BLs; zero plain or predicated outgoing BLs. Full mask
//! tail-branches with BEQ to the word-count fill entry at 0x08038994.
//! Context +0x90/+0x94/+0x98 specifies band origin, stride, and row count.
//! Full mask ignores the rectangle and fills that band. Other masks replace
//! selected bits in rectangle x/y/width/height, advancing by the stride.
//! Deliberate deviation: inline the verified 12-word/tail helper as a scalar
//! word loop, not a firmware seam. Volatile pixel accesses prevent bulk-memory
//! substitution and preserve zero-mask read/write behavior.

/// # Safety
/// Context provides aligned u32 words through +0x98. Pixels and all accessed
/// rectangle words must be valid and aligned; rectangle may be null for a full
/// mask. Geometry must describe accessible pixels; full-fill word count must
/// fit i32 (the stock helper uses signed subtraction and a computed tail jump).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn masked_u32_rectangle_fill(
    context: *const u32, pixels: *mut u32, value: u32, mask: u32,
    rectangle: *const u32,
) {
    let stride = context.add(0x94 / 4).read();
    if mask == u32::MAX {
        let origin = context.add(0x90 / 4).read();
        let rows = context.add(0x98 / 4).read();
        let count = stride.wrapping_mul(rows);
        let mut pixel = pixels.wrapping_add(stride.wrapping_mul(origin) as usize);
        for _ in 0..count {
            pixel.write_volatile(value);
            pixel = pixel.wrapping_add(1);
        }
        return;
    }
    let column = rectangle.read();
    let row = rectangle.add(1).read();
    let width = rectangle.add(2).read();
    let height = rectangle.add(3).read();
    let mut pixel = pixels.wrapping_add(stride.wrapping_mul(row).wrapping_add(column) as usize);
    let skip = stride.wrapping_sub(width) as i32;
    let replacement = value & mask;
    for _ in 0..height {
        // Stock reloads width each row; retain that behavior if storage aliases.
        for _ in 0..rectangle.add(2).read() {
            pixel.write_volatile((pixel.read_volatile() & !mask) | replacement);
            pixel = pixel.wrapping_add(1);
        }
        pixel = pixel.wrapping_offset(skip as isize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(stride: u32, origin: u32, rows: u32) -> [u32; 39] {
        let mut c = [0; 39];
        c[0x90 / 4] = origin; c[0x94 / 4] = stride; c[0x98 / 4] = rows;
        c
    }

    #[test]
    fn partial_and_zero_masks_preserve_other_bits_and_row_gaps() {
        let c = context(7, 0, 4);
        let rect = [2, 1, 3, 2];
        for mask in [0, 0x00ff_0ff0, 0xffff_0000] {
            let mut pixels = core::array::from_fn::<_, 28, _>(|i| 0xa5c3_1234 ^ i as u32);
            let before = pixels;
            unsafe { masked_u32_rectangle_fill(c.as_ptr(), pixels.as_mut_ptr(), 0x1234_abcd, mask, rect.as_ptr()); }
            for i in 0..28 {
                let expected = if (1..3).contains(&(i / 7)) && (2..5).contains(&(i % 7)) {
                    (before[i] & !mask) | (0x1234_abcd & mask)
                } else { before[i] };
                assert_eq!(pixels[i], expected, "index {i}, mask {mask:x}");
            }
        }
    }

    #[test]
    fn full_mask_ignores_null_rectangle_and_covers_helper_tail_boundaries() {
        for count in 0..=37 {
            let c = context(1, 3, count);
            let mut pixels = [0xdead_beef; 44];
            unsafe { masked_u32_rectangle_fill(c.as_ptr(), pixels.as_mut_ptr(), 0x1234_5678, u32::MAX, core::ptr::null()); }
            for i in 0..44 {
                assert_eq!(pixels[i], if (3..3 + count as usize).contains(&i) { 0x1234_5678 } else { 0xdead_beef });
            }
        }
        let c = context(5, 1, 3);
        let mut pixels = [0; 25];
        unsafe { masked_u32_rectangle_fill(c.as_ptr(), pixels.as_mut_ptr(), 9, u32::MAX, core::ptr::null()); }
        assert_eq!(pixels, [0,0,0,0,0,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0,0,0]);
    }

    #[test]
    fn empty_rectangles_access_no_pixels() {
        let c = context(6, 0, 1);
        for rect in [[0, 0, 0, 3], [0, 0, 4, 0]] {
            unsafe { masked_u32_rectangle_fill(c.as_ptr(), core::ptr::null_mut(), 1, 1, rect.as_ptr()); }
        }
    }
}
