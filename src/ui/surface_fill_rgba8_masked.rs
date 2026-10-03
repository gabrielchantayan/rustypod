//! RGBA8 masked surface fill — `FUN_082566e4` @ `0x082566e4`.
//!
//! True extent: 184 bytes, ending before the prologue at 0x0825679c.
//! Raw whole-image ARM decoding: 2 plain incoming BLs, 0 predicated;
//! 10 plain outgoing BLs, 0 predicated. Read format at +0x64, pack mask
//! before color using the existing format packers, then dispatch with the
//! buffer at +0x68 and rectangle to the 16/32-bit masked filler.
//! Unsupported formats do nothing. Full masks retain the callees' band-fill
//! behavior (surface +0x90/+0x94/+0x98), rather than imposing the rectangle.
//!
//! Deliberate deviations: the u32 writer uses the Rust port. Host callers
//! must install the unported u16 writer. Buffer fields remain 32-bit.

use crate::ui::{rgb565_pack::rgb8_to_rgb565, rgb555a1_pack::rgba8_to_rgb555a1,
    rgba4444_pack::rgba8_to_rgba4444, rgba8888_pack::rgba8_to_rgba8888};

pub type MaskedSurfaceFill = unsafe extern "C" fn(*mut u8, *mut u8, u32, u32, *const i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_fill16(surface: *mut u8, buffer: *mut u8, color: u32, mask: u32, rect: *const i32) {
    core::mem::transmute::<usize, MaskedSurfaceFill>(0x0825_65b4)(surface, buffer, color, mask, rect);
}
unsafe extern "C" fn fill32(surface: *mut u8, buffer: *mut u8, color: u32, mask: u32, rect: *const i32) {
    crate::util::masked_u32_rectangle_fill::masked_u32_rectangle_fill(
        surface.cast(), buffer.cast(), color, mask, rect.cast());
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_writer(_: *mut u8, _: *mut u8, _: u32, _: u32, _: *const i32) {
    panic!("surface_fill_rgba8_masked requires retailOS masked surface writers");
}

#[cfg(target_os = "none")]
pub static mut SURFACE_MASKED_FILL16: MaskedSurfaceFill = retail_fill16;
#[cfg(target_os = "none")]
pub static mut SURFACE_MASKED_FILL32: MaskedSurfaceFill = fill32;
#[cfg(not(target_os = "none"))]
pub static mut SURFACE_MASKED_FILL16: MaskedSurfaceFill = missing_writer;
#[cfg(not(target_os = "none"))]
pub static mut SURFACE_MASKED_FILL32: MaskedSurfaceFill = fill32;

/// # Safety
/// Surface has the retailOS layout through +0x9b. Supported formats require
/// readable component records (three bytes for RGB565, four otherwise) and
/// a valid buffer/rectangle for the writer. Host seam mutation must be serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn surface_fill_rgba8_masked(surface: *mut u8, color: *const u8, mask: *const u8, rect: *const i32) {
    let format = surface.add(0x64).cast::<i8>().read();
    let (packed_mask, packed_color) = match format {
        4 => (rgba8_to_rgba8888(mask), rgba8_to_rgba8888(color)),
        5 => (rgb8_to_rgb565(mask), rgb8_to_rgb565(color)),
        6 => (rgba8_to_rgba4444(mask), rgba8_to_rgba4444(color)),
        7 => (rgba8_to_rgb555a1(mask), rgba8_to_rgb555a1(color)),
        _ => return,
    };
    let buffer = surface.add(0x68).cast::<u32>().read() as usize as *mut u8;
    let writer = if format == 4 {
        core::ptr::addr_of!(SURFACE_MASKED_FILL32).read()
    } else {
        core::ptr::addr_of!(SURFACE_MASKED_FILL16).read()
    };
    writer(surface, buffer, packed_color, packed_mask, rect);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Executable callee model: asserts final pixels, not forwarded arguments.
    unsafe fn model16_pixels(surface: *mut u8, buffer: *mut u8, color: u32, mask: u32, rect: *const i32) {
        let stride = surface.add(0x94).cast::<u32>().read() as usize;
        let full = mask == 0xffff;
        let (x, y, width, height) = if full {
            (0, surface.add(0x90).cast::<u32>().read() as usize, stride,
                surface.add(0x98).cast::<u32>().read() as usize)
        } else {
            (rect.read() as usize, rect.add(1).read() as usize,
                rect.add(2).read() as usize, rect.add(3).read() as usize)
        };
        for row in y..y + height {
            for col in x..x + width {
                let index = row * stride + col;
                let p = buffer.cast::<u16>().add(index);
                p.write((p.read() & !(mask as u16)) | ((color & mask) as u16));
            }
        }
    }
    unsafe extern "C" fn model16(s: *mut u8, b: *mut u8, c: u32, m: u32, r: *const i32) { model16_pixels(s, b, c, m, r); }

    fn reference_pack(format: u8, bytes: [u8; 4]) -> u32 {
        let [r, g, b, a] = bytes.map(u32::from);
        match format {
            4 => r * 0x1000000 + g * 0x10000 + b * 0x100 + a,
            5 => (r / 8) * 2048 + (g / 4) * 32 + b / 8,
            6 => (r / 16) * 4096 + (g / 16) * 256 + (b / 16) * 16 + a / 16,
            7 => (r / 8) * 2048 + (g / 8) * 64 + (b / 8) * 2 + a / 128,
            _ => unreachable!(),
        }
    }

    #[test]
    fn masked_pixels_formats_empty_rectangles_and_full_mask_band() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::SURFACE_FILL_RGBA8_MASKED, 4096) else { return; };
        unsafe {
            let old16 = SURFACE_MASKED_FILL16;
            let old32 = SURFACE_MASKED_FILL32;
            SURFACE_MASKED_FILL16 = model16;
            SURFACE_MASKED_FILL32 = fill32;
            let buffer = slab.add(256);
            slab.add(0x68).cast::<u32>().write(buffer as usize as u32);
            slab.add(0x90).cast::<u32>().write(1);
            slab.add(0x94).cast::<u32>().write(4);
            slab.add(0x98).cast::<u32>().write(2);
            let color = [0xab, 0x67, 0xe1, 0x91];
            for format in 4..=7 {
                slab.add(0x64).write(format);
                for mask in [[0; 4], [0xf1, 0x83, 0x38, 0x80], [255; 4]] {
                    for rect in [[1, 1, 2, 2], [1, 1, 0, 2], [1, 1, 2, 0]] {
                        let wide = format == 4;
                        for i in 0..16 {
                            if wide { buffer.cast::<u32>().add(i).write(0x5a3cc3a5); }
                            else { buffer.cast::<u16>().add(i).write(0xc3a5); }
                        }
                        surface_fill_rgba8_masked(slab, color.as_ptr(), mask.as_ptr(), rect.as_ptr());
                        let m = reference_pack(format, mask);
                        let c = reference_pack(format, color);
                        let full = m == if wide { u32::MAX } else { 0xffff };
                        for i in 0..16 {
                            let inside = if full { (4..12).contains(&i) } else {
                                i / 4 >= 1 && i / 4 < 1 + rect[3] as usize &&
                                i % 4 >= 1 && i % 4 < 1 + rect[2] as usize
                            };
                            let before = if wide { 0x5a3cc3a5 } else { 0xc3a5 };
                            let expected = if inside { (before & !m) | (c & m) } else { before };
                            let actual = if wide { buffer.cast::<u32>().add(i).read() }
                                else { u32::from(buffer.cast::<u16>().add(i).read()) };
                            assert_eq!(actual, expected, "format={format} mask={mask:?} rect={rect:?} pixel={i}");
                        }
                    }
                }
            }
            SURFACE_MASKED_FILL16 = old16;
            SURFACE_MASKED_FILL32 = old32;
        }
    }

    #[test]
    fn unsupported_formats_do_not_read_sources_or_buffer() {
        let mut surface = [0u8; 101];
        for format in [0, 1, 2, 3, 8, 127, 128, 255] {
            surface[100] = format;
            unsafe { surface_fill_rgba8_masked(surface.as_mut_ptr(), core::ptr::null(), core::ptr::null(), core::ptr::null()); }
            assert_eq!(surface[100], format);
        }
    }
}
