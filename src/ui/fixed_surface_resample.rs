//! Fixed-coordinate surface resampling — `FUN_08273a54` @ `0x08273a54`.
//! True extent: 132 bytes through `0x08273ad8`, including 16 literal bytes;
//! executable size 116 bytes. Six plain outbound BLs, no predicated BLs.
//! Two inbound BLs: one plain and one EQ-predicated.
//!
//! Resample inclusive columns 9..145 first along y=32.3..42.7 with the
//! preceding-row blend, then y=168.19..162.456 with nearest-row selection.
//! Coordinates are truncated Q16.16 values from the original f32 words.
//! Deliberate deviation: LLVM may fold the four literal conversions. The
//! unported raster routines remain fixed-address calls on the device; host
//! callers must install equivalent implementations, not a silent fallback.

use crate::util::fixed::f32_to_fixed16_trunc;

/// Target descriptor: 32-bit pixel address, then 16-bit width and height.
#[repr(C)]
pub struct Surface565 {
    pub pixels: u32,
    pub width: u16,
    pub height: u16,
}

pub type ResamplePass = unsafe extern "C" fn(*mut Surface565, i32, i32, i32, i32);

unsafe extern "C" fn preceding_row(surface: *mut Surface565, x0: i32, y0: i32, x1: i32, y1: i32) {
    #[cfg(target_os = "none")]
    {
        let pass: ResamplePass = core::mem::transmute(0x08274004usize);
        pass(surface, x0, y0, x1, y1);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (surface, x0, y0, x1, y1); panic!("install preceding-row resampler on host"); }
}

unsafe extern "C" fn nearest_row(surface: *mut Surface565, x0: i32, y0: i32, x1: i32, y1: i32) {
    #[cfg(target_os = "none")]
    {
        let pass: ResamplePass = core::mem::transmute(0x08274108usize);
        pass(surface, x0, y0, x1, y1);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (surface, x0, y0, x1, y1); panic!("install nearest-row resampler on host"); }
}

pub static mut PRECEDING_ROW_RESAMPLE: ResamplePass = preceding_row;
pub static mut NEAREST_ROW_RESAMPLE: ResamplePass = nearest_row;

/// Apply both stock resampling passes in order.
///
/// # Safety
/// Descriptor and backing pixels must satisfy both original raster routines:
/// width must accommodate column 145, and rows 31..169 must be accessible.
/// Host seam replacement requires external synchronization.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_surface_resample(surface: *mut Surface565) {
    let mut y0 = 0;
    let mut y1 = 0;
    f32_to_fixed16_trunc(&mut y1, 0x422acccd);
    f32_to_fixed16_trunc(&mut y0, 0x42013333);
    let first = core::ptr::read_volatile(core::ptr::addr_of!(PRECEDING_ROW_RESAMPLE));
    first(surface, 9, y0, 145, y1);
    f32_to_fixed16_trunc(&mut y0, 0x432274bc);
    f32_to_fixed16_trunc(&mut y1, 0x432830a4);
    let second = core::ptr::read_volatile(core::ptr::addr_of!(NEAREST_ROW_RESAMPLE));
    second(surface, 9, y1, 145, y0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::rgb565_weighted_blend::rgb565_weighted_blend;

    #[repr(C)]
    struct Fixture {
        surface: Surface565,
        pixels: [u16; 320 * 240],
    }

    unsafe fn raster(surface: *mut Surface565, x0: i32, y0: i32, x1: i32, y1: i32, nearest: bool) {
        let fixture = &mut *surface.cast::<Fixture>();
        let width = fixture.surface.width as usize;
        let step = (y1 - y0) / (x1 - x0);
        let mut y = y0 + 0x8000;
        for x in x0..=x1 {
            let row = (y >> 16) as usize;
            let phase = y & 0xffff;
            let index = row * width + x as usize;
            let (a, b) = if nearest && phase > 0x8000 {
                (fixture.pixels[index + width], fixture.pixels[index])
            } else {
                (fixture.pixels[index], fixture.pixels[index - width])
            };
            fixture.pixels[index] = rgb565_weighted_blend(a, b, phase + i32::from(phase > 0x8000));
            y += step;
        }
    }

    unsafe extern "C" fn first(surface: *mut Surface565, x0: i32, y0: i32, x1: i32, y1: i32) {
        raster(surface, x0, y0, x1, y1, false);
    }

    unsafe extern "C" fn second(surface: *mut Surface565, x0: i32, y0: i32, x1: i32, y1: i32) {
        raster(surface, x0, y0, x1, y1, true);
    }

    #[test]
    fn resamples_nonuniform_pixels_without_touching_border_columns() {
        // Host dependency models exercise pixel effects, rather than recording
        // forwarding arguments. Only this test replaces these private seams.
        unsafe {
            let saved = (PRECEDING_ROW_RESAMPLE, NEAREST_ROW_RESAMPLE);
            PRECEDING_ROW_RESAMPLE = first;
            NEAREST_ROW_RESAMPLE = second;
            for width in [146, 320] {
                let mut actual = Fixture {
                    surface: Surface565 { pixels: 0, width, height: 240 },
                    pixels: core::array::from_fn(|i| (i as u16).wrapping_mul(7919)),
                };
                let mut expected = Fixture {
                    surface: Surface565 { pixels: 0, width, height: 240 },
                    pixels: actual.pixels,
                };
                let untouched = actual.pixels;
                fixed_surface_resample(&mut actual.surface);
                // Independent floating-point interpretation of the raw literals.
                raster(&mut expected.surface, 9, (32.3f32 * 65536.0) as i32,
                    145, (42.7f32 * 65536.0) as i32, false);
                raster(&mut expected.surface, 9, (168.19f32 * 65536.0) as i32,
                    145, (162.456f32 * 65536.0) as i32, true);
                assert_eq!(actual.pixels, expected.pixels);
                assert_ne!(actual.pixels, untouched);
                for row in 0..240 {
                    assert_eq!(&actual.pixels[row * width as usize..row * width as usize + 9],
                        &untouched[row * width as usize..row * width as usize + 9]);
                }
            }
            PRECEDING_ROW_RESAMPLE = saved.0;
            NEAREST_ROW_RESAMPLE = saved.1;
        }
    }
}
