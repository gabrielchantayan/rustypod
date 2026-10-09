//! Embedded-bitmap decoder storage initialization.

use core::ffi::c_void;
use crate::ft::glyph_slot::{ft_glyphslot_alloc_bitmap, FtBitmap, FtFace};

/// Decoder prefix: four ARM pointers followed by byte-sized state fields.
/// The unused second pointer is retained without assigning it an identity.
#[repr(C)]
pub struct FtSbitDecoder {
    pub face: *mut FtFace,
    pub reserved: *mut c_void,
    pub bitmap: *mut FtBitmap,
    /// Metrics start with unsigned height and width bytes.
    pub metrics: *const u8,
    pub metrics_loaded: u8,
    pub bitmap_allocated: u8,
    pub bit_depth: u8,
}

/// Initialize embedded-bitmap storage — `FUN_080df060` @ 0x080df060.
/// True extent: 180 bytes, ending at the next function's PUSH at 0x080df114.
/// Verified outgoing calls: one plain BL (ft_glyphslot_alloc_bitmap at
/// 0x082cf988), zero predicated BLs; two incoming plain BL call sites.
/// Copy height/width from metrics, round pitch for depths 1/2/4/8 and select
/// MONO/GRAY2/GRAY4/GRAY. Allocate pitch*rows through face->glyph, marking
/// bitmap_allocated only on allocation success. Empty images return success
/// without allocation or setting the flag. Missing metrics return 6; invalid
/// depth returns 3 after updating dimensions but before pitch/pixel mode.
/// No deliberate behavioral deviations. Named repr(C) fields widen host
/// pointers without changing the target layout; no new callee seam is needed.
///
/// # Safety
/// `decoder` must be valid. With loaded metrics, `bitmap` and at least two
/// metrics bytes must be valid. For a nonempty supported image, face->glyph
/// and its allocator/internal records must satisfy ft_glyphslot_alloc_bitmap.
/// Verification: 15,083 host tests pass, including all byte widths at each
/// supported depth, empty dimensions, invalid depths and allocation failure.
/// Standalone public-ABI smoke allocates and zeros a 9x3 mono image (6 bytes).
/// ARM release build passes. match.py reports 45 original versus 62 Rust
/// instructions: LLVM replaces predicated depth tests with a guarded jump
/// table, uses logical shifts for nonnegative widths and a halfword multiply
/// for byte-bounded dimensions, retaining the allocator call and flag gate.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_sbit_decoder_alloc_bitmap(decoder: *mut FtSbitDecoder) -> i32 {
    if (*decoder).metrics_loaded == 0 {
        return 6;
    }
    let bitmap = (*decoder).bitmap;
    let width = *(*decoder).metrics.add(1) as i32;
    let rows = *(*decoder).metrics as i32;
    (*bitmap).width = width;
    (*bitmap).rows = rows;
    let (pitch, pixel_mode) = match (*decoder).bit_depth {
        1 => ((width + 7) >> 3, 1),
        2 => ((width + 3) >> 2, 3),
        4 => ((width + 1) >> 1, 4),
        8 => (width, 2),
        _ => return 3,
    };
    (*bitmap).pixel_mode = pixel_mode;
    (*bitmap).pitch = pitch;
    let size = pitch * rows;
    if size == 0 {
        return 0;
    }
    let error = ft_glyphslot_alloc_bitmap((*(*decoder).face).glyph, size);
    if error == 0 {
        (*decoder).bitmap_allocated = 1;
    }
    error
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ft::glyph_slot::{FtGlyphSlot, FtGlyphSlotInternal};
    use crate::ft::memory::FtMemory;

    unsafe extern "C" fn alloc(memory: *mut FtMemory, size: i32) -> *mut u8 {
        let state = &mut *((*memory).user as *mut (i32, *mut u8));
        state.0 = size;
        state.1
    }
    unsafe extern "C" fn free(_: *mut FtMemory, _: *mut u8) {}
    unsafe extern "C" fn realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 {
        panic!("unexpected reallocation")
    }

    #[test]
    fn missing_metrics_and_invalid_depth_preserve_unwritten_fields() {
        unsafe {
            let mut bitmap: FtBitmap = core::mem::zeroed();
            bitmap.rows = -7;
            bitmap.width = -8;
            bitmap.pitch = -9;
            bitmap.pixel_mode = 99;
            let metrics = [17, 19];
            let mut decoder = FtSbitDecoder {
                face: core::ptr::null_mut(), reserved: core::ptr::null_mut(),
                bitmap: &mut bitmap, metrics: core::ptr::null(),
                metrics_loaded: 0, bitmap_allocated: 7, bit_depth: 1,
            };
            assert_eq!(ft_sbit_decoder_alloc_bitmap(&mut decoder), 6);
            assert_eq!((bitmap.rows, bitmap.width, bitmap.pitch, bitmap.pixel_mode), (-7, -8, -9, 99));
            decoder.metrics = metrics.as_ptr();
            decoder.metrics_loaded = 2;
            for depth in [0, 3, 5, 7, 9, 255] {
                decoder.bit_depth = depth;
                assert_eq!(ft_sbit_decoder_alloc_bitmap(&mut decoder), 3);
                assert_eq!((bitmap.rows, bitmap.width, bitmap.pitch, bitmap.pixel_mode), (17, 19, -9, 99));
                assert_eq!(decoder.bitmap_allocated, 7);
            }
        }
    }

    #[test]
    fn all_widths_depths_empty_images_and_allocator_failure() {
        unsafe {
            let mut storage = [0xa5u8; 65025];
            let mut state = (-1, storage.as_mut_ptr());
            let mut memory = FtMemory { user: (&mut state as *mut (i32, *mut u8)).cast(), alloc, free, realloc };
            let mut face: FtFace = core::mem::zeroed();
            let mut slot: FtGlyphSlot = core::mem::zeroed();
            let mut internal: FtGlyphSlotInternal = core::mem::zeroed();
            face.memory = &mut memory;
            face.glyph = &mut slot;
            slot.face = &mut face;
            slot.internal = &mut internal;
            let mut metrics = [0u8; 2];
            let mut decoder = FtSbitDecoder {
                face: &mut face, reserved: core::ptr::null_mut(), bitmap: &mut slot.bitmap,
                metrics: metrics.as_ptr(), metrics_loaded: 1, bitmap_allocated: 0, bit_depth: 1,
            };
            for (depth, pixels_per_byte, mode) in [(1, 8, 1), (2, 4, 3), (4, 2, 4), (8, 1, 2)] {
                decoder.bit_depth = depth;
                for width in 0..=255u8 {
                    for rows in [0, 1, 255u8] {
                        metrics[0] = rows;
                        metrics[1] = width;
                        let pitch = (width as i32 + pixels_per_byte - 1) / pixels_per_byte;
                        let size = pitch * rows as i32;
                        state.0 = -1;
                        decoder.bitmap_allocated = 0;
                        assert_eq!(ft_sbit_decoder_alloc_bitmap(&mut decoder), 0);
                        assert_eq!((slot.bitmap.rows, slot.bitmap.width, slot.bitmap.pitch, slot.bitmap.pixel_mode),
                                   (rows as i32, width as i32, pitch, mode));
                        assert_eq!(state.0, if size == 0 { -1 } else { size });
                        assert_eq!(decoder.bitmap_allocated, if size == 0 { 0 } else { 1 });
                        if size != 0 {
                            assert!(storage[..size as usize].iter().all(|&byte| byte == 0));
                            storage[..size as usize].fill(0xa5);
                        }
                    }
                }
            }
            state.1 = core::ptr::null_mut();
            metrics = [3, 9];
            decoder.metrics = metrics.as_ptr();
            for flag in [0, 7] {
                decoder.bitmap_allocated = flag;
                assert_eq!(ft_sbit_decoder_alloc_bitmap(&mut decoder), 0x40);
                assert_eq!(decoder.bitmap_allocated, flag);
                assert!(slot.bitmap.buffer.is_null());
                assert_eq!(state.0, 27);
            }
        }
    }
}
