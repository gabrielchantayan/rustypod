//! FreeType smooth-outline rasterization.

use core::ffi::c_void;

use crate::ft::glyph_slot::{FtBitmap, FtGlyphSlot, FT_GLYPH_OWN_BITMAP};
use crate::ft::memory::{ft_mem_alloc, ft_mem_free, FtMemory};
use crate::ft::outline::{ft_outline_get_cbox, ft_outline_translate};
use crate::ft::types::{FtBBox, FtOutline, FtVector};

/// `FT_Raster_Params` prefix used by the smooth raster callback.
#[repr(C)]
pub struct FtRasterParams {
    pub target: *mut FtBitmap,
    pub source: *mut FtOutline,
    pub flags: u32,
}

/// `FT_RendererRec` members used by `ft_smooth_render_generic`. On ARM,
/// `memory`, `glyph_format`, `raster`, and `raster_render` are at +0x08,
/// +0x18, +0x3c, and +0x40 respectively.
#[repr(C)]
pub struct FtRenderer {
    _module_head: [u32; 2],
    pub memory: *mut FtMemory,
    _module_tail: [u32; 3],
    pub glyph_format: u32,
    _reserved: [u32; 8],
    pub raster: *mut c_void,
    pub raster_render: unsafe extern "C" fn(*mut c_void, *mut FtRasterParams) -> i32,
}

/// FreeType `ft_smooth_render_generic` (`ftsmooth.c`) — original:
/// `FUN_080d4364` @ 0x080d4364 (732 bytes, true executable extent
/// 0x080d4364..0x080d4640; the word at 0x080d4640 is its literal pool and
/// the following push starts the next function). Raw A32 decoding finds two
/// incoming plain `bl` calls (0x0809aa30 and 0x080b6978), no predicated
/// incoming calls, seven plain and one predicated direct outgoing `bl`, plus
/// one indirect `blx` raster callback.
///
/// Validates the renderer format and requested mode, temporarily applies an
/// origin, computes a 64-unit-aligned control box, replaces an owned bitmap,
/// allocates its grayscale buffer, calls the renderer raster callback, then
/// restores scaled coordinates and the origin. `x_scale` and `y_scale` are
/// applied before rasterization and divided back afterwards. On success it
/// commits bitmap format and the aligned left/top bearings. Deliberate
/// deviation: direct retail calls to the already-ported outline and memory
/// helpers are Rust calls; their observable order and arguments are retained.
///
/// # Safety
/// All non-null pointers and callback fields must denote valid FreeType
/// records and storage, as required by the retail implementation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_smooth_render_generic(
    renderer: *mut FtRenderer,
    slot: *mut FtGlyphSlot,
    mode: u32,
    origin: *const FtVector,
    required_mode: u32,
    x_scale: i32,
    y_scale: i32,
) -> i32 {
    if (*slot).format != (*renderer).glyph_format {
        return 6;
    }
    if mode != required_mode {
        return 0x13;
    }

    let outline = &mut (*slot).outline;
    if !origin.is_null() {
        ft_outline_translate(outline, (*origin).x, (*origin).y);
    }

    let mut cbox = FtBBox { x_min: 0, y_min: 0, x_max: 0, y_max: 0 };
    ft_outline_get_cbox(outline, &mut cbox);
    cbox.x_min &= !63;
    cbox.y_min &= !63;
    cbox.x_max = cbox.x_max.wrapping_add(63) & !63;
    cbox.y_max = cbox.y_max.wrapping_add(63) & !63;
    let mut width = (cbox.x_max.wrapping_sub(cbox.x_min) >> 6) as u32;
    let mut height = cbox.y_max.wrapping_sub(cbox.y_min) >> 6;

    if (*(*slot).internal).flags & FT_GLYPH_OWN_BITMAP != 0 {
        ft_mem_free((*renderer).memory, (*slot).bitmap.buffer);
        (*slot).bitmap.buffer = core::ptr::null_mut();
        (*(*slot).internal).flags &= !FT_GLYPH_OWN_BITMAP;
    }

    let pitch = if x_scale != 0 {
        width = (x_scale as u32).wrapping_mul(width);
        width.wrapping_add(3) & !3
    } else {
        width
    };
    if y_scale != 0 {
        height = y_scale.wrapping_mul(height);
    }
    (*slot).bitmap.pixel_mode = 2;
    (*slot).bitmap.num_grays = 0x100;
    (*slot).bitmap.pitch = pitch as i32;
    (*slot).bitmap.rows = height;
    (*slot).bitmap.width = width as i32;

    let mut error = 0;
    (*slot).bitmap.buffer = ft_mem_alloc((*renderer).memory, height.wrapping_mul(pitch as i32), &mut error);
    if error == 0 {
        (*(*slot).internal).flags |= FT_GLYPH_OWN_BITMAP;
        ft_outline_translate(outline, cbox.x_min.wrapping_neg(), cbox.y_min.wrapping_neg());
        if x_scale != 0 {
            let mut point = outline.points;
            for _ in 0..outline.n_points.max(0) as usize {
                (*point).x = x_scale.wrapping_mul((*point).x);
                point = point.add(1);
            }
        }
        if y_scale != 0 {
            let mut point = outline.points;
            for _ in 0..outline.n_points.max(0) as usize {
                (*point).y = y_scale.wrapping_mul((*point).y);
                point = point.add(1);
            }
        }
        let mut params = FtRasterParams { target: &mut (*slot).bitmap, source: outline, flags: 1 };
        error = ((*renderer).raster_render)((*renderer).raster, &mut params);
        if x_scale != 0 {
            let mut point = outline.points;
            for _ in 0..outline.n_points.max(0) as usize {
                (*point).x /= x_scale;
                point = point.add(1);
            }
        }
        if y_scale != 0 {
            let mut point = outline.points;
            for _ in 0..outline.n_points.max(0) as usize {
                (*point).y /= y_scale;
                point = point.add(1);
            }
        }
        ft_outline_translate(outline, cbox.x_min, cbox.y_min);
        if error == 0 {
            (*slot).format = 0x7362_6974;
            (*slot).bitmap_left = cbox.x_min >> 6;
            (*slot).bitmap_top = cbox.y_max >> 6;
        }
    }
    if !origin.is_null() {
        ft_outline_translate(outline, (*origin).x.wrapping_neg(), (*origin).y.wrapping_neg());
    }
    error
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::ft::glyph_slot::FtGlyphSlotInternal;
    use core::alloc::Layout;
    use core::sync::atomic::{AtomicU32, Ordering};

    static CALLBACK_FLAGS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn alloc(_: *mut FtMemory, size: i32) -> *mut u8 {
        std::alloc::alloc_zeroed(Layout::from_size_align(size as usize, 4).unwrap())
    }
    unsafe extern "C" fn free(_: *mut FtMemory, block: *mut u8) {
        if !block.is_null() {
            std::alloc::dealloc(block, Layout::from_size_align(4, 4).unwrap());
        }
    }
    unsafe extern "C" fn realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn render(_: *mut c_void, params: *mut FtRasterParams) -> i32 {
        CALLBACK_FLAGS.store((*params).flags, Ordering::Relaxed);
        0
    }

    #[test]
    fn rejects_wrong_format_before_dereferencing_other_slot_fields() {
        let mut slot: FtGlyphSlot = unsafe { core::mem::zeroed() };
        let renderer = FtRenderer {
            _module_head: [0; 2], memory: core::ptr::null_mut(), _module_tail: [0; 3],
            glyph_format: 7, _reserved: [0; 8], raster: core::ptr::null_mut(), raster_render: render,
        };
        slot.format = 6;
        assert_eq!(unsafe { ft_smooth_render_generic(&renderer as *const _ as *mut _, &mut slot, 0, core::ptr::null(), 0, 0, 0) }, 6);
    }

    #[test]
    fn rasterizes_aligned_box_and_restores_origin_and_scaled_points() {
        let mut memory = FtMemory { user: core::ptr::null_mut(), alloc, free, realloc };
        let mut internal = FtGlyphSlotInternal { loader: core::ptr::null_mut(), flags: 0 };
        let mut points = [FtVector { x: 65, y: 127 }, FtVector { x: 129, y: 192 }];
        let mut slot: FtGlyphSlot = unsafe { core::mem::zeroed() };
        slot.internal = &mut internal;
        slot.format = 3;
        slot.outline.n_points = 2;
        slot.outline.points = points.as_mut_ptr();
        let renderer = FtRenderer {
            _module_head: [0; 2], memory: &mut memory, _module_tail: [0; 3],
            glyph_format: 3, _reserved: [0; 8], raster: core::ptr::null_mut(), raster_render: render,
        };
        let origin = FtVector { x: 4, y: -5 };
        CALLBACK_FLAGS.store(0, Ordering::Relaxed);
        assert_eq!(unsafe { ft_smooth_render_generic(&renderer as *const _ as *mut _, &mut slot, 2, &origin, 2, 2, 3) }, 0);
        assert_eq!(CALLBACK_FLAGS.load(Ordering::Relaxed), 1);
        assert_eq!(points, [FtVector { x: 65, y: 127 }, FtVector { x: 129, y: 192 }]);
        assert_eq!((slot.bitmap.width, slot.bitmap.rows, slot.bitmap.pitch), (4, 6, 4));
        assert_eq!((slot.bitmap_left, slot.bitmap_top, slot.format), (1, 3, 0x7362_6974));
    }
}
