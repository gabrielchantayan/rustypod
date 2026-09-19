//! FreeType glyph-loader subglyph storage.

use crate::ft::memory::{ft_mem_realloc, FtMemory};
use crate::ft::types::{FtOutline, FtVector};

/// `FT_SubGlyphRec` is 32 bytes in this FreeType build. Its contents are
/// immaterial to the loader's capacity check.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FtSubGlyph {
    _words: [u32; 8],
}

/// `FT_GlyphLoadRec` — 32 bytes on ARM. `num_subglyphs` and `subglyphs` are
/// at +0x18 and +0x1c respectively.
#[repr(C)]
pub struct FtGlyphLoad {
    pub outline: FtOutline,
    pub extra_points: *mut FtVector,
    pub num_subglyphs: u32,
    pub subglyphs: *mut FtSubGlyph,
}

/// `FT_GlyphLoaderRec` fields used by [`ft_glyphloader_check_subglyphs`].
/// On ARM `base` and `current` begin at +0x14 and +0x34; host pointers widen,
/// so all accesses deliberately use fields rather than byte offsets.
#[repr(C)]
pub struct FtGlyphLoader {
    pub memory: *mut FtMemory,
    pub max_points: u32,
    pub max_contours: u32,
    pub max_subglyphs: u32,
    pub use_extra: u8,
    _padding: [u8; 3],
    pub base: FtGlyphLoad,
    pub current: FtGlyphLoad,
}

/// FreeType `FT_GlyphLoader_CheckSubGlyphs` (`ftgloadr.c`) — original:
/// `FUN_0804c798` @ 0x0804c798 (120 bytes; true extent through 0x0804c810;
/// 4 incoming `bl` call sites, 1 plain outgoing `bl` and 1 predicated
/// `bleq`).
///
/// Ensures capacity for `base.num_subglyphs + current.num_subglyphs +
/// n_subglyphs`, rounding a required growth up to an even count. It renews
/// the 32-byte `FT_SubGlyphRec` array through [`ft_mem_realloc`] and, on
/// success, updates `current.subglyphs` to the base-array element after the
/// committed subglyphs. The original reaches that final assignment through
/// `FT_GlyphLoader_Adjust_SubGlyphs` @ 0x080e2d58; it is inlined here because
/// this is its only observed caller and its six-instruction body is exactly
/// that field assignment. No other deviations.
///
/// # Safety
/// `loader` must point to a valid glyph loader. Its memory allocator and its
/// existing subglyph array must satisfy [`ft_mem_realloc`]'s requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_glyphloader_check_subglyphs(
    loader: *mut FtGlyphLoader,
    n_subglyphs: u32,
) -> i32 {
    let loader = &mut *loader;
    let required = loader.base.num_subglyphs
        .wrapping_add(loader.current.num_subglyphs)
        .wrapping_add(n_subglyphs);

    if required > loader.max_subglyphs {
        let new_max = required.wrapping_add(1) & !1;
        let mut error = 0;
        loader.base.subglyphs = ft_mem_realloc(
            loader.memory,
            0x20,
            loader.max_subglyphs as i32,
            new_max as i32,
            loader.base.subglyphs.cast(),
            &mut error,
        )
        .cast();
        if error == 0 {
            loader.max_subglyphs = new_max;
            loader.current.subglyphs = loader.base.subglyphs.add(loader.base.num_subglyphs as usize);
        }
        return error;
    }

    0
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use core::alloc::Layout;

    unsafe extern "C" fn alloc(_: *mut FtMemory, size: i32) -> *mut u8 {
        std::alloc::alloc_zeroed(Layout::from_size_align(size as usize, 4).unwrap())
    }

    unsafe extern "C" fn free(_: *mut FtMemory, _: *mut u8) {}

    unsafe extern "C" fn realloc(
        _: *mut FtMemory,
        _: i32,
        _: i32,
        _: *mut u8,
    ) -> *mut u8 {
        core::ptr::null_mut()
    }

    fn loader(memory: *mut FtMemory) -> FtGlyphLoader {
        FtGlyphLoader {
            memory,
            max_points: 0,
            max_contours: 0,
            max_subglyphs: 0,
            use_extra: 0,
            _padding: [0; 3],
            base: unsafe { core::mem::zeroed() },
            current: unsafe { core::mem::zeroed() },
        }
    }

    #[test]
    fn grows_even_capacity_and_adjusts_current_subglyphs() {
        let mut memory = FtMemory { user: core::ptr::null_mut(), alloc, free, realloc };
        let mut glyph_loader = loader(&mut memory);
        glyph_loader.base.num_subglyphs = 1;
        glyph_loader.current.num_subglyphs = 2;

        assert_eq!(unsafe { ft_glyphloader_check_subglyphs(&mut glyph_loader, 2) }, 0);
        assert_eq!(glyph_loader.max_subglyphs, 6);
        assert!(!glyph_loader.base.subglyphs.is_null());
        assert_eq!(glyph_loader.current.subglyphs, unsafe { glyph_loader.base.subglyphs.add(1) });
    }

    #[test]
    fn leaves_storage_untouched_when_existing_capacity_suffices() {
        let mut memory = FtMemory { user: core::ptr::null_mut(), alloc, free, realloc };
        let mut glyph_loader = loader(&mut memory);
        let mut storage = [FtSubGlyph { _words: [0; 8] }; 4];
        glyph_loader.max_subglyphs = 4;
        glyph_loader.base.num_subglyphs = 1;
        glyph_loader.current.num_subglyphs = 2;
        glyph_loader.base.subglyphs = storage.as_mut_ptr();
        glyph_loader.current.subglyphs = unsafe { storage.as_mut_ptr().add(3) };

        assert_eq!(unsafe { ft_glyphloader_check_subglyphs(&mut glyph_loader, 1) }, 0);
        assert_eq!(glyph_loader.max_subglyphs, 4);
        assert_eq!(glyph_loader.base.subglyphs, storage.as_mut_ptr());
        assert_eq!(glyph_loader.current.subglyphs, unsafe { storage.as_mut_ptr().add(3) });
    }
}
