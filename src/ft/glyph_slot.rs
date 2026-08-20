//! FreeType glyph-slot bitmap ownership cleanup.
//!
//! The structures below retain the FreeType 2.x member order used by the
//! retailOS build.  Pointer fields widen on host builds; the port uses named
//! members rather than host-dependent raw offsets.

use core::ffi::c_void;

use crate::ft::memory::{ft_mem_free, FtMemory};
use crate::ft::types::{FtBBox, FtGlyphMetrics, FtOutline, FtVector};

/// `FT_Generic` — two pointer-sized fields in FreeType's public records.
#[repr(C)]
pub struct FtGeneric {
    pub data: *mut c_void,
    pub finalizer: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// `FT_Bitmap` — the glyph image descriptor.  `buffer` is at +0x0c on ARM.
#[repr(C)]
pub struct FtBitmap {
    pub rows: i32,
    pub width: i32,
    pub pitch: i32,
    pub buffer: *mut u8,
    pub num_grays: u16,
    pub pixel_mode: u8,
    pub palette_mode: u8,
    pub palette: *mut c_void,
}

/// `FT_FaceRec` fields through `memory`, which is at +0x64 on ARM.
#[repr(C)]
pub struct FtFace {
    pub num_faces: i32,
    pub face_index: i32,
    pub face_flags: i32,
    pub style_flags: i32,
    pub num_glyphs: i32,
    pub family_name: *mut u8,
    pub style_name: *mut u8,
    pub num_fixed_sizes: i32,
    pub available_sizes: *mut c_void,
    pub num_charmaps: i32,
    pub charmaps: *mut *mut c_void,
    pub generic: FtGeneric,
    pub bbox: FtBBox,
    pub units_per_em: u16,
    pub ascender: i16,
    pub descender: i16,
    pub height: i16,
    pub max_advance_width: i16,
    pub max_advance_height: i16,
    pub underline_position: i16,
    pub underline_thickness: i16,
    pub glyph: *mut FtGlyphSlot,
    pub size: *mut c_void,
    pub charmap: *mut FtCharMap,
    pub driver: *mut c_void,
    pub memory: *mut FtMemory,
}

/// `FT_CharMapRec` — public charmap prefix of the private `FT_CMapRec`.
/// `FT_CMap` extends this record and its `clazz` is at +0x0c on ARM.
#[repr(C)]
pub struct FtCharMap {
    pub face: *mut FtFace,
    pub encoding: u32,
    pub platform_id: u16,
    pub encoding_id: u16,
}

/// FreeType 2.3 `FT_CMap_ClassRec` prefix through `char_index`.
///
/// The first three words are `size`, `init`, and `done`; `char_index` is
/// consequently the callback at +0x0c in the retail ARM layout.
#[repr(C)]
pub struct FtCMapClass {
    pub size: u32,
    pub init: *const c_void,
    pub done: *const c_void,
    pub char_index: unsafe extern "C" fn(*mut FtCMap, u32) -> u32,
}

/// FreeType's private `FT_CMapRec`: its public `FT_CharMapRec` prefix plus
/// the class vtable pointer used by character lookup.
#[repr(C)]
pub struct FtCMap {
    pub charmap: FtCharMap,
    pub clazz: *const FtCMapClass,
}

/// `FT_GlyphSlot_InternalRec` prefix.  `flags` is at +4 on ARM.
#[repr(C)]
pub struct FtGlyphSlotInternal {
    pub loader: *mut c_void,
    pub flags: u32,
}

/// `FT_GlyphSlotRec` — the public glyph-slot record.  `bitmap.buffer` is at
/// +0x58 and `internal` is at +0x9c in the retail ARM layout.
#[repr(C)]
pub struct FtGlyphSlot {
    pub library: *mut c_void,
    pub face: *mut FtFace,
    pub next: *mut FtGlyphSlot,
    pub reserved: u32,
    pub generic: FtGeneric,
    pub metrics: FtGlyphMetrics,
    pub linear_hori_advance: i32,
    pub linear_vert_advance: i32,
    pub advance: FtVector,
    pub format: u32,
    pub bitmap: FtBitmap,
    pub bitmap_left: i32,
    pub bitmap_top: i32,
    pub outline: FtOutline,
    pub num_subglyphs: u32,
    pub subglyphs: *mut c_void,
    pub control_data: *mut c_void,
    pub control_len: i32,
    pub lsb_delta: i32,
    pub rsb_delta: i32,
    pub other: *mut c_void,
    pub internal: *mut FtGlyphSlotInternal,
}

/// The `FT_GLYPH_OWN_BITMAP` ownership bit in `FT_GlyphSlot_InternalRec`.
pub const FT_GLYPH_OWN_BITMAP: u32 = 1;

/// FreeType `FT_Get_Char_Index` (ftobjs.c) — original:
/// `FUN_0804c4d0` @ 0x0804c4d0 (48 bytes).
///
/// Returns zero when `face` or its selected charmap is absent. Otherwise,
/// casts the public `FT_CharMapRec` to its private `FT_CMapRec` extension and
/// invokes the class's `char_index(cmap, charcode)` callback. The FreeType
/// 2.3.0 source has these same two null gates; the raw ARM body loads
/// `face->charmap` at +0x5c, then `cmap->clazz` and `clazz->char_index` at
/// +0x0c before its indirect call. No deviations.
///
/// # Safety
/// A non-null `face->charmap` must be the `FT_CharMapRec` prefix of a valid
/// `FtCMap` with a valid `clazz` and `char_index` callback, just as required
/// by the original FreeType API.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_get_char_index(face: *mut FtFace, charcode: u32) -> u32 {
    if face.is_null() {
        return 0;
    }

    let charmap = (*face).charmap;
    if charmap.is_null() {
        return 0;
    }

    let cmap = charmap.cast::<FtCMap>();
    ((*(*cmap).clazz).char_index)(cmap, charcode)
}

/// FreeType `ft_glyphslot_free_bitmap` (ftobjs.c) — original:
/// `FUN_082cf9e4` @ 0x082cf9e4 (72 bytes).
///
/// If the glyph slot owns its bitmap (`internal->flags &
/// FT_GLYPH_OWN_BITMAP`), release `bitmap.buffer` via the owning face's
/// `FT_MemoryRec`, then clear both the buffer pointer and ownership bit.  A
/// non-owned (including stolen) buffer is merely cleared; its flags and its
/// allocator are untouched.  This is the `FT_FREE` cleanup helper used by
/// FreeType's glyph-slot clear, done, and bitmap-replacement paths.
///
/// # Safety
/// `slot`, `slot->internal`, and — when the ownership bit is set —
/// `slot->face` and its `memory` must be valid.  The buffer must belong to
/// that allocator when non-null.  As in the original, there are no null
/// guards for the slot or its internal record.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_glyphslot_free_bitmap(slot: *mut FtGlyphSlot) {
    let internal = (*slot).internal;

    if (*internal).flags & FT_GLYPH_OWN_BITMAP != 0 {
        let memory = (*(*slot).face).memory;
        ft_mem_free(memory, (*slot).bitmap.buffer);
        (*slot).bitmap.buffer = core::ptr::null_mut();
        (*internal).flags &= !FT_GLYPH_OWN_BITMAP;
    } else {
        (*slot).bitmap.buffer = core::ptr::null_mut();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FREED_BLOCK: AtomicUsize = AtomicUsize::new(0);
    static CHAR_INDEX_CMAP: AtomicUsize = AtomicUsize::new(0);
    static CHAR_INDEX_CODE: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn unused_alloc(_: *mut FtMemory, _: i32) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe extern "C" fn recording_free(_: *mut FtMemory, block: *mut u8) {
        FREE_CALLS.fetch_add(1, Ordering::Relaxed);
        FREED_BLOCK.store(block as usize, Ordering::Relaxed);
    }

    unsafe extern "C" fn recording_char_index(cmap: *mut FtCMap, charcode: u32) -> u32 {
        CHAR_INDEX_CMAP.store(cmap as usize, Ordering::Relaxed);
        CHAR_INDEX_CODE.store(charcode, Ordering::Relaxed);
        0x1234_5678
    }

    unsafe extern "C" fn unused_realloc(
        _: *mut FtMemory,
        _: i32,
        _: i32,
        _: *mut u8,
    ) -> *mut u8 {
        core::ptr::null_mut()
    }

    fn allocator() -> FtMemory {
        FtMemory {
            user: core::ptr::null_mut(),
            alloc: unused_alloc,
            free: recording_free,
            realloc: unused_realloc,
        }
    }

    #[test]
    fn owned_bitmap_is_freed_then_pointer_and_ownership_bit_are_cleared() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        FREE_CALLS.store(0, Ordering::Relaxed);
        FREED_BLOCK.store(0, Ordering::Relaxed);

        let mut bytes = [0u8; 8];
        let block = bytes.as_mut_ptr();
        let mut memory = allocator();
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        face.memory = &mut memory;
        let mut internal = FtGlyphSlotInternal {
            loader: core::ptr::null_mut(),
            flags: FT_GLYPH_OWN_BITMAP | 0x80,
        };
        let mut slot: FtGlyphSlot = unsafe { core::mem::zeroed() };
        slot.face = &mut face;
        slot.internal = &mut internal;
        slot.bitmap.buffer = block;

        unsafe { ft_glyphslot_free_bitmap(&mut slot) };

        assert_eq!(FREE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(FREED_BLOCK.load(Ordering::Relaxed), block as usize);
        assert!(slot.bitmap.buffer.is_null());
        assert_eq!(internal.flags, 0x80);
    }

    #[test]
    fn non_owned_bitmap_is_cleared_without_calling_the_allocator_or_changing_flags() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        FREE_CALLS.store(0, Ordering::Relaxed);
        FREED_BLOCK.store(0, Ordering::Relaxed);

        let mut bytes = [0u8; 8];
        let mut internal = FtGlyphSlotInternal {
            loader: core::ptr::null_mut(),
            flags: 0x80,
        };
        let mut slot: FtGlyphSlot = unsafe { core::mem::zeroed() };
        slot.internal = &mut internal;
        slot.bitmap.buffer = bytes.as_mut_ptr();

        unsafe { ft_glyphslot_free_bitmap(&mut slot) };

        assert_eq!(FREE_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(FREED_BLOCK.load(Ordering::Relaxed), 0);
        assert!(slot.bitmap.buffer.is_null());
        assert_eq!(internal.flags, 0x80);
    }

    #[test]
    fn char_index_returns_zero_for_a_null_face() {
        assert_eq!(unsafe { ft_get_char_index(core::ptr::null_mut(), 0x41) }, 0);
    }

    #[test]
    fn char_index_returns_zero_without_a_selected_charmap() {
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { ft_get_char_index(&mut face, 0x41) }, 0);
    }

    #[test]
    fn char_index_dispatches_to_the_cmap_class_callback() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        CHAR_INDEX_CMAP.store(0, Ordering::Relaxed);
        CHAR_INDEX_CODE.store(0, Ordering::Relaxed);

        let class = FtCMapClass {
            size: 0,
            init: core::ptr::null(),
            done: core::ptr::null(),
            char_index: recording_char_index,
        };
        let mut cmap = FtCMap {
            charmap: FtCharMap {
                face: core::ptr::null_mut(),
                encoding: 0,
                platform_id: 0,
                encoding_id: 0,
            },
            clazz: &class,
        };
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        cmap.charmap.face = &mut face;
        face.charmap = &mut cmap.charmap;

        assert_eq!(unsafe { ft_get_char_index(&mut face, 0x1f642) }, 0x1234_5678);
        assert_eq!(CHAR_INDEX_CMAP.load(Ordering::Relaxed), &mut cmap as *mut FtCMap as usize);
        assert_eq!(CHAR_INDEX_CODE.load(Ordering::Relaxed), 0x1f642);
    }
}
