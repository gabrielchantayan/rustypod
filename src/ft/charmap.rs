//! FreeType character-map enumeration.
//!
//! This module builds on the public `FT_CharMapRec` and private `FT_CMapRec`
//! layout shared with the glyph-slot ports.  The vtable overlay below extends
//! the existing `char_index` prefix through the `char_next` callback.

use core::ffi::c_void;

use crate::ft::glyph_slot::{FtCMap, FtFace};

/// `FT_CMap_ClassRec` through `char_next`.
///
/// `char_next` follows the `size`, `init`, `done`, and `char_index` words, so
/// it is at +0x10 in the retail ARM layout.
#[repr(C)]
struct FtCMapClassWithNext {
    size: u32,
    init: *const c_void,
    done: *const c_void,
    char_index: unsafe extern "C" fn(*mut FtCMap, u32) -> u32,
    char_next: unsafe extern "C" fn(*mut FtCMap, *mut u32) -> u32,
}

/// FreeType 2.3 `FT_Get_Next_Char` (ftobjs.c) — original:
/// `FUN_0804c578` @ 0x0804c578 (80 bytes).
///
/// Enumerates the selected character map by calling its `char_next` callback
/// with a mutable 32-bit character code.  It preserves FreeType's two null
/// gates: without a face or selected charmap it skips dispatch and reports a
/// zero glyph index.  A callback result of zero suppresses the returned
/// character code even if the callback changed it; the optional `agindex`
/// out-parameter always receives the callback's glyph index. No deviations.
///
/// # Safety
/// When `face` and `face->charmap` are non-null, the charmap must be the
/// `FT_CharMapRec` prefix of a valid `FtCMap` with a class vtable through its
/// `char_next` callback. `agindex`, when non-null, must be writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_get_next_char(
    face: *mut FtFace,
    charcode: u32,
    agindex: *mut u32,
) -> u32 {
    let mut result = 0;
    let mut glyph_index = 0;

    if !face.is_null() {
        let charmap = (*face).charmap;
        if !charmap.is_null() {
            let cmap = charmap.cast::<FtCMap>();
            let class = (*cmap).clazz.cast::<FtCMapClassWithNext>();
            let mut code = charcode;
            glyph_index = ((*class).char_next)(cmap, &mut code);
            if glyph_index != 0 {
                result = code;
            }
        }
    }

    if !agindex.is_null() {
        *agindex = glyph_index;
    }

    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::ft::glyph_slot::FtCharMap;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static NEXT_CMAP: AtomicUsize = AtomicUsize::new(0);
    static NEXT_INPUT: AtomicU32 = AtomicU32::new(0);
    static NEXT_CODE: AtomicU32 = AtomicU32::new(0);
    static NEXT_GLYPH_INDEX: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn recording_char_index(_: *mut FtCMap, _: u32) -> u32 {
        0
    }

    unsafe extern "C" fn recording_char_next(cmap: *mut FtCMap, code: *mut u32) -> u32 {
        NEXT_CMAP.store(cmap as usize, Ordering::Relaxed);
        NEXT_INPUT.store(*code, Ordering::Relaxed);
        *code = NEXT_CODE.load(Ordering::Relaxed);
        NEXT_GLYPH_INDEX.load(Ordering::Relaxed)
    }

    #[test]
    fn next_char_reports_a_zero_index_without_face_or_charmap() {
        let mut glyph_index = 0xffff_ffff;
        assert_eq!(unsafe { ft_get_next_char(core::ptr::null_mut(), 0x41, &mut glyph_index) }, 0);
        assert_eq!(glyph_index, 0);

        let mut face: FtFace = unsafe { core::mem::zeroed() };
        glyph_index = 0xffff_ffff;
        assert_eq!(unsafe { ft_get_next_char(&mut face, 0x41, &mut glyph_index) }, 0);
        assert_eq!(glyph_index, 0);
    }

    #[test]
    fn next_char_dispatches_and_returns_the_advanced_code_only_for_a_glyph() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        NEXT_CMAP.store(0, Ordering::Relaxed);
        NEXT_INPUT.store(0, Ordering::Relaxed);
        NEXT_CODE.store(0x1f642, Ordering::Relaxed);
        NEXT_GLYPH_INDEX.store(0x1234, Ordering::Relaxed);

        let class = FtCMapClassWithNext {
            size: 0,
            init: core::ptr::null(),
            done: core::ptr::null(),
            char_index: recording_char_index,
            char_next: recording_char_next,
        };
        let mut cmap = FtCMap {
            charmap: FtCharMap {
                face: core::ptr::null_mut(),
                encoding: 0,
                platform_id: 0,
                encoding_id: 0,
            },
            clazz: (&class as *const FtCMapClassWithNext).cast(),
        };
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        cmap.charmap.face = &mut face;
        face.charmap = &mut cmap.charmap;

        let mut glyph_index = 0;
        assert_eq!(unsafe { ft_get_next_char(&mut face, 0x41, &mut glyph_index) }, 0x1f642);
        assert_eq!(glyph_index, 0x1234);
        assert_eq!(NEXT_CMAP.load(Ordering::Relaxed), &mut cmap as *mut FtCMap as usize);
        assert_eq!(NEXT_INPUT.load(Ordering::Relaxed), 0x41);

        NEXT_GLYPH_INDEX.store(0, Ordering::Relaxed);
        glyph_index = 0xffff_ffff;
        assert_eq!(unsafe { ft_get_next_char(&mut face, 0x42, &mut glyph_index) }, 0);
        assert_eq!(glyph_index, 0);
        assert_eq!(NEXT_INPUT.load(Ordering::Relaxed), 0x42);
    }
}
