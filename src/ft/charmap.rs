//! FreeType character-map enumeration.
//!
//! This module builds on the public `FT_CharMapRec` and private `FT_CMapRec`
//! layout shared with the glyph-slot ports.  The vtable overlay below extends
//! the existing `char_index` prefix through the `char_next` callback.

use core::ffi::c_void;

use crate::ft::error::{
    FT_ERR_INVALID_ARGUMENT, FT_ERR_INVALID_CHARMAP_HANDLE, FT_ERR_INVALID_FACE_HANDLE,
    FT_ERR_OK,
};
use crate::ft::glyph_slot::{FtCMap, FtCharMap, FtFace};

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

/// FreeType 2.3 `FT_Set_Charmap` (ftobjs.c) — original: `FUN_0804ec64`
/// @ 0x0804ec64 (88 bytes, 0 BL instructions; 4 direct callers in osos.asm at
/// 0x080770a8, 0x0807711c, 0x080bf610, and 0x080e6b68 — Ghidra's "5 call
/// sites" overcounts).
///
/// Selects `face`'s active character map by scanning `face->charmaps` for a
/// pointer identical to `charmap`.  Null face returns
/// `FT_Err_Invalid_Face_Handle` (0x23); a null charmap table returns
/// `FT_Err_Invalid_CharMap_Handle` (0x26).  On the first match the matched
/// table entry (not the argument) is stored into `face->charmap` and zero is
/// returned; exhausting `face->num_charmaps` entries returns
/// `FT_Err_Invalid_Argument` (6).  The original computes the table limit as
/// `charmaps + num_charmaps` in raw words, so a negative count yields an
/// empty scan; the port's `0..num_charmaps` range reproduces that.
/// No deviations.
///
/// # Safety
/// `face`, when non-null, must be a valid `FT_FaceRec`; `face->charmaps`,
/// when non-null, must point to `face->num_charmaps` readable charmap
/// pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_set_charmap(
    face: *mut FtFace,
    charmap: *mut FtCharMap,
) -> i32 {
    if face.is_null() {
        return FT_ERR_INVALID_FACE_HANDLE;
    }
    let charmaps = (*face).charmaps.cast::<*mut FtCharMap>();
    if charmaps.is_null() {
        return FT_ERR_INVALID_CHARMAP_HANDLE;
    }
    for i in 0..(*face).num_charmaps {
        let cur = *charmaps.offset(i as isize);
        if cur == charmap {
            (*face).charmap = cur;
            return FT_ERR_OK;
        }
    }
    FT_ERR_INVALID_ARGUMENT
}

/// FreeType 2.3 `FT_Select_Charmap` (ftobjs.c) — original:
/// `FUN_0804ea90` @ 0x0804ea90 (108 bytes through its Unicode literal at
/// 0x0804eaf8; 0 outgoing BL instructions; 3 plain direct inbound BL calls
/// at 0x080ad4dc, 0x080bf5c8, and 0x080e6a6c; no predicated inbound BL calls).
///
/// Selects an encoding from `face->charmaps`. Non-Unicode encodings take the
/// first forward match. Unicode scans backward, preferring platform 3,
/// encoding 10, then platform 0, encoding 4; if neither exists, it retains
/// the last Unicode map encountered by the reverse scan. Null faces return
/// `FT_Err_Invalid_Face_Handle` (0x23); absent tables and unmatched Unicode
/// maps return `FT_Err_Invalid_CharMap_Handle` (0x26).
///
/// Deliberate deviation: the retail function branches to shared code at
/// 0x080b6828 for Unicode; this port inlines that verified branch target so
/// the hook does not re-enter retailOS.
///
/// # Safety
/// `face`, when non-null, must be a valid `FT_FaceRec`; `face->charmaps`,
/// when non-null, must point to `face->num_charmaps` readable charmap pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_select_charmap(face: *mut FtFace, encoding: u32) -> i32 {
    const FT_ENCODING_UNICODE: u32 = 0x756e_6963;

    if face.is_null() {
        return 0x23;
    }

    let charmaps = (*face).charmaps;
    if charmaps.is_null() {
        return 0x26;
    }

    let count = (*face).num_charmaps;
    if encoding != FT_ENCODING_UNICODE {
        for index in 0..count {
            let charmap = (*charmaps.offset(index as isize)).cast::<FtCharMap>();
            if (*charmap).encoding == encoding {
                (*face).charmap = charmap;
                return 0;
            }
        }
        return 6;
    }

    let mut fallback = core::ptr::null_mut();
    for index in (0..count).rev() {
        let charmap = (*charmaps.offset(index as isize)).cast::<FtCharMap>();
        if (*charmap).encoding != FT_ENCODING_UNICODE {
            continue;
        }

        fallback = charmap;
        if ((*charmap).platform_id == 3 && (*charmap).encoding_id == 10)
            || ((*charmap).platform_id == 0 && (*charmap).encoding_id == 4)
        {
            (*face).charmap = charmap;
            return 0;
        }
    }

    if fallback.is_null() {
        0x26
    } else {
        (*face).charmap = fallback;
        0
    }
}


#[cfg(test)]
mod select_charmap_tests {
    use super::*;
    use core::mem::MaybeUninit;

    fn face_with(charmaps: &mut [*mut core::ffi::c_void]) -> FtFace {
        let mut face = unsafe { MaybeUninit::<FtFace>::zeroed().assume_init() };
        face.num_charmaps = charmaps.len() as i32;
        face.charmaps = charmaps.as_mut_ptr();
        face
    }

    #[test]
    fn rejects_null_face_and_missing_charmap_table() {
        assert_eq!(unsafe { ft_select_charmap(core::ptr::null_mut(), 1) }, 0x23);
        let face = unsafe { MaybeUninit::<FtFace>::zeroed().assume_init() };
        assert_eq!(unsafe { ft_select_charmap(&raw const face as *mut FtFace, 1) }, 0x26);
    }

    #[test]
    fn selects_first_non_unicode_match_and_rejects_absent_encoding() {
        let mut first = FtCharMap { face: core::ptr::null_mut(), encoding: 7, platform_id: 0, encoding_id: 0 };
        let mut second = FtCharMap { face: core::ptr::null_mut(), encoding: 7, platform_id: 0, encoding_id: 0 };
        let mut maps = [(&raw mut first).cast(), (&raw mut second).cast()];
        let mut face = face_with(&mut maps);

        assert_eq!(unsafe { ft_select_charmap(&raw mut face, 7) }, 0);
        assert_eq!(face.charmap, &raw mut first);
        assert_eq!(unsafe { ft_select_charmap(&raw mut face, 8) }, 6);
    }

    #[test]
    fn unicode_prefers_windows_then_unicode_platform_and_falls_back_to_last() {
        let mut fallback = FtCharMap { face: core::ptr::null_mut(), encoding: 0x756e_6963, platform_id: 1, encoding_id: 0 };
        let mut unicode = FtCharMap { face: core::ptr::null_mut(), encoding: 0x756e_6963, platform_id: 0, encoding_id: 4 };
        let mut windows = FtCharMap { face: core::ptr::null_mut(), encoding: 0x756e_6963, platform_id: 3, encoding_id: 10 };
        let mut maps = [(&raw mut fallback).cast(), (&raw mut unicode).cast(), (&raw mut windows).cast()];
        let mut face = face_with(&mut maps);

        assert_eq!(unsafe { ft_select_charmap(&raw mut face, 0x756e_6963) }, 0);
        assert_eq!(face.charmap, &raw mut windows);

        maps = [(&raw mut fallback).cast(), (&raw mut fallback).cast(), (&raw mut fallback).cast()];
        assert_eq!(unsafe { ft_select_charmap(&raw mut face, 0x756e_6963) }, 0);
        assert_eq!(face.charmap, &raw mut fallback);
    }
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

    fn blank_charmap() -> FtCharMap {
        FtCharMap {
            face: core::ptr::null_mut(),
            encoding: 0,
            platform_id: 0,
            encoding_id: 0,
        }
    }

    #[test]
    fn set_charmap_rejects_null_face_and_null_table() {
        let mut charmap = blank_charmap();
        assert_eq!(
            unsafe { ft_set_charmap(core::ptr::null_mut(), &mut charmap) },
            FT_ERR_INVALID_FACE_HANDLE
        );

        let mut face: FtFace = unsafe { core::mem::zeroed() };
        face.num_charmaps = 2;
        assert_eq!(
            unsafe { ft_set_charmap(&mut face, &mut charmap) },
            FT_ERR_INVALID_CHARMAP_HANDLE
        );
        assert!(face.charmap.is_null());
    }

    #[test]
    fn set_charmap_reports_invalid_argument_when_absent_or_table_empty() {
        let mut first = blank_charmap();
        let mut second = blank_charmap();
        let mut wanted = blank_charmap();
        let table = [&mut first as *mut FtCharMap, &mut second as *mut FtCharMap];

        let mut face: FtFace = unsafe { core::mem::zeroed() };
        face.charmaps = table.as_ptr() as *mut *mut c_void;
        face.num_charmaps = 2;
        assert_eq!(
            unsafe { ft_set_charmap(&mut face, &mut wanted) },
            FT_ERR_INVALID_ARGUMENT
        );
        assert!(face.charmap.is_null());

        // The original's raw-word limit makes a non-positive count an empty scan.
        face.num_charmaps = 0;
        assert_eq!(
            unsafe { ft_set_charmap(&mut face, table[0]) },
            FT_ERR_INVALID_ARGUMENT
        );
        face.num_charmaps = -1;
        assert_eq!(
            unsafe { ft_set_charmap(&mut face, table[0]) },
            FT_ERR_INVALID_ARGUMENT
        );
    }

    #[test]
    fn set_charmap_installs_the_first_matching_table_entry() {
        let mut first = blank_charmap();
        let mut second = blank_charmap();
        let table = [&mut first as *mut FtCharMap, &mut second as *mut FtCharMap];

        let mut face: FtFace = unsafe { core::mem::zeroed() };
        face.charmaps = table.as_ptr() as *mut *mut c_void;
        face.num_charmaps = 2;

        assert_eq!(unsafe { ft_set_charmap(&mut face, table[1]) }, FT_ERR_OK);
        assert_eq!(face.charmap, table[1]);

        assert_eq!(unsafe { ft_set_charmap(&mut face, table[0]) }, FT_ERR_OK);
        assert_eq!(face.charmap, table[0]);
    }
}
