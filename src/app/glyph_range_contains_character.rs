//! `glyph_range_contains_character` — original: `FUN_08297e84` @ `0x08297e84`
//! (172 bytes, `0x08297e84..0x08297f30`; two plain `bl`, zero predicated
//! `bl`, and one indirect `blx` call).
//!
//! # Algorithm
//!
//! Locks the owner's counted mutex at `+0x18`, searches its indexed glyph
//! ranges and optional trailing range for `character`, then returns whether
//! the matching range's u16 glyph entry is not the `0xffff` missing-glyph
//! marker. It releases the mutex on both return paths.
//!
//! # Deliberate deviations
//!
//! The target's vector callback at vtable offset `+0x40` and its optional
//! trailing range are target-width pointers. Host builds use an operation
//! seam for those two pointer-producing operations while preserving the
//! lock, lookup order, inclusive bounds, and missing-glyph test.

#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted, CountedMutex};

const MISSING_GLYPH: u16 = u16::MAX;
const RANGE_VECTOR_AT_OFFSET: usize = 0x40;

#[repr(C)]
pub struct GlyphRange {
    pub first_character: u16,
    pub last_character: u16,
    pub glyph_indices: *const u16,
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct GlyphRangeContainsCharacterOps {
    pub lock: unsafe extern "C" fn(*mut u32),
    pub range_at: unsafe extern "C" fn(*mut u32, u32) -> *const *const GlyphRange,
    pub trailing_range: unsafe extern "C" fn(*mut u32) -> *const GlyphRange,
    pub unlock: unsafe extern "C" fn(*mut u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lock(_owner: *mut u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_range_at(_owner: *mut u32, _index: u32) -> *const *const GlyphRange {
    core::ptr::null()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_trailing_range(_owner: *mut u32) -> *const GlyphRange {
    core::ptr::null()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_unlock(_owner: *mut u32) {}

#[cfg(not(target_os = "none"))]
pub static mut GLYPH_RANGE_CONTAINS_CHARACTER_OPS: GlyphRangeContainsCharacterOps = GlyphRangeContainsCharacterOps {
    lock: missing_lock,
    range_at: missing_range_at,
    trailing_range: missing_trailing_range,
    unlock: missing_unlock,
};

unsafe fn range_contains_character(range: *const GlyphRange, character: u32) -> bool {
    let first = (*range).first_character as u32;
    if character < first || character > (*range).last_character as u32 {
        return false;
    }
    (*range).glyph_indices.add((character - first) as usize).read() != MISSING_GLYPH
}

#[cfg(target_os = "none")]
unsafe fn glyph_range_contains_character_target(owner: *mut u32, character: u32) -> bool {
    mutex_lock_counted(owner.add(6).cast::<CountedMutex>());
    let range_count = owner.add(2).read();
    let mut index = 0;
    while index <= range_count {
        let range = if index < range_count {
            let vector = owner.add(1);
            let vtable = vector.read() as usize as *const u32;
            let range_at: unsafe extern "C" fn(*mut u32, u32) -> *const *const GlyphRange =
                core::mem::transmute(vtable.add(RANGE_VECTOR_AT_OFFSET / 4).read() as usize);
            range_at(vector, index).read()
        } else {
            owner.add(5).read() as usize as *const GlyphRange
        };
        if range.is_null() {
            break;
        }
        if range_contains_character(range, character) {
            mutex_unlock_counted(owner.add(6).cast::<CountedMutex>());
            return true;
        }
        index = index.wrapping_add(1);
    }
    mutex_unlock_counted(owner.add(6).cast::<CountedMutex>());
    false
}

/// Looks up `character` in the owner's indexed and trailing glyph ranges.
///
/// `owner` uses retailOS's target-width word layout: word 1 is the indexed
/// range vector, word 2 its count, word 5 the optional trailing range, and
/// word 6 begins the [`CountedMutex`]. The index callback returns a pointer
/// to a range pointer; the selected range's first two halfwords bound the
/// character and its word at `+4` points to the glyph-index table.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn glyph_range_contains_character(owner: *mut u32, character: u32) -> bool {
    #[cfg(target_os = "none")]
    { glyph_range_contains_character_target(owner, character) }

    #[cfg(not(target_os = "none"))]
    {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(GLYPH_RANGE_CONTAINS_CHARACTER_OPS));
        (ops.lock)(owner);
        let range_count = owner.add(2).read();
        let mut index = 0;
        while index <= range_count {
            let range = if index < range_count {
                (ops.range_at)(owner.add(1), index).read()
            } else {
                (ops.trailing_range)(owner)
            };
            if range.is_null() {
                break;
            }
            if range_contains_character(range, character) {
                (ops.unlock)(owner);
                return true;
            }
            index = index.wrapping_add(1);
        }
        (ops.unlock)(owner);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RANGES: [*const GlyphRange; 2] = [core::ptr::null(); 2];
    static mut EVENTS: [u32; 8] = [0; 8];
    static mut EVENT_LEN: usize = 0;

    unsafe extern "C" fn lock(_owner: *mut u32) { EVENTS[EVENT_LEN] = 1; EVENT_LEN += 1; }
    unsafe extern "C" fn range_at(_vector: *mut u32, index: u32) -> *const *const GlyphRange {
        EVENTS[EVENT_LEN] = 10 + index;
        EVENT_LEN += 1;
        RANGES.as_ptr().add(index as usize)
    }
    unsafe extern "C" fn trailing_range(_owner: *mut u32) -> *const GlyphRange {
        EVENTS[EVENT_LEN] = 20;
        EVENT_LEN += 1;
        RANGES[1]
    }
    unsafe extern "C" fn unlock(_owner: *mut u32) { EVENTS[EVENT_LEN] = 2; EVENT_LEN += 1; }

    #[test]
    fn searches_inclusive_ranges_then_trailing_range_and_rejects_missing_glyphs() {
        let _guard = TEST_LOCK.lock();
        let first_glyphs = [4u16, MISSING_GLYPH, 9];
        let trailing_glyphs = [MISSING_GLYPH, 7];
        let first = GlyphRange { first_character: 10, last_character: 12, glyph_indices: first_glyphs.as_ptr() };
        let trailing = GlyphRange { first_character: 20, last_character: 21, glyph_indices: trailing_glyphs.as_ptr() };
        let mut owner = [0u32; 9];
        owner[2] = 1;
        unsafe {
            GLYPH_RANGE_CONTAINS_CHARACTER_OPS = GlyphRangeContainsCharacterOps { lock, range_at, trailing_range, unlock };
            RANGES = [&first, &trailing];
            EVENTS = [0; 8]; EVENT_LEN = 0;
            assert!(glyph_range_contains_character(owner.as_mut_ptr(), 10));
            assert_eq!(&EVENTS[..EVENT_LEN], &[1, 10, 2]);
            EVENTS = [0; 8]; EVENT_LEN = 0;
            assert!(!glyph_range_contains_character(owner.as_mut_ptr(), 11));
            assert_eq!(&EVENTS[..EVENT_LEN], &[1, 10, 20, 2]);
            EVENTS = [0; 8]; EVENT_LEN = 0;
            assert!(glyph_range_contains_character(owner.as_mut_ptr(), 21));
            assert_eq!(&EVENTS[..EVENT_LEN], &[1, 10, 20, 2]);
        }
    }

    #[test]
    fn unlocks_when_no_range_matches_or_trailing_range_is_absent() {
        let _guard = TEST_LOCK.lock();
        let glyphs = [1u16];
        let range = GlyphRange { first_character: 100, last_character: 100, glyph_indices: glyphs.as_ptr() };
        let mut owner = [0u32; 9];
        owner[2] = 1;
        unsafe {
            GLYPH_RANGE_CONTAINS_CHARACTER_OPS = GlyphRangeContainsCharacterOps { lock, range_at, trailing_range, unlock };
            RANGES = [&range, core::ptr::null()];
            EVENTS = [0; 8]; EVENT_LEN = 0;
            assert!(!glyph_range_contains_character(owner.as_mut_ptr(), 99));
            assert_eq!(&EVENTS[..EVENT_LEN], &[1, 10, 20, 2]);
        }
    }
}
