//! Character-class flag lookup used by retailOS text processing.
//!
//! The 24-byte source object has an unrecovered 20-byte prefix and a pointer
//! to a `u16` flag table at +0x14. This leaf only observes that table; nearby
//! case-folding callers establish that the table classifies character values.

/// A 32-bit retailOS character-class object.
///
/// The prefix is not read by [`character_class_matches_mask`]. The table
/// pointer remains a target-width word so the target's +0x14 layout also
/// holds in 64-bit host tests.
#[repr(C)]
pub struct CharacterClass {
    pub unrecovered_prefix: [u32; 5],
    pub flags: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(CharacterClass, unrecovered_prefix)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(CharacterClass, flags)];
const _: [u8; 0x18] = [0; core::mem::size_of::<CharacterClass>()];

/// character_class_matches_mask — original: `FUN_082a7258` @ `0x082a7258`
/// (24 bytes; 26 direct `bl` call sites, all unconditional plain `bl`; no
/// predicated `bl` or plain-`b` tail sites, binary-scanned from `osos.dec`).
///
/// Loads `class.flags[character]` as an aligned little-endian `u16`, masks it
/// with `mask`, and returns a normalized 0-or-1 result. The ARM body has no
/// NULL or bounds check for either pointer or character index. No deviations.
///
/// # Safety
///
/// `class` must point to an aligned readable [`CharacterClass`], and its
/// target-width `flags` word must name an aligned readable `u16` table with an
/// element at `character`. This intentionally preserves the original's lack
/// of NULL and bounds guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn character_class_matches_mask(
    class: *const CharacterClass,
    mask: u16,
    character: u32,
) -> u32 {
    let flags = (*class).flags as usize as *const u16;
    ((*flags.add(character as usize) & mask) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::LazyLock;

    const FLAG_COUNT: usize = 0x200;
    const CLASS_OFFSET: usize = 0x1000;

    /// Maps this module's target-width-pointer fixture once: the mapper never
    /// unmaps, so retrying the same hint in independent tests would silently
    /// skip after the first mapping.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::CHARACTER_CLASS,
                0x2000,
            )
            .map(|pointer| pointer as usize)
        });
        SLAB.map(|pointer| pointer as *mut u8)
    }

    /// Reinitializes an in-place character table and object in the shared slab.
    unsafe fn fixture() -> Option<(*mut u16, *mut CharacterClass)> {
        let slab = try_slab()?;
        let flags = slab as *mut u16;
        for index in 0..FLAG_COUNT {
            flags.add(index).write(0);
        }
        let class = slab.add(CLASS_OFFSET) as *mut CharacterClass;
        class.write(CharacterClass {
            unrecovered_prefix: [0; 5],
            flags: slab as u32,
        });
        Some((flags, class))
    }

    #[test]
    fn character_flag_masks_normalize_and_index_u16_table() {
        let Some((flags, class)) = (unsafe { fixture() }) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/character_class"));
            return;
        };
        unsafe {
            flags.add(0).write(0b1000);
            flags.add(FLAG_COUNT - 1).write(0b0101);
            let original_pointer = (*class).flags;

            assert_eq!(character_class_matches_mask(class, 0, 0), 0);
            assert_eq!(character_class_matches_mask(class, 0b0100, 0), 0);
            assert_eq!(character_class_matches_mask(class, 0b1000, 0), 1);
            assert_eq!(character_class_matches_mask(class, 0b0010, FLAG_COUNT as u32 - 1), 0);
            assert_eq!(character_class_matches_mask(class, 0b0100, FLAG_COUNT as u32 - 1), 1);
            assert_eq!((*class).flags, original_pointer);
            assert_eq!(flags.add(0).read(), 0b1000);
            assert_eq!(flags.add(FLAG_COUNT - 1).read(), 0b0101);
        }
    }
}
