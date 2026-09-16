//! First entry of a matchable entry list on a `'liti'`-holding container.
//!
//! - `entry_match_first` — original: `FUN_080522bc` @ 0x080522bc
//!   (24 bytes; 5 direct `bl` call sites, 0 predicated BL, plus one
//!   predicated `beq` tail dispatch, verified by decoding every B/BL word
//!   in `osos.dec`).

use crate::app::nested_liti_class_check::nested_liti_class_check;

/// Byte offset of the first-entry word (`ldrne r0,[r2,#0x24]`).
const FIRST_ENTRY_OFFSET: usize = 0x24;

/// entry_match_first — original: `FUN_080522bc` @ 0x080522bc (24 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x080522bc..0x080522d4`; the next function `ui_tdat_first_plst` begins
/// with `mov r2, r0` at `0x080522d4`, confirming Ghidra's 24-byte extent:
///
/// ```text
/// 080522bc  mov r2, r0
/// 080522c0  push {lr}
/// 080522c4  bl 0x08057bdc       ; nested_liti_class_check
/// 080522c8  movs r0, r0
/// 080522cc  ldrne r0, [r2, #0x24]
/// 080522d0  pop {pc}
/// ```
///
/// Algorithm: validate `container` with the ported `nested_liti_class_check`
/// (non-NULL container whose word at +0x08 points at a `'liti'`-tagged
/// ImageLibrary database object), then return the word at `container + 0x24`;
/// return zero for every rejected input. The stored word is the first entry
/// of the container's matchable entry list: `entry_match_next` @ 0x08053b14
/// starts its iteration from this value, steps with the successor selector
/// @ 0x08053bb8, and matches each entry by comparing the word at entry+8;
/// caller 0x08050708 walks the same list for an exact or sentinel-marked
/// entry. The container type beyond its +0x08 nested object and the +0x24
/// list head remains opaque, so the port names only this verified
/// relationship.
///
/// Call sites: 5 unconditional `bl` (0x08046ff8, 0x08050724, 0x08053b2c,
/// 0x0806bff4, 0x081a8d8c), zero predicated BL, and one predicated `beq`
/// tail dispatch from 0x08053b10. Deliberate deviations: none. The aligned
/// word load matches the original `ldr`; the port calls the already-ported
/// nested check directly instead of branching to its retailOS address.
///
/// # Safety
///
/// `container` may be NULL. A non-NULL pointer must be four-byte aligned and
/// readable through +0x0a for the nested class check; if the check passes it
/// must also be readable through +0x27 for the returned word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.entry_match_first")]
pub unsafe extern "C" fn entry_match_first(container: *const u8) -> u32 {
    if nested_liti_class_check(container) != 0 {
        unsafe { container.add(FIRST_ENTRY_OFFSET).cast::<u32>().read() }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const CONTAINER_OFFSET: usize = 0x100;
    const NESTED_OFFSET: usize = 0x200;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;
    const FIRST_ENTRY_WORD: usize = FIRST_ENTRY_OFFSET / core::mem::size_of::<u32>();

    static ENTRY_MATCH_FIRST_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ENTRY_MATCH_FIRST_FIXTURE: std::sync::LazyLock<Option<usize>> =
        std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ENTRY_MATCH_FIRST,
                FIXTURE_LEN,
            )
            .map(|pointer| pointer as usize)
        });

    /// Zeroed slab holding the container at +0x100 (nested-object pointer in
    /// word 2, first-entry word in word 9) and the nested object at +0x200.
    fn mapped_objects() -> Option<(*mut u32, *mut u32)> {
        let base = (*ENTRY_MATCH_FIRST_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.add(CONTAINER_OFFSET).cast::<u32>(),
                base.add(NESTED_OFFSET).cast::<u32>(),
            ))
        }
    }

    macro_rules! locked_fixture {
        () => {
            match mapped_objects() {
                Some(objects) => (
                    ENTRY_MATCH_FIRST_TEST_LOCK
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                    objects,
                ),
                None => {
                    assert!(crate::testing::note_missing_u32_fixture("app::entry_match_first"));
                    return;
                }
            }
        };
    }

    #[test]
    fn null_container_returns_zero() {
        assert_eq!(unsafe { entry_match_first(core::ptr::null()) }, 0);
    }

    #[test]
    fn liti_container_returns_its_first_entry_word() {
        let (_guard, (container, nested)) = locked_fixture!();
        unsafe {
            nested.write(LITI_CLASS_TAG);
            container.add(2).write(nested as usize as u32);
            for first_entry in [0, 0x0804_7bfc, 0x2200_aed8, u32::MAX] {
                container.add(FIRST_ENTRY_WORD).write(first_entry);
                assert_eq!(entry_match_first(container.cast()), first_entry);
            }
        }
    }

    #[test]
    fn wrong_nested_class_tag_returns_zero_even_with_entry_word() {
        let (_guard, (container, nested)) = locked_fixture!();
        unsafe {
            nested.write(0x706c_7374); // 'plst'
            container.add(2).write(nested as usize as u32);
            container.add(FIRST_ENTRY_WORD).write(0x0804_7bfc);
            assert_eq!(entry_match_first(container.cast()), 0);
        }
    }

    #[test]
    fn null_nested_object_returns_zero() {
        let (_guard, (container, _nested)) = locked_fixture!();
        unsafe {
            container.add(FIRST_ENTRY_WORD).write(0x0804_7bfc);
            assert_eq!(entry_match_first(container.cast()), 0);
        }
    }

    #[test]
    fn only_word_at_offset_24_is_returned() {
        let (_guard, (container, nested)) = locked_fixture!();
        unsafe {
            nested.write(LITI_CLASS_TAG);
            container.add(2).write(nested as usize as u32);
            container.add(FIRST_ENTRY_WORD - 1).write(0xdead_beef);
            container.add(FIRST_ENTRY_WORD).write(0x1020_3040);
            assert_eq!(entry_match_first(container.cast()), 0x1020_3040);
        }
    }
}
