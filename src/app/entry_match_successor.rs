//! Successor selector for a matchable entry list.
//!
//! - `entry_match_successor` — original: `FUN_08053bb8` @ `0x08053bb8`
//!   (24 bytes; 4 direct `bl` call sites, 0 predicated BL).

use crate::app::nested_liti_class_check::nested_liti_class_check;

/// Byte offset of the entry's nested `'liti'` container pointer.
const NESTED_CONTAINER_OFFSET: usize = 4;

/// `entry_match_successor` — original: `FUN_08053bb8` @ `0x08053bb8` (24 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x08053bb8..0x08053bd0`; the separately linked next function begins with
/// `push {r4, lr}` at `0x08053bd0`, confirming the extent:
///
/// ```text
/// 08053bb8  mov r2, r0
/// 08053bbc  push {lr}
/// 08053bc0  bl  0x08057c04       ; entry_nested_liti_class_check
/// 08053bc4  movs r0, r0
/// 08053bc8  ldrne r0, [r2]
/// 08053bcc  pop {pc}
/// ```
///
/// Algorithm: validate the entry's nested `'liti'` container at +0x04, then
/// return the entry's word at +0x00, its successor in the matchable-entry
/// list; return zero for a NULL entry or a rejected nested container. The
/// callee is the 16-byte wrapper at 0x08057c04, whose raw code loads the word
/// at +0x04 and calls [`nested_liti_class_check`].
///
/// Call sites: four unconditional plain `bl` (0x0804700c, 0x08050784,
/// 0x08053b48, 0x0806c000), zero predicated BL; one predicated `bne` tail
/// caller at 0x08053b0c is not a BL. Deliberate deviations: the retail
/// wrapper at 0x08057c04 is inlined because it has no ported seam; this port
/// directly calls its already-ported nested check. Aligned target-width word
/// loads match the original `ldr` instructions.
///
/// # Safety
///
/// `entry` may be NULL. When non-NULL, it must be four-byte aligned and
/// readable through +0x07. Its word at +0x04 may be NULL; otherwise it must
/// satisfy [`nested_liti_class_check`]'s safety requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.entry_match_successor")]
pub unsafe extern "C" fn entry_match_successor(entry: *const u8) -> u32 {
    if entry.is_null() {
        return 0;
    }

    let nested_container = unsafe { entry.add(NESTED_CONTAINER_OFFSET).cast::<u32>().read() } as usize
        as *const u8;
    if unsafe { nested_liti_class_check(nested_container) } != 0 {
        unsafe { entry.cast::<u32>().read() }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const ENTRY_OFFSET: usize = 0x100;
    const CONTAINER_OFFSET: usize = 0x200;
    const TARGET_OFFSET: usize = 0x300;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;

    static ENTRY_MATCH_SUCCESSOR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ENTRY_MATCH_SUCCESSOR_FIXTURE: std::sync::LazyLock<Option<usize>> =
        std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ENTRY_MATCH_SUCCESSOR,
                FIXTURE_LEN,
            )
            .map(|pointer| pointer as usize)
        });

    fn mapped_objects() -> Option<(*mut u32, *mut u32, *mut u32)> {
        let base = (*ENTRY_MATCH_SUCCESSOR_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.add(ENTRY_OFFSET).cast::<u32>(),
                base.add(CONTAINER_OFFSET).cast::<u32>(),
                base.add(TARGET_OFFSET).cast::<u32>(),
            ))
        }
    }

    macro_rules! locked_fixture {
        () => {
            match mapped_objects() {
                Some(objects) => (
                    ENTRY_MATCH_SUCCESSOR_TEST_LOCK
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                    objects,
                ),
                None => {
                    assert!(crate::testing::note_missing_u32_fixture("app::entry_match_successor"));
                    return;
                }
            }
        };
    }

    #[test]
    fn null_entry_returns_zero() {
        assert_eq!(unsafe { entry_match_successor(core::ptr::null()) }, 0);
    }

    #[test]
    fn liti_entry_returns_each_successor_word() {
        let (_guard, (entry, container, target)) = locked_fixture!();
        unsafe {
            target.write(LITI_CLASS_TAG);
            container.add(2).write(target as usize as u32);
            entry.add(1).write(container as usize as u32);
            for successor in [0, 0x0804_7bfc, 0x2200_aed8, u32::MAX] {
                entry.write(successor);
                assert_eq!(entry_match_successor(entry.cast()), successor);
            }
        }
    }

    #[test]
    fn null_nested_container_returns_zero() {
        let (_guard, (entry, _container, _target)) = locked_fixture!();
        unsafe {
            entry.write(0x0804_7bfc);
            assert_eq!(entry_match_successor(entry.cast()), 0);
        }
    }

    #[test]
    fn wrong_nested_class_returns_zero_even_with_successor() {
        let (_guard, (entry, container, target)) = locked_fixture!();
        unsafe {
            target.write(0x706c_7374); // 'plst'
            container.add(2).write(target as usize as u32);
            entry.add(1).write(container as usize as u32);
            entry.write(0x0804_7bfc);
            assert_eq!(entry_match_successor(entry.cast()), 0);
        }
    }

    #[test]
    fn only_word_zero_is_returned_after_validation() {
        let (_guard, (entry, container, target)) = locked_fixture!();
        unsafe {
            target.write(LITI_CLASS_TAG);
            container.add(2).write(target as usize as u32);
            entry.add(1).write(container as usize as u32);
            entry.write(0x1020_3040);
            assert_eq!(entry_match_successor(entry.cast()), 0x1020_3040);
        }
    }
}
