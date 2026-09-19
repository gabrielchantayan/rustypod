//! Find an eligible entry in a matchable entry list.
//!
//! - `entry_match_find_eligible` — original: `FUN_08050708` @ 0x08050708
//!   (144 bytes; 4 direct `bl` call sites, 0 predicated BL).

use crate::app::entry_match_first::entry_match_first;
use crate::app::entry_match_successor::entry_match_successor;

const ENTRY_KEY_OFFSET: usize = 8;
const ENTRY_STATE_OFFSET: usize = 12;

/// `entry_match_find_eligible` — original: `FUN_08050708` @ 0x08050708 (144 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x08050708..0x08050798`; the next separately linked function begins with
/// `push {r4-r11,lr}` at `0x08050798`, confirming the 144-byte extent.
///
/// Algorithm: start at the match-list head, then follow each validated entry's
/// successor. Return the first entry whose word at +0x08 equals `key` and whose
/// signed state word at +0x0c is either zero or minus one; return zero when the
/// list is exhausted. The raw setup makes r3 permanently one, so its apparent
/// fallback-candidate block is unreachable and deliberately omitted.
///
/// Call sites: four unconditional `bl` (0x08106e54, 0x08106ed0, 0x0813e820,
/// 0x0813e89c), zero predicated BL, verified by decoding every B/BL-immediate
/// word in `osos.dec`. Deliberate deviations: direct calls to the ported
/// `entry_match_first` and `entry_match_successor` replace retailOS branches;
/// aligned target-width word loads and the reachable control flow are unchanged.
///
/// # Safety
///
/// `container` may be NULL. A non-NULL container and every reachable entry
/// must meet the safety requirements of the selector helpers. Each returned
/// entry pointer is a target-width address and must be four-byte aligned and
/// readable through +0x0f.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.entry_match_find_eligible")]
pub unsafe extern "C" fn entry_match_find_eligible(container: *const u8, key: u32) -> u32 {
    let mut entry = unsafe { entry_match_first(container) };
    while entry != 0 {
        let entry_ptr = entry as usize as *const u8;
        if unsafe { entry_ptr.add(ENTRY_KEY_OFFSET).cast::<u32>().read() } == key {
            let state = unsafe { entry_ptr.add(ENTRY_STATE_OFFSET).cast::<i32>().read() };
            if state == 0 || state == -1 {
                return entry;
            }
        }
        entry = unsafe { entry_match_successor(entry_ptr) };
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const CONTAINER_OFFSET: usize = 0x100;
    const NESTED_OFFSET: usize = 0x200;
    const TARGET_OFFSET: usize = 0x280;
    const FIRST_ENTRY_OFFSET: usize = 0x300;
    const SECOND_ENTRY_OFFSET: usize = 0x340;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;

    static ENTRY_MATCH_FIND_ELIGIBLE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ENTRY_MATCH_FIND_ELIGIBLE_FIXTURE: std::sync::LazyLock<Option<usize>> =
        std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ENTRY_MATCH_FIND_ELIGIBLE,
                FIXTURE_LEN,
            )
            .map(|pointer| pointer as usize)
        });

    fn mapped_objects() -> Option<(*mut u32, *mut u32, *mut u32, *mut u32, *mut u32)> {
        let base = (*ENTRY_MATCH_FIND_ELIGIBLE_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.add(CONTAINER_OFFSET).cast(),
                base.add(NESTED_OFFSET).cast(),
                base.add(TARGET_OFFSET).cast(),
                base.add(FIRST_ENTRY_OFFSET).cast(),
                base.add(SECOND_ENTRY_OFFSET).cast(),
            ))
        }
    }

    macro_rules! locked_fixture {
        () => {
            match mapped_objects() {
                Some(objects) => (
                    ENTRY_MATCH_FIND_ELIGIBLE_TEST_LOCK
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                    objects,
                ),
                None => {
                    assert!(crate::testing::note_missing_u32_fixture("app::entry_match_find_eligible"));
                    return;
                }
            }
        };
    }

    unsafe fn initialize_list(container: *mut u32, nested: *mut u32, target: *mut u32, first: *mut u32, second: *mut u32) {
        unsafe {
            target.write(LITI_CLASS_TAG);
            nested.add(2).write(target as usize as u32);
            container.add(2).write(target as usize as u32);
            container.add(9).write(first as usize as u32);
            first.add(1).write(nested as usize as u32);
            first.add(2).write(0x11);
            first.add(3).write(1);
            first.write(second as usize as u32);
            second.add(1).write(nested as usize as u32);
            second.add(2).write(0x22);
            second.add(3).write(0);
        }
    }

    #[test]
    fn null_container_returns_zero() {
        assert_eq!(unsafe { entry_match_find_eligible(core::ptr::null(), 0x11) }, 0);
    }

    #[test]
    fn skips_ineligible_match_and_returns_later_zero_state_match() {
        let (_guard, (container, nested, target, first, second)) = locked_fixture!();
        unsafe {
            initialize_list(container, nested, target, first, second);
            assert_eq!(entry_match_find_eligible(container.cast(), 0x11), 0);
            assert_eq!(entry_match_find_eligible(container.cast(), 0x22), second as usize as u32);
        }
    }

    #[test]
    fn accepts_minus_one_and_zero_state_matches() {
        let (_guard, (container, nested, target, first, second)) = locked_fixture!();
        unsafe {
            initialize_list(container, nested, target, first, second);
            first.add(3).write(u32::MAX);
            assert_eq!(entry_match_find_eligible(container.cast(), 0x11), first as usize as u32);
            first.add(3).write(0);
            assert_eq!(entry_match_find_eligible(container.cast(), 0x11), first as usize as u32);
        }
    }

    #[test]
    fn does_not_return_different_key_or_non_sentinel_state() {
        let (_guard, (container, nested, target, first, second)) = locked_fixture!();
        unsafe {
            initialize_list(container, nested, target, first, second);
            second.add(3).write(2);
            assert_eq!(entry_match_find_eligible(container.cast(), 0x33), 0);
            assert_eq!(entry_match_find_eligible(container.cast(), 0x22), 0);
        }
    }
}
