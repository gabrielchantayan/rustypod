//! Finds a matchable entry by key after an optional predecessor.
//!
//! - `entry_match_next` — original: `FUN_08053b14` @ `0x08053b14`
//!   (72 bytes; 4 direct `bl` call sites, 0 predicated BL).

use crate::app::entry_match_first::entry_match_first;
use crate::app::entry_match_successor::entry_match_successor;

/// Byte offset of an entry's match key.
const MATCH_KEY_OFFSET: usize = 8;

/// `entry_match_next` — original: `FUN_08053b14` @ `0x08053b14` (72 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @ `0x08053b14..0x08053b5c`:
/// the following `push {r4, r5, r6, lr}` at `0x08053b5c` starts the next real
/// function, confirming the 72-byte extent.
///
/// ```text
/// 08053b14  push {r4, lr}
/// 08053b18  cmp r0, #0
/// 08053b1c  mov r4, r2
/// 08053b20  popeq {pc}
/// 08053b24  cmp r1, #0
/// 08053b28  bne 0x08053b44
/// 08053b2c  bl  0x080522bc       ; entry_match_first
/// 08053b30  movs r1, r0
/// 08053b34  beq 0x08053b54
/// 08053b38  ldr r0, [r1, #8]
/// 08053b3c  cmp r0, r4
/// 08053b40  beq 0x08053b54
/// 08053b44  mov r0, r1
/// 08053b48  bl  0x08053bb8       ; entry_match_successor
/// 08053b4c  movs r1, r0
/// 08053b50  bne 0x08053b38
/// 08053b54  mov r0, r1
/// 08053b58  pop {r4, pc}
/// ```
///
/// Algorithm: when `previous` is NULL, begin with the validated list head
/// from `container`; otherwise begin with `previous`'s validated successor.
/// Compare each candidate's word at +0x08 against `match_key`, advancing with
/// the successor selector until a match or a NULL list end. A NULL `container`
/// returns NULL before either helper is called.
///
/// Call sites: four unconditional plain `bl` (0x0826f924, 0x0826f9d0,
/// 0x0826fae4, 0x0826fb90), zero predicated BL, verified by decoding every
/// ARM B/BL-immediate word in `osos.dec`. Deliberate deviations: calls the
/// already-ported first-entry and successor helpers directly rather than their
/// retailOS addresses; their validation and target-width aligned word reads
/// preserve the original behavior.
///
/// # Safety
///
/// `container` may be NULL. If it is non-NULL, it must satisfy
/// [`entry_match_first`]'s safety requirements. Every non-NULL candidate must
/// satisfy [`entry_match_successor`]'s requirements and be readable through
/// +0x0b.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.entry_match_next")]
pub unsafe extern "C" fn entry_match_next(
    container: *const u8,
    previous: *mut u8,
    match_key: u32,
) -> *mut u8 {
    if container.is_null() {
        return core::ptr::null_mut();
    }

    let mut entry = if previous.is_null() {
        unsafe { entry_match_first(container) as usize as *mut u8 }
    } else {
        unsafe { entry_match_successor(previous) as usize as *mut u8 }
    };

    while !entry.is_null() {
        if unsafe { entry.add(MATCH_KEY_OFFSET).cast::<u32>().read() } == match_key {
            return entry;
        }
        entry = unsafe { entry_match_successor(entry) as usize as *mut u8 };
    }

    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const CONTAINER_OFFSET: usize = 0x100;
    const NESTED_OFFSET: usize = 0x200;
    const FIRST_ENTRY_OFFSET: usize = 0x300;
    const SECOND_ENTRY_OFFSET: usize = 0x340;
    const THIRD_ENTRY_OFFSET: usize = 0x380;
    const ENTRY_NESTED_OFFSET: usize = 0x400;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;

    static ENTRY_MATCH_NEXT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ENTRY_MATCH_NEXT_FIXTURE: std::sync::LazyLock<Option<usize>> =
        std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::ENTRY_MATCH_NEXT, FIXTURE_LEN)
                .map(|pointer| pointer as usize)
        });

    fn mapped_objects() -> Option<(*mut u32, *mut u32, [*mut u32; 3], *mut u32)> {
        let base = (*ENTRY_MATCH_NEXT_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.add(CONTAINER_OFFSET).cast::<u32>(),
                base.add(NESTED_OFFSET).cast::<u32>(),
                [
                    base.add(FIRST_ENTRY_OFFSET).cast::<u32>(),
                    base.add(SECOND_ENTRY_OFFSET).cast::<u32>(),
                    base.add(THIRD_ENTRY_OFFSET).cast::<u32>(),
                ],
                base.add(ENTRY_NESTED_OFFSET).cast::<u32>(),
            ))
        }
    }

    fn initialized_list() -> Option<(*mut u32, [*mut u32; 3])> {
        let (container, nested, entries, entry_nested) = mapped_objects()?;
        unsafe {
            nested.write(LITI_CLASS_TAG);
            container.add(2).write(nested as usize as u32);
            container.add(9).write(entries[0] as usize as u32);
            entry_nested.write(LITI_CLASS_TAG);
            for entry in entries {
                entry.add(1).write(container as usize as u32);
            }
            entries[0].write(entries[1] as usize as u32);
            entries[1].write(entries[2] as usize as u32);
        }
        Some((container, entries))
    }

    macro_rules! locked_fixture {
        () => {{
            let guard = ENTRY_MATCH_NEXT_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match initialized_list() {
                Some(objects) => (guard, objects),
                None => {
                    assert!(crate::testing::note_missing_u32_fixture("app::entry_match_next"));
                    return;
                }
            }
        }};
    }

    #[test]
    fn null_container_returns_null_without_reading_previous() {
        assert!(unsafe { entry_match_next(core::ptr::null(), 1usize as *mut u8, 1) }.is_null());
    }

    #[test]
    fn starts_at_first_entry_and_finds_each_key() {
        let (_guard, (container, entries)) = locked_fixture!();
        unsafe {
            entries[0].add(2).write(0x10);
            entries[1].add(2).write(0x20);
            entries[2].add(2).write(0x30);
            for (key, expected) in [(0x10, entries[0]), (0x20, entries[1]), (0x30, entries[2])] {
                assert_eq!(entry_match_next(container.cast(), core::ptr::null_mut(), key), expected.cast());
            }
        }
    }

    #[test]
    fn starts_after_previous_entry() {
        let (_guard, (container, entries)) = locked_fixture!();
        unsafe {
            entries[0].add(2).write(0x20);
            entries[1].add(2).write(0x20);
            assert_eq!(entry_match_next(container.cast(), entries[0].cast(), 0x20), entries[1].cast());
        }
    }

    #[test]
    fn returns_null_for_missing_key_and_invalid_list_head() {
        let (_guard, (container, entries)) = locked_fixture!();
        unsafe {
            entries[0].add(2).write(0x10);
            assert!(entry_match_next(container.cast(), core::ptr::null_mut(), 0x99).is_null());
            container.add(2).write(0);
            assert!(entry_match_next(container.cast(), core::ptr::null_mut(), 0x10).is_null());
        }
    }
}
