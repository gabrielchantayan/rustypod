//! Matchable-entry nested `'liti'` container predicate.
//!
//! - `entry_nested_liti_class_check` — original: `FUN_08057c04` @
//!   `0x08057c04` (40 bytes; 3 direct plain `bl` call sites, 0 predicated BL).

use crate::app::nested_liti_class_check::nested_liti_class_check;

/// Byte offset of the matchable entry's nested container pointer.
const NESTED_CONTAINER_OFFSET: usize = 4;

/// `entry_nested_liti_class_check` — original: `FUN_08057c04` @ `0x08057c04`
/// (40 bytes).
///
/// Raw ARM extent is exactly `0x08057c04..0x08057c2c`: the distinct next
/// function begins with `cmp r0, #0` at `0x08057c2c`. Decoding every ARM B/BL
/// word in `osos.dec` finds three inbound unconditional plain `bl` calls
/// (0x08049050, 0x080523cc, 0x08053bc0), zero predicated BL forms, and one
/// predicated `bne` tail caller at 0x08053b0c. The body has one unconditional
/// plain `bl` to `nested_liti_class_check` and no predicated BL.
///
/// ```text
/// 08057c04  cmp r0, #0
/// 08057c08  str lr, [sp, #-4]!
/// 08057c0c  beq 08057c24
/// 08057c10  ldr r0, [r0, #4]
/// 08057c14  bl  08057bdc       ; nested_liti_class_check
/// 08057c18  cmp r0, #0
/// 08057c1c  movne r0, #1
/// 08057c20  ldrne pc, [sp], #4
/// 08057c24  mov r0, #0
/// 08057c28  ldr pc, [sp], #4
/// ```
///
/// Algorithm: return 0 for a NULL entry; otherwise load its aligned
/// target-width word at +0x04, pass that pointer to the nested `'liti'` class
/// predicate, and canonicalize a nonzero result to 1. Deliberate deviation:
/// the direct Rust call replaces the retail direct `bl` with the canonical
/// ported callee. LLVM proves that callee already returns canonical booleans,
/// so it lowers this to a tail branch; the exported wrapper remains a distinct
/// hookable symbol, with the same field load and zero-on-rejection behavior.
///
/// # Safety
///
/// `entry` may be NULL. When non-NULL, it must be four-byte aligned and
/// readable through +0x07. Its +0x04 word may be NULL; otherwise it must meet
/// [`nested_liti_class_check`]'s safety requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.entry_nested_liti_class_check")]
pub unsafe extern "C" fn entry_nested_liti_class_check(entry: *const u8) -> u32 {
    if entry.is_null() {
        return 0;
    }

    let nested_container = unsafe { entry.add(NESTED_CONTAINER_OFFSET).cast::<u32>().read() } as usize
        as *const u8;
    if unsafe { nested_liti_class_check(nested_container) } != 0 {
        1
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

    static ENTRY_NESTED_LITI_CLASS_CHECK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ENTRY_NESTED_LITI_CLASS_CHECK_FIXTURE: std::sync::LazyLock<Option<usize>> =
        std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ENTRY_NESTED_LITI_CLASS_CHECK,
                FIXTURE_LEN,
            )
            .map(|pointer| pointer as usize)
        });

    fn mapped_objects() -> Option<(*mut u32, *mut u32, *mut u32)> {
        let base = (*ENTRY_NESTED_LITI_CLASS_CHECK_FIXTURE)? as *mut u8;
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
        () => {{
            let guard = ENTRY_NESTED_LITI_CLASS_CHECK_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(objects) = mapped_objects() else {
                assert!(crate::testing::note_missing_u32_fixture("app::entry_nested_liti_class_check"));
                return;
            };
            (guard, objects)
        }};
    }

    #[test]
    fn null_entry_returns_zero() {
        assert_eq!(unsafe { entry_nested_liti_class_check(core::ptr::null()) }, 0);
    }

    #[test]
    fn liti_nested_container_returns_one() {
        let (_guard, (entry, container, target)) = locked_fixture!();
        unsafe {
            target.write(LITI_CLASS_TAG);
            container.add(2).write(target as usize as u32);
            entry.add(1).write(container as usize as u32);
            assert_eq!(entry_nested_liti_class_check(entry.cast()), 1);
        }
    }

    #[test]
    fn null_nested_container_returns_zero() {
        let (_guard, (entry, _container, _target)) = locked_fixture!();
        unsafe {
            assert_eq!(entry_nested_liti_class_check(entry.cast()), 0);
        }
    }

    #[test]
    fn wrong_nested_class_returns_zero() {
        let (_guard, (entry, container, target)) = locked_fixture!();
        unsafe {
            target.write(0x706c_7374); // 'plst'
            container.add(2).write(target as usize as u32);
            entry.add(1).write(container as usize as u32);
            assert_eq!(entry_nested_liti_class_check(entry.cast()), 0);
        }
    }

    #[test]
    fn only_word_at_offset_four_is_read() {
        let (_guard, (entry, container, target)) = locked_fixture!();
        unsafe {
            entry.write(0);
            target.write(LITI_CLASS_TAG);
            container.add(2).write(target as usize as u32);
            entry.add(1).write(container as usize as u32);
            entry.add(2).write(0);
            assert_eq!(entry_nested_liti_class_check(entry.cast()), 1);
        }
    }
}
