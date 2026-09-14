//! The nested `'liti'` ImageLibrary-database class check.
//!
//! - `nested_liti_class_check` — original: `FUN_08057bdc` @ `0x08057bdc`
//!   (40 bytes; 6 direct `bl` call sites, 0 predicated).

use crate::app::liti_class_check::image_library_is_liti_class;

/// `nested_liti_class_check` — original: `FUN_08057bdc` @ `0x08057bdc`
/// (40 bytes).
///
/// Raw ARM extent is exactly `0x08057bdc..0x08057c04`: the next separately
/// linked function starts with `cmp r0, #0` at `0x08057c04`. Decoding every
/// ARM B/BL word in `osos.dec` finds six inbound direct calls, all
/// unconditional plain `bl`; there are no predicated BL forms or plain-B tail
/// callers.
///
/// ```text
/// 08057bdc  cmp r0, #0
/// 08057be0  str lr, [sp, #-4]!
/// 08057be4  beq 08057bfc
/// 08057be8  ldr r0, [r0, #8]
/// 08057bec  bl  08057c2c  ; image_library_is_liti_class
/// 08057bf0  cmp r0, #0
/// 08057bf4  movne r0, #1
/// 08057bf8  ldrne pc, [sp], #4
/// 08057bfc  mov r0, #0
/// 08057c00  ldr pc, [sp], #4
/// ```
///
/// Algorithm: return 0 for a NULL `container`; otherwise load its target-width
/// word at +0x08 and pass that pointer to the NULL-guarded `'liti'` class-tag
/// predicate. A nonzero predicate result is canonicalized to 1. The enclosing
/// object type is otherwise unknown, so its verified field is addressed as
/// word index 2 rather than assigned an unsupported structural type.
///
/// Deliberate deviations: none. The original uses an aligned `ldr` at +0x08;
/// this port uses the same aligned target-width word load. Its Rust direct call
/// replaces the retail direct `bl` with a direct call to the canonical port.
///
/// # Safety
///
/// `container` may be NULL. When non-NULL, it must be four-byte aligned and
/// readable through word index 2; a nonzero field must be a valid target-width
/// pointer readable by [`image_library_is_liti_class`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.nested_liti_class_check")]
pub unsafe extern "C" fn nested_liti_class_check(container: *const u8) -> u32 {
    if container.is_null() {
        return 0;
    }

    let target = unsafe { container.cast::<u32>().add(2).read() } as usize as *const u8;
    u32::from(unsafe { image_library_is_liti_class(target) } != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const CONTAINER_OFFSET: usize = 0x100;
    const TARGET_OFFSET: usize = 0x200;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;

    static NESTED_LITI_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static NESTED_LITI_FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::NESTED_LITI_FIELD_CHECK,
            FIXTURE_LEN,
        )
        .map(|pointer| pointer as usize)
    });

    fn mapped_objects() -> Option<(*mut u32, *mut u32)> {
        let base = (*NESTED_LITI_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.add(CONTAINER_OFFSET).cast::<u32>(),
                base.add(TARGET_OFFSET).cast::<u32>(),
            ))
        }
    }

    #[test]
    fn null_container_returns_zero() {
        assert_eq!(unsafe { nested_liti_class_check(core::ptr::null()) }, 0);
    }

    #[test]
    fn follows_word_two_to_liti_object() {
        let _guard = NESTED_LITI_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((container, target)) = mapped_objects() else {
            assert!(crate::testing::note_missing_u32_fixture("app::nested_liti_class_check"));
            return;
        };

        unsafe {
            target.write(LITI_CLASS_TAG);
            container.add(2).write(target as usize as u32);
            assert_eq!(nested_liti_class_check(container.cast()), 1);
        }
    }

    #[test]
    fn null_word_two_returns_zero() {
        let _guard = NESTED_LITI_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((container, _target)) = mapped_objects() else {
            assert!(crate::testing::note_missing_u32_fixture("app::nested_liti_class_check"));
            return;
        };

        unsafe {
            container.add(2).write(0);
            assert_eq!(nested_liti_class_check(container.cast()), 0);
        }
    }

    #[test]
    fn other_nested_class_tag_returns_zero() {
        let _guard = NESTED_LITI_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((container, target)) = mapped_objects() else {
            assert!(crate::testing::note_missing_u32_fixture("app::nested_liti_class_check"));
            return;
        };

        unsafe {
            target.write(0x706c_7374);
            container.add(2).write(target as usize as u32);
            assert_eq!(nested_liti_class_check(container.cast()), 0);
        }
    }
}
