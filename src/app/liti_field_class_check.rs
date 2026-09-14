//! The word-one `'liti'` ImageLibrary-database class check.
//!
//! - `liti_field_class_check` — original: `FUN_08057bb4` @ `0x08057bb4`
//!   (40 bytes; 6 direct `bl` call sites, 0 predicated).

use crate::app::liti_class_check::image_library_is_liti_class;

/// `liti_field_class_check` — original: `FUN_08057bb4` @ `0x08057bb4`
/// (40 bytes).
///
/// Raw ARM establishes the exact extent `0x08057bb4..0x08057bdc`: the
/// separately linked sibling `FUN_08057bdc` begins with `cmp r0, #0` at
/// `0x08057bdc`. Decoding every ARM B/BL word in `osos.dec` finds six inbound
/// direct calls, all unconditional plain `bl`; there are no predicated BL
/// forms. One unconditional plain-B tail caller at `0x081070a0` is distinct
/// from that six-call count.
///
/// ```text
/// 08057bb4  cmp r0, #0
/// 08057bb8  str lr, [sp, #-4]!
/// 08057bbc  beq 08057bd4
/// 08057bc0  ldr r0, [r0, #4]
/// 08057bc4  bl  08057c2c  ; image_library_is_liti_class
/// 08057bc8  cmp r0, #0
/// 08057bcc  movne r0, #1
/// 08057bd0  ldrne pc, [sp], #4
/// 08057bd4  mov r0, #0
/// 08057bd8  ldr pc, [sp], #4
/// ```
///
/// Algorithm: return 0 for a NULL `object`; otherwise load its target-width
/// word at +0x04 and pass that pointer to the NULL-guarded `'liti'` class-tag
/// predicate. The nonzero predicate result is canonicalized to 1. The
/// enclosing object type and its field identity are otherwise unknown, so the
/// verified field is addressed as word index 1 rather than given an unsupported
/// structural type.
///
/// Deliberate deviations: none. The original uses an aligned `ldr` at +0x04;
/// this port performs the same aligned target-width word load. The direct Rust
/// call replaces the retail direct `bl` with a direct call to the canonical
/// predicate port.
///
/// # Safety
///
/// `object` may be NULL. When non-NULL, it must be four-byte aligned and
/// readable through word index 1; a nonzero field must be a valid target-width
/// pointer readable by [`image_library_is_liti_class`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.liti_field_class_check")]
pub unsafe extern "C" fn liti_field_class_check(object: *const u8) -> u32 {
    if object.is_null() {
        return 0;
    }

    let target = unsafe { object.cast::<u32>().add(1).read() } as usize as *const u8;
    u32::from(unsafe { image_library_is_liti_class(target) } != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const OBJECT_OFFSET: usize = 0x100;
    const TARGET_OFFSET: usize = 0x200;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;

    static LITI_FIELD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static LITI_FIELD_FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::LITI_FIELD_CLASS_CHECK,
            FIXTURE_LEN,
        )
        .map(|pointer| pointer as usize)
    });

    fn mapped_objects() -> Option<(*mut u32, *mut u32)> {
        let base = (*LITI_FIELD_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.add(OBJECT_OFFSET).cast::<u32>(),
                base.add(TARGET_OFFSET).cast::<u32>(),
            ))
        }
    }

    #[test]
    fn null_object_returns_zero() {
        assert_eq!(unsafe { liti_field_class_check(core::ptr::null()) }, 0);
    }

    #[test]
    fn follows_word_one_to_liti_object() {
        let _guard = LITI_FIELD_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((object, target)) = mapped_objects() else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_field_class_check"));
            return;
        };

        unsafe {
            target.write(LITI_CLASS_TAG);
            object.add(1).write(target as usize as u32);
            assert_eq!(liti_field_class_check(object.cast()), 1);
        }
    }

    #[test]
    fn null_word_one_returns_zero() {
        let _guard = LITI_FIELD_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((object, _target)) = mapped_objects() else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_field_class_check"));
            return;
        };

        unsafe {
            object.add(1).write(0);
            assert_eq!(liti_field_class_check(object.cast()), 0);
        }
    }

    #[test]
    fn other_word_one_class_tag_returns_zero() {
        let _guard = LITI_FIELD_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((object, target)) = mapped_objects() else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_field_class_check"));
            return;
        };

        unsafe {
            target.write(0x706c_7374);
            object.add(1).write(target as usize as u32);
            assert_eq!(liti_field_class_check(object.cast()), 0);
        }
    }
}
