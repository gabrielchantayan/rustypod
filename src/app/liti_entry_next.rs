//! Validated successor lookup for a `'liti'` list entry.
//!
//! - `liti_entry_next` — original: `FUN_08053b7c` @ `0x08053b7c`
//!   (24 bytes; 3 direct `bl` call sites, 0 predicated).

use crate::app::liti_field_class_check::liti_field_class_check;

/// `liti_entry_next` — original: `FUN_08053b7c` @ `0x08053b7c` (24 bytes).
///
/// Raw ARM establishes the exact extent `0x08053b7c..0x08053b94`: the
/// separately linked sibling `FUN_08053b94` begins with `cmp r0, #0` at
/// `0x08053b94`. Decoding every aligned ARM B/BL-immediate word in `osos.dec`
/// finds three inbound direct calls at `0x080490dc`, `0x080525a8`, and
/// `0x0813e7d0`; all are unconditional plain `bl`, with no predicated forms.
///
/// ```text
/// 08053b7c  mov r2, r0
/// 08053b80  str lr, [sp, #-4]!
/// 08053b84  bl  08057bb4  ; liti_field_class_check
/// 08053b88  movs r0, r0
/// 08053b8c  ldrne r0, [r2, #0]
/// 08053b90  ldr pc, [sp], #4
/// ```
///
/// Algorithm: validate `entry` with the word-one `'liti'` class predicate;
/// if it succeeds, return the aligned target-width word at offset zero,
/// otherwise return zero. Callers use that word as the successor while walking
/// a `'liti'` entry list.
///
/// Deliberate deviations: none. The direct Rust call replaces the retail
/// direct `bl` to the canonical predicate port; the conditional aligned word
/// load and zero-on-rejection behavior are unchanged.
///
/// # Safety
///
/// `entry` may be NULL. When non-NULL, it must be four-byte aligned and
/// readable through word index 1; its nonzero word-one target must satisfy
/// [`liti_field_class_check`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.liti_entry_next")]
pub unsafe extern "C" fn liti_entry_next(entry: *const u8) -> u32 {
    if unsafe { liti_field_class_check(entry) } == 0 {
        return 0;
    }

    unsafe { entry.cast::<u32>().read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const ENTRY_OFFSET: usize = 0x100;
    const TARGET_OFFSET: usize = 0x200;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;

    static LITI_ENTRY_NEXT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static LITI_ENTRY_NEXT_FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::LITI_ENTRY_NEXT, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });

    fn mapped_fixture() -> Option<(*mut u32, *mut u32)> {
        let base = (*LITI_ENTRY_NEXT_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.add(ENTRY_OFFSET).cast::<u32>(),
                base.add(TARGET_OFFSET).cast::<u32>(),
            ))
        }
    }

    #[test]
    fn null_entry_returns_zero() {
        assert_eq!(unsafe { liti_entry_next(core::ptr::null()) }, 0);
    }

    #[test]
    fn returns_successor_word_for_liti_entry_including_zero() {
        let _guard = LITI_ENTRY_NEXT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((entry, target)) = mapped_fixture() else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_entry_next"));
            return;
        };

        unsafe {
            target.write(LITI_CLASS_TAG);
            entry.add(1).write(target as usize as u32);
            entry.write(0xdead_beef);
            assert_eq!(liti_entry_next(entry.cast()), 0xdead_beef);
            entry.write(0);
            assert_eq!(liti_entry_next(entry.cast()), 0);
        }
    }

    #[test]
    fn rejects_non_liti_entry() {
        let _guard = LITI_ENTRY_NEXT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((entry, target)) = mapped_fixture() else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_entry_next"));
            return;
        };

        unsafe {
            target.write(0x706c_7374);
            entry.add(1).write(target as usize as u32);
            entry.write(0xdead_beef);
            assert_eq!(liti_entry_next(entry.cast()), 0);
        }
    }
}
