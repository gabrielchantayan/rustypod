//! First entry accessor for a `'liti'` ImageLibrary database.

use crate::app::liti_class_check::image_library_is_liti_class;

/// Target-byte offset of the first-entry word.
const FIRST_ENTRY_OFFSET: usize = 0x18;

/// image_library_first_entry — original: `FUN_08052274` @ `0x08052274`
/// (24 bytes).
///
/// Raw `osos.dec` decodes as:
///
/// ```text
/// 08052274  mov r2, r0
/// 08052278  push {lr}
/// 0805227c  bl  0x08057c2c       ; image_library_is_liti_class
/// 08052280  movs r0, r0
/// 08052284  ldrne r0, [r2, #0x18]
/// 08052288  pop {pc}
/// ```
///
/// The next separately callable accessor starts at `0x0805228c` with
/// `mov r2, r0`, establishing the 24-byte extent. The body has one plain
/// outbound `bl` and no predicated `bl`; whole-image decoding finds three
/// inbound plain `bl` callsites and no predicated inbound forms.
///
/// Algorithm: validate `database` as a non-NULL `'liti'` ImageLibrary object,
/// then return its target-width word at `+0x18`; return zero on rejection.
/// The callers at `0x080490d0`, `0x08052594`, and `0x0813e748` use that word
/// as the initial element of a successor-walked list. Deliberate deviation:
/// calls the existing Rust class predicate directly rather than branching to
/// retailOS; the aligned word load and zero-on-rejection behavior are unchanged.
///
/// # Safety
///
/// `database` may be NULL. A non-NULL pointer must be four-byte aligned and
/// readable through `+0x03`; if it has the `'liti'` tag it must also be readable
/// through `+0x1b`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.image_library_first_entry")]
pub unsafe extern "C" fn image_library_first_entry(database: *const u8) -> u32 {
    if unsafe { image_library_is_liti_class(database) } != 0 {
        unsafe { database.add(FIRST_ENTRY_OFFSET).cast::<u32>().read() }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const DATABASE_OFFSET: usize = 0x100;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;
    const FIRST_ENTRY_WORD: usize = FIRST_ENTRY_OFFSET / core::mem::size_of::<u32>();

    static IMAGE_LIBRARY_FIRST_ENTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static IMAGE_LIBRARY_FIRST_ENTRY_FIXTURE: std::sync::LazyLock<Option<usize>> =
        std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::IMAGE_LIBRARY_FIRST_ENTRY,
                FIXTURE_LEN,
            )
            .map(|pointer| pointer as usize)
        });

    fn mapped_database() -> Option<*mut u32> {
        let base = (*IMAGE_LIBRARY_FIRST_ENTRY_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some(base.add(DATABASE_OFFSET).cast())
        }
    }

    macro_rules! locked_database {
        () => {
            match mapped_database() {
                Some(database) => (
                    IMAGE_LIBRARY_FIRST_ENTRY_TEST_LOCK
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                    database,
                ),
                None => {
                    assert!(crate::testing::note_missing_u32_fixture(
                        "app::image_library_first_entry"
                    ));
                    return;
                }
            }
        };
    }

    #[test]
    fn null_database_returns_zero() {
        assert_eq!(unsafe { image_library_first_entry(core::ptr::null()) }, 0);
    }

    #[test]
    fn liti_database_returns_entry_word_including_zero_and_high_bit_values() {
        let (_guard, database) = locked_database!();
        unsafe {
            database.write(LITI_CLASS_TAG);
            for entry in [0, 0x0804_7bfc, 0x2200_aed8, u32::MAX] {
                database.add(FIRST_ENTRY_WORD).write(entry);
                assert_eq!(image_library_first_entry(database.cast()), entry);
            }
        }
    }

    #[test]
    fn non_liti_database_returns_zero_without_reading_entry_word() {
        let (_guard, database) = locked_database!();
        unsafe {
            database.write(0x706c_7374); // 'plst'
            database.add(FIRST_ENTRY_WORD).write(0xdead_beef);
            assert_eq!(image_library_first_entry(database.cast()), 0);
        }
    }

    #[test]
    fn only_word_at_offset_18_is_returned() {
        let (_guard, database) = locked_database!();
        unsafe {
            database.write(LITI_CLASS_TAG);
            database.add(FIRST_ENTRY_WORD - 1).write(0xdead_beef);
            database.add(FIRST_ENTRY_WORD).write(0x1020_3040);
            database.add(FIRST_ENTRY_WORD + 1).write(0xcafe_babe);
            assert_eq!(image_library_first_entry(database.cast()), 0x1020_3040);
        }
    }
}
