//! Indexed entry lookup for a `'liti'` ImageLibrary database object.
//!
//! - `liti_indexed_entry_lookup` — original: `FUN_080525b8` @ `0x080525b8`
//!   (64 bytes; 4 direct `bl` call sites, 0 predicated).

use crate::app::liti_field_class_check::liti_field_class_check;

/// `liti_indexed_entry_lookup` — original: `FUN_080525b8` @ `0x080525b8`
/// (64 bytes).
///
/// Raw ARM establishes the exact extent `0x080525b8..0x080525f8`: the next
/// separately linked function starts with `push {r4,r5,r6,lr}` at
/// `0x080525f8`. Decoding every aligned ARM B/BL-immediate word in `osos.dec`
/// finds four inbound direct calls at `0x08106d20`, `0x08106d5c`,
/// `0x08106f74`, and `0x08107038`; all are unconditional plain `bl`, with no
/// predicated forms.
///
/// ```text
/// 080525b8  mov r2, r0
/// 080525bc  mov r3, r1
/// 080525c0  str lr, [sp, #-4]!
/// 080525c4  bl  08057bb4  ; liti_field_class_check
/// 080525c8  cmp r0, #0
/// 080525cc  beq 080525f0
/// 080525d0  movs r0, r2
/// 080525d4  ldrne r0, [r2, #0x18]
/// 080525d8  cmp r0, r3
/// 080525dc  bls 080525f0
/// 080525e0  ldr r0, [r2, #0x1c]
/// 080525e4  cmp r0, #0
/// 080525e8  ldrne r0, [r0, r3, lsl #2]
/// ```
///
/// Algorithm: first require that `object` has a word-one `'liti'` target.
/// Then return word `index` from the target-width table pointer at +0x1c only
/// when `index` is strictly below the count at +0x18; otherwise return zero.
///
/// Deliberate deviations: none. Target-width fields remain `u32` word indices
/// on the host, preserving the retail +0x18/+0x1c layout despite host pointers
/// being wider.
///
/// # Safety
///
/// `object` may be NULL. Otherwise it must be four-byte aligned and readable
/// through word index 7. Its word-one target must satisfy
/// [`liti_field_class_check`]; a nonzero table pointer must designate at least
/// `count` readable `u32` words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.liti_indexed_entry_lookup")]
pub unsafe extern "C" fn liti_indexed_entry_lookup(object: *const u8, index: u32) -> u32 {
    if unsafe { liti_field_class_check(object) } == 0 {
        return 0;
    }

    let object = object.cast::<u32>();
    if index >= unsafe { object.add(6).read() } {
        return 0;
    }

    let entries = unsafe { object.add(7).read() } as usize as *const u32;
    if entries.is_null() {
        return 0;
    }

    unsafe { entries.add(index as usize).read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const FIXTURE_LEN: usize = 0x1000;
    const OBJECT_OFFSET: usize = 0x100;
    const TARGET_OFFSET: usize = 0x200;
    const TABLE_OFFSET: usize = 0x300;
    const LITI_CLASS_TAG: u32 = 0x6974_696c;

    static LITI_INDEXED_ENTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static LITI_INDEXED_ENTRY_FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::LITI_INDEXED_ENTRY_LOOKUP, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });

    fn mapped_fixture() -> Option<(*mut u32, *mut u32, *mut u32)> {
        let base = (*LITI_INDEXED_ENTRY_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some((
                base.add(OBJECT_OFFSET).cast::<u32>(),
                base.add(TARGET_OFFSET).cast::<u32>(),
                base.add(TABLE_OFFSET).cast::<u32>(),
            ))
        }
    }

    #[test]
    fn null_object_returns_zero() {
        assert_eq!(unsafe { liti_indexed_entry_lookup(core::ptr::null(), 0) }, 0);
    }

    #[test]
    fn returns_indexed_entry_for_liti_object() {
        let _guard = LITI_INDEXED_ENTRY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((object, target, table)) = mapped_fixture() else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_indexed_entry_lookup"));
            return;
        };

        unsafe {
            target.write(LITI_CLASS_TAG);
            object.add(1).write(target as usize as u32);
            object.add(6).write(3);
            object.add(7).write(table as usize as u32);
            table.add(0).write(0x1111_1111);
            table.add(1).write(0xdead_beef);
            table.add(2).write(0x3333_3333);
            assert_eq!(liti_indexed_entry_lookup(object.cast(), 1), 0xdead_beef);
        }
    }

    #[test]
    fn rejects_count_boundary_and_null_table() {
        let _guard = LITI_INDEXED_ENTRY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((object, target, table)) = mapped_fixture() else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_indexed_entry_lookup"));
            return;
        };

        unsafe {
            target.write(LITI_CLASS_TAG);
            object.add(1).write(target as usize as u32);
            object.add(6).write(1);
            object.add(7).write(table as usize as u32);
            table.write(0x1234_5678);
            assert_eq!(liti_indexed_entry_lookup(object.cast(), 1), 0);
            object.add(7).write(0);
            assert_eq!(liti_indexed_entry_lookup(object.cast(), 0), 0);
        }
    }

    #[test]
    fn rejects_non_liti_object_without_reading_table_fields() {
        let _guard = LITI_INDEXED_ENTRY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((object, target, _table)) = mapped_fixture() else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_indexed_entry_lookup"));
            return;
        };

        unsafe {
            target.write(0x706c_7374);
            object.add(1).write(target as usize as u32);
            assert_eq!(liti_indexed_entry_lookup(object.cast(), 0), 0);
        }
    }
}
