//! Finds a FreeType linked-module record by its class word.
//!
//! `ft_linked_module_find_by_class` — original: `FUN_0804ced4` @ `0x0804ced4`
//! (100 bytes; 4 plain `bl` call sites, no predicated BL).
//!
//! Raw `osos.dec` words cover `0x0804ced4..0x0804cf38`; the separately entered
//! `stmdb sp!, {r4,r5,r6,r7,r8,lr}` at `0x0804cf38` begins the next function.
//! The body has no outgoing calls.
//!
//! # Algorithm
//!
//! A null owner returns null. Otherwise, start at the owner word at +0x9c, or,
//! when `cursor` names a prior linked-record word, at that record's successor
//! (+4); clear `*cursor` before the search. Walk each record's successor (+4),
//! compare the class word at `record->module` (+8) + 0x18, and return that
//! module. On a match store its linked record in `cursor`; exhaustion returns
//! null. Deliberate deviation: none; target-width pointer fields are modeled as
//! volatile `u32` words rather than host pointer-width fields.

use core::ptr;

const OWNER_HEAD_OFFSET: usize = 0x9c;
const RECORD_NEXT_OFFSET: usize = 4;
const RECORD_MODULE_OFFSET: usize = 8;
const MODULE_CLASS_OFFSET: usize = 0x18;

/// Finds the first linked module whose class word equals `module_class`.
///
/// # Safety
///
/// `owner` may be null. Otherwise it must be readable through +0x9f and its
/// target-width linked records and modules must remain readable for the walk.
/// If non-null, `cursor` must be writable; its initial target word is either
/// null or a readable linked record.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ft_linked_module_find_by_class")]
pub unsafe extern "C" fn ft_linked_module_find_by_class(
    owner: *const u8,
    module_class: u32,
    cursor: *mut u32,
) -> *mut u8 {
    if owner.is_null() {
        return ptr::null_mut();
    }

    let mut record = ptr::addr_of!(*owner.add(OWNER_HEAD_OFFSET).cast::<u32>()).read_volatile();
    if !cursor.is_null() {
        let previous = cursor.read_volatile();
        if previous != 0 {
            record = ptr::addr_of!(*(previous as usize as *const u8)
                .add(RECORD_NEXT_OFFSET)
                .cast::<u32>())
            .read_volatile();
        }
        cursor.write_volatile(0);
    }

    while record != 0 {
        let record_pointer = record as usize as *const u8;
        let module = ptr::addr_of!(*record_pointer.add(RECORD_MODULE_OFFSET).cast::<u32>()).read_volatile();
        let class = ptr::addr_of!(*(module as usize as *const u8)
            .add(MODULE_CLASS_OFFSET)
            .cast::<u32>())
        .read_volatile();
        if class == module_class {
            if !cursor.is_null() {
                cursor.write_volatile(record);
            }
            return module as usize as *mut u8;
        }
        record = ptr::addr_of!(*record_pointer.add(RECORD_NEXT_OFFSET).cast::<u32>()).read_volatile();
    }

    ptr::null_mut()

}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const FIRST_RECORD: usize = 0x200;
    const SECOND_RECORD: usize = 0x240;
    const THIRD_RECORD: usize = 0x280;
    const FIRST_MODULE: usize = 0x400;
    const SECOND_MODULE: usize = 0x440;
    const THIRD_MODULE: usize = 0x480;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::FT_LINKED_MODULE_FIND_BY_CLASS, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn write_word(base: *mut u8, offset: usize, value: usize) {
        base.add(offset).cast::<u32>().write_volatile(value as u32);
    }

    unsafe fn setup() -> Option<*mut u8> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        write_word(base, OWNER_HEAD_OFFSET, base.add(FIRST_RECORD) as usize);
        write_word(base, FIRST_RECORD + RECORD_NEXT_OFFSET, base.add(SECOND_RECORD) as usize);
        write_word(base, SECOND_RECORD + RECORD_NEXT_OFFSET, base.add(THIRD_RECORD) as usize);
        write_word(base, FIRST_RECORD + RECORD_MODULE_OFFSET, base.add(FIRST_MODULE) as usize);
        write_word(base, SECOND_RECORD + RECORD_MODULE_OFFSET, base.add(SECOND_MODULE) as usize);
        write_word(base, THIRD_RECORD + RECORD_MODULE_OFFSET, base.add(THIRD_MODULE) as usize);
        write_word(base, FIRST_MODULE + MODULE_CLASS_OFFSET, 0x11);
        write_word(base, SECOND_MODULE + MODULE_CLASS_OFFSET, 0x22);
        write_word(base, THIRD_MODULE + MODULE_CLASS_OFFSET, 0x22);
        Some(base)
    }

    #[test]
    fn finds_first_match_and_records_its_link() {
        let _lock = LOCK.lock();
        let Some(base) = (unsafe { setup() }) else {
            assert!(note_missing_u32_fixture("ft/linked_module_find_by_class"));
            return;
        };
        let mut cursor = 0u32;
        assert_eq!(unsafe { ft_linked_module_find_by_class(base, 0x22, &mut cursor) }, unsafe { base.add(SECOND_MODULE) });
        assert_eq!(cursor as usize, unsafe { base.add(SECOND_RECORD) } as usize);
    }

    #[test]
    fn resumes_after_cursor_and_clears_it_on_miss() {
        let _lock = LOCK.lock();
        let Some(base) = (unsafe { setup() }) else {
            assert!(note_missing_u32_fixture("ft/linked_module_find_by_class"));
            return;
        };
        let mut cursor = unsafe { base.add(SECOND_RECORD) } as usize as u32;
        assert_eq!(unsafe { ft_linked_module_find_by_class(base, 0x22, &mut cursor) }, unsafe { base.add(THIRD_MODULE) });
        assert_eq!(cursor as usize, unsafe { base.add(THIRD_RECORD) } as usize);
        assert!(unsafe { ft_linked_module_find_by_class(base, 0x22, &mut cursor) }.is_null());
        assert_eq!(cursor, 0);
    }

    #[test]
    fn null_owner_preserves_cursor_and_empty_head_clears_it() {
        let _lock = LOCK.lock();
        let Some(base) = (unsafe { setup() }) else {
            assert!(note_missing_u32_fixture("ft/linked_module_find_by_class"));
            return;
        };
        let mut cursor = 0x1234_5678;
        assert!(unsafe { ft_linked_module_find_by_class(ptr::null(), 0x22, &mut cursor) }.is_null());
        assert_eq!(cursor, 0x1234_5678);
        cursor = unsafe { base.add(THIRD_RECORD) } as usize as u32;
        unsafe { write_word(base, OWNER_HEAD_OFFSET, 0) };
        assert!(unsafe { ft_linked_module_find_by_class(base, 0x22, &mut cursor) }.is_null());
        assert_eq!(cursor, 0);
    }
}
