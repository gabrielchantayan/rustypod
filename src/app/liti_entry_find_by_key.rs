use crate::app::liti_field_class_check::liti_field_class_check;

/// `liti_entry_find_by_key` — `FUN_0805038c` @ `0x0805038c`.
/// True extent: 96 bytes, ending at the independent function at 0x080503ec.
/// Whole-image aligned A32 decoding verifies two plain inbound BLs
/// (0x08106e44, 0x08106ec0), zero predicated inbound BLs, and one internal
/// plain BL (0x08050398 to liti_field_class_check), zero predicated BLs.
/// Reject a non-liti object or null table at +0x1c. Search its +0x18 count
/// of target-width entry pointers in order, returning the first entry whose
/// aligned +0x0c word equals key, or zero when exhausted. The callers use
/// the result for subsequent nested-entry lookup and image metadata reads.
/// Deliberate deviations: use the existing Rust class predicate; omit the
/// redundant null-object check after that predicate has accepted the object.
/// Only r0 and r1 are inputs; Ghidra's extra parameters are not arguments.
///
/// # Safety
/// A non-null object must satisfy liti_field_class_check's contract. An
/// accepted object must be aligned and readable through word seven. Its
/// nonzero table must contain count readable u32 entry pointers, each of
/// which must be nonzero, aligned, and readable through word three.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn liti_entry_find_by_key(object: *const u8, key: u32) -> u32 {
    if unsafe { liti_field_class_check(object) } == 0 {
        return 0;
    }
    let object = object.cast::<u32>();
    let table = unsafe { object.add(7).read() } as usize as *const u32;
    if table.is_null() {
        return 0;
    }
    let count = unsafe { object.add(6).read() };
    let mut index = 0;
    while index < count {
        let entry = unsafe { table.add(index as usize).read() };
        if unsafe { (entry as usize as *const u32).add(3).read() } == key {
            return entry;
        }
        index += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::LITI_ENTRY_FIND_BY_KEY, 0x1000)
            .map(|pointer| pointer as usize)
    });

    #[test]
    fn null_and_rejected_objects_do_not_access_table() {
        unsafe {
            assert_eq!(liti_entry_find_by_key(core::ptr::null(), 0), 0);
            let object = [0u32, 0];
            assert_eq!(liti_entry_find_by_key(object.as_ptr().cast(), u32::MAX), 0);
        }
    }

    #[test]
    fn ordered_search_boundaries_and_rejection() {
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_entry_find_by_key"));
            return;
        };
        unsafe {
            let object = base as *mut u32;
            core::ptr::write_bytes(object, 0, 0x1000 / 4);
            let class = object.add(32);
            let table = object.add(64);
            let entries = [object.add(96), object.add(104), object.add(112), object.add(120)];
            class.write(0x6974_696c);
            object.add(1).write(class as usize as u32);
            object.add(6).write(4);
            object.add(7).write(table as usize as u32);
            let keys = [0, u32::MAX, 0x8000_0000, u32::MAX];
            for i in 0..4 {
                table.add(i).write(entries[i] as usize as u32);
                entries[i].add(2).write(0x1234_5678);
                entries[i].add(3).write(keys[i]);
            }
            for (key, expected) in [(0, entries[0]), (u32::MAX, entries[1]), (0x8000_0000, entries[2])] {
                assert_eq!(liti_entry_find_by_key(object.cast(), key), expected as usize as u32);
            }
            assert_eq!(liti_entry_find_by_key(object.cast(), 0x1234_5678), 0);
            object.add(6).write(1);
            assert_eq!(liti_entry_find_by_key(object.cast(), u32::MAX), 0);
            object.add(6).write(0);
            table.write(0); // Empty tables must not dereference their first slot.
            assert_eq!(liti_entry_find_by_key(object.cast(), 0), 0);
            object.add(6).write(u32::MAX);
            object.add(7).write(0);
            assert_eq!(liti_entry_find_by_key(object.cast(), 0), 0);
            class.write(0x706c_7374);
            object.add(7).write(1); // Rejection must precede reading the invalid table.
            assert_eq!(liti_entry_find_by_key(object.cast(), 0), 0);
        }
    }
}
