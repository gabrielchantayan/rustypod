//! SQLite trigger UPDATE-column overlap predicate.
//!
//! `check_column_overlap` — `FUN_082c24f0` @ `0x082c24f0`, 92 bytes
//! (`0x082c24f0..0x082c254c`; next raw ARM push prologue at the end).
//! Raw word decoding finds two incoming unconditional BLs (0x08372fdc,
//! 0x08385258), one outgoing unconditional BL to string_table_find_index
//! @ 0x0837b204, and no predicated BLs. NULL lists mean unrestricted overlap.
//! Otherwise scan the signed ExprList count and search each 12-byte item's
//! name (word 1) in the IdList's case-insensitive string table. Return 1 on
//! the first match, else 0. Deliberate deviation: retain target pointers as
//! u32 words and widen for dereference so host layouts match ARM.

use super::string_table_find_index::string_table_find_index;

/// Test whether trigger columns intersect changed expression names.
///
/// # Safety
/// Non-NULL `columns` is an IdList `{ u32 entries, i32 count }` accepted by
/// string_table_find_index. Non-NULL `changes` has signed count at word 0
/// and an item pointer at word 3; positive counts require readable three-word
/// items with readable NUL-terminated names in word 1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn check_column_overlap(columns: *const u32, changes: *const u32) -> i32 {
    if columns.is_null() || changes.is_null() {
        return 1;
    }
    let mut index = 0i32;
    while index < changes.cast::<i32>().read() {
        let items = changes.add(3).read() as usize as *const u32;
        let name = items.add(index as usize * 3 + 1).read() as usize as *const u8;
        if string_table_find_index(columns, name) >= 0 {
            return 1;
        }
        index = index.wrapping_add(1);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn null_lists_are_unrestricted_without_reading_the_other_list() {
        unsafe {
            assert_eq!(check_column_overlap(core::ptr::null(), core::ptr::null()), 1);
            let inaccessible = 4usize as *const u32;
            assert_eq!(check_column_overlap(core::ptr::null(), inaccessible), 1);
            assert_eq!(check_column_overlap(inaccessible, core::ptr::null()), 1);
        }
    }

    #[test]
    fn signed_counts_strided_names_and_case_insensitive_intersection() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_CHECK_COLUMN_OVERLAP, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite/check_column_overlap"));
            return;
        };
        unsafe {
            let columns = slab.cast::<u32>();
            let changes = slab.add(0x20).cast::<u32>();
            let ids = slab.add(0x40).cast::<u32>();
            let items = slab.add(0x80).cast::<u32>();
            let name = slab.add(0x100);
            core::ptr::copy_nonoverlapping(b"Alpha\0missing\0aLPHa\0".as_ptr(), name, 20);
            columns.write(ids as usize as u32);
            columns.add(1).write(1);
            ids.write(name as usize as u32);
            changes.add(3).write(items as usize as u32);
            // Non-name words are invalid pointers: only word 1 may be read.
            for i in 0..6 { items.add(i).write(1); }
            items.add(1).write(name.add(6) as usize as u32);
            items.add(4).write(name.add(14) as usize as u32);
            for count in [i32::MIN, -1, 0, 1] {
                changes.cast::<i32>().write(count);
                assert_eq!(check_column_overlap(columns, changes), 0);
            }
            changes.write(2);
            assert_eq!(check_column_overlap(columns, changes), 1);
            // A first match must not touch the invalid second name.
            items.add(1).write(name.add(14) as usize as u32);
            items.add(4).write(1);
            assert_eq!(check_column_overlap(columns, changes), 1);
            changes.write(1);
            for count in [0i32, -1] {
                columns.add(1).cast::<i32>().write(count);
                assert_eq!(check_column_overlap(columns, changes), 0);
            }
        }
    }
}
