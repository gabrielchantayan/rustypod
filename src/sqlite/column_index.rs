//! Finds a named column in a SQLite table.
//!
//! `column_index` — original: `FUN_082c4380` @ 0x082c4380 (80 bytes;
//! raw extent 0x082c4380..0x082c43d0, ending before `column_mem`). Four
//! direct `bl` call sites were verified from the ARM image, all unconditional;
//! the body itself has one unconditional `bl` and no predicated calls.
//!
//! The function linearly scans `Table.nCol` (+0x04) entries in `Table.aCol`
//! (+0x08), which are 20-byte `Column` records whose first word is `zName`.
//! It returns the first case-insensitive name match through `str_icmp`, or -1.
//! Deviation: none. Target pointer fields are loaded as u32 words so host
//! pointers cannot distort the recovered target layout.

use super::stricmp::str_icmp;

const TABLE_N_COL_OFFSET: usize = 0x04;
const TABLE_A_COL_OFFSET: usize = 0x08;
const COLUMN_SIZE: usize = 0x14;
const COLUMN_Z_NAME_OFFSET: usize = 0x00;

/// `sqlite3ColumnIndex` — original: `FUN_082c4380` @ 0x082c4380 (80 bytes;
/// 4 unconditional direct `bl` callers, no predicated callers).
///
/// Return the index of the first `Table.aCol` entry whose `zName` compares
/// equal to `name` under SQLite's ASCII-only case fold, or -1 if none match.
///
/// # Safety
/// `table` must reference a target-layout `Table`; its `aCol` word must name
/// at least signed `nCol` 20-byte records, and every visited `zName` and
/// `name` must be readable NUL-terminated strings.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn column_index(table: *const u8, name: *const u8) -> i32 {
    let mut index = 0i32;
    loop {
        let n_col = table.add(TABLE_N_COL_OFFSET).cast::<i32>().read_volatile();
        if n_col <= index {
            return -1;
        }
        let columns = table.add(TABLE_A_COL_OFFSET).cast::<u32>().read() as usize;
        let column = (columns + index as usize * COLUMN_SIZE + COLUMN_Z_NAME_OFFSET) as *const u32;
        if str_icmp(column.read() as *const u8, name) == 0 {
            return index;
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static SLAB_LOCK: Mutex<()> = Mutex::new(());

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::SQLITE_COLUMN_INDEX, 0x1000)
                .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    unsafe fn build_table(names: &[&[u8]], n_col: i32) {
        let base = slab();
        base.add(TABLE_N_COL_OFFSET).cast::<i32>().write(n_col);
        base.add(TABLE_A_COL_OFFSET).cast::<u32>().write(base.add(0x40) as u32);
        for (index, name) in names.iter().enumerate() {
            let column = base.add(0x40 + index * COLUMN_SIZE);
            let z_name = base.add(0x200 + index * 0x20);
            core::ptr::copy_nonoverlapping(name.as_ptr(), z_name, name.len());
            column.add(COLUMN_Z_NAME_OFFSET).cast::<u32>().write(z_name as u32);
        }
    }

    #[test]
    fn finds_first_matching_column_with_sqlite_case_fold() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() { return; }
        unsafe {
            build_table(&[b"album\0", b"Artist\0", b"title\0"], 3);
            assert_eq!(column_index(slab(), b"ARTIST\0".as_ptr()), 1);
        }
    }

    #[test]
    fn returns_first_duplicate_and_minus_one_for_a_miss() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() { return; }
        unsafe {
            build_table(&[b"name\0", b"NAME\0", b"other\0"], 3);
            assert_eq!(column_index(slab(), b"name\0".as_ptr()), 0);
            assert_eq!(column_index(slab(), b"missing\0".as_ptr()), -1);
        }
    }

    #[test]
    fn nonpositive_column_count_does_not_follow_a_col() {
        let _slab_guard = SLAB_LOCK.lock();
        if try_slab().is_none() { return; }
        unsafe {
            let table = slab();
            table.add(TABLE_A_COL_OFFSET).cast::<u32>().write(0);
            for n_col in [0, -1] {
                table.add(TABLE_N_COL_OFFSET).cast::<i32>().write(n_col);
                assert_eq!(column_index(table, b"unread\0".as_ptr()), -1);
            }
        }
    }
}
