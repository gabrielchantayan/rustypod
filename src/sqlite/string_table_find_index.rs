//! Finding a case-insensitive string in an 8-byte target-width table.
//!
//! `string_table_find_index` — original: `FUN_0837b204` @ `0x0837b204`
//! (80 bytes; raw extent `0x0837b204..0x0837b254`, ending at the next
//! `stmdb` function prologue). Raw ARM-word decoding verifies two incoming
//! direct `bl` call sites, both unconditional, and one outbound unconditional
//! `bl` to `str_icmp` @ `0x08384f14`; no predicated `bl` forms occur.
//!
//! The function scans a nullable `{ entries: u32, count: i32 }` header whose
//! 8-byte entries begin with a target-width C-string pointer. It returns the
//! first index whose string equals `key` under SQLite's ASCII case fold, or
//! `-1`. Deliberate deviation: target pointers remain explicit `u32` words
//! and are widened only for dereference, preserving the firmware layout on
//! 64-bit host tests.

use super::stricmp::str_icmp;

const ENTRY_WORDS: usize = 2;

/// Find the first case-insensitive `key` match in a target-width string table.
///
/// # Safety
/// When non-NULL, `table` must point to a `{ u32 entries, i32 count }` header.
/// A positive count requires `entries` to name that many readable two-word
/// records, each with a readable NUL-terminated C string in its first word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_table_find_index(table: *const u32, key: *const u8) -> i32 {
    if table.is_null() {
        return -1;
    }

    let entries = table.read() as usize as *const u32;
    let mut index = 0i32;
    while index < table.add(1).cast::<i32>().read() {
        let candidate = entries.add(index as usize * ENTRY_WORDS).read() as usize as *const u8;
        if str_icmp(candidate, key) == 0 {
            return index;
        }
        index = index.wrapping_add(1);
    }
    -1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const HEADER: usize = 0x00;
    const ENTRIES: usize = 0x20;
    const FIRST_NAME: usize = 0x100;
    const SECOND_NAME: usize = 0x120;
    const THIRD_NAME: usize = 0x140;
    const KEY: usize = 0x180;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_STRING_TABLE_FIND_INDEX, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    unsafe fn base() -> *mut u8 { SLAB.expect("fixture mapping was checked") as *mut u8 }

    unsafe fn set_c_string(offset: usize, value: &[u8]) {
        core::ptr::copy_nonoverlapping(value.as_ptr(), base().add(offset), value.len());
    }

    unsafe fn fixture() -> *const u32 {
        let base = base();
        core::ptr::write_bytes(base, 0, FIXTURE_LEN);
        set_c_string(FIRST_NAME, b"Alpha\0");
        set_c_string(SECOND_NAME, b"beta\0");
        set_c_string(THIRD_NAME, b"ALPHA\0");
        set_c_string(KEY, b"aLpHa\0");
        let entries = base.add(ENTRIES).cast::<u32>();
        entries.write(base.add(FIRST_NAME) as usize as u32);
        entries.add(ENTRY_WORDS).write(base.add(SECOND_NAME) as usize as u32);
        entries.add(ENTRY_WORDS * 2).write(base.add(THIRD_NAME) as usize as u32);
        let header = base.add(HEADER).cast::<u32>();
        header.write(entries as usize as u32);
        header.add(1).cast::<i32>().write(3);
        header
    }

    #[test]
    fn finds_first_case_insensitive_match() {
        if SLAB.is_none() {
            assert!(note_missing_u32_fixture("sqlite/string_table_find_index"));
            return;
        }
        unsafe {
            let header = fixture();
            assert_eq!(string_table_find_index(header, base().add(KEY)), 0);
            set_c_string(KEY, b"BETA\0");
            assert_eq!(string_table_find_index(header, base().add(KEY)), 1);
            set_c_string(KEY, b"missing\0");
            assert_eq!(string_table_find_index(header, base().add(KEY)), -1);
        }
    }

    #[test]
    fn null_and_nonpositive_tables_do_not_dereference_entries() {
        unsafe {
            assert_eq!(string_table_find_index(core::ptr::null(), core::ptr::null()), -1);
        }
        if SLAB.is_none() {
            assert!(note_missing_u32_fixture("sqlite/string_table_find_index"));
            return;
        }
        unsafe {
            let header = fixture();
            header.add(1).cast_mut().cast::<i32>().write(0);
            assert_eq!(string_table_find_index(header, base().add(KEY)), -1);
            header.add(1).cast_mut().cast::<i32>().write(-1);
            assert_eq!(string_table_find_index(header, base().add(KEY)), -1);
        }
    }
}
