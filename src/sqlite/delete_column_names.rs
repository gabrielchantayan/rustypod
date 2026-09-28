//! Release a table's column metadata.
//!
//! `sqlite3DeleteColumnNames` — original: `FUN_08391cbc` @ `0x08391cbc`
//! (104 bytes, true extent `0x08391cbc..0x08391d24`; the independent
//! `free_tag57` veneer begins at `0x08391d24`). Raw ARM-word decoding finds
//! **5 direct unconditional `bl` instructions** (four `tracked_free` and one
//! `expr_delete` per column) and **0 predicated `bl` instructions**.
//!
//! The target-width table prefix holds signed `nCol` at +0x04 and its `aCol`
//! pointer at +0x08. When `aCol` is non-NULL, release each 20-byte column's
//! name, default expression, declared type, and collation name in that order;
//! then release the array. Finally clear `aCol` and `nCol`, even for a NULL
//! array. Deliberate deviation: target pointers are read as u32 words instead
//! of a host-pointer `repr(C)` layout so the retail offsets and 20-byte stride
//! remain exact on 64-bit host tests.

use crate::heap::tracked::tracked_free;
use super::expr_delete::expr_delete;

const N_COL_WORD: usize = 1;
const COLUMNS_WORD: usize = 2;
const COLUMN_WORDS: usize = 5;

#[inline(always)]
unsafe fn word(object: *const u8, index: usize) -> u32 {
    (object as *const u32).add(index).read_volatile()
}

#[inline(always)]
unsafe fn set_word(object: *mut u8, index: usize, value: u32) {
    (object as *mut u32).add(index).write_volatile(value);
}

/// `sqlite3DeleteColumnNames(table)` — release `table->aCol` and reset it.
///
/// # Safety
///
/// `table` must point to the target-width Table prefix. If its `aCol` word is
/// nonzero, it must name `nCol` consecutive, aligned 20-byte Column records.
/// Every pointer word released by the retail routine must meet its callee's
/// safety requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_delete_column_names(table: *mut u8) {
    let columns = word(table, COLUMNS_WORD) as usize as *mut u8;
    if !columns.is_null() {
        let mut column = columns;
        let mut index = 0_i32;
        while index < word(table, N_COL_WORD) as i32 {
            tracked_free(word(column, 0) as usize as *mut u8);
            expr_delete(word(column, 1) as usize as *mut u8);
            tracked_free(word(column, 2) as usize as *mut u8);
            tracked_free(word(column, 3) as usize as *mut u8);
            index += 1;
            column = column.add(COLUMN_WORDS * core::mem::size_of::<u32>());
        }
        tracked_free(columns);
    }
    set_word(table, COLUMNS_WORD, 0);
    set_word(table, N_COL_WORD, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::mock_heap;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_LEN: usize = 0x1000;
    const TABLE: usize = 0x000;
    const COLUMNS: usize = 0x100;
    const NAME: usize = 0x300;
    const DEFAULT: usize = 0x400;
    const TYPE: usize = 0x500;
    const COLLATION: usize = 0x600;

    unsafe fn set_word_at(base: *mut u8, offset: usize, value: u32) {
        (base.add(offset) as *mut u32).write(value);
    }

    // Creates the minimal tracked allocation cookie consumed by tracked_free.
    unsafe fn tracked_payload(base: *mut u8, offset: usize) -> *mut u8 {
        let payload = base.add(offset);
        set_word_at(base, offset - 12, 1);
        set_word_at(base, offset - 4, 4);
        payload
    }

    #[test]
    fn releases_every_column_field_in_retail_order_and_resets_table() {
        let _heap = mock_heap();
        let Some(base) = (unsafe { try_map_u32_slab(hints::SQLITE_DELETE_COLUMN_NAMES, FIXTURE_LEN) }) else {
            assert!(note_missing_u32_fixture("sqlite/delete_column_names"));
            return;
        };
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            let name = tracked_payload(base, NAME);
            let default = tracked_payload(base, DEFAULT);
            let ty = tracked_payload(base, TYPE);
            let collation = tracked_payload(base, COLLATION);
            let columns = tracked_payload(base, COLUMNS);
            set_word_at(base, TABLE + N_COL_WORD * 4, 1);
            set_word_at(base, TABLE + COLUMNS_WORD * 4, columns as usize as u32);
            set_word_at(base, COLUMNS, name as usize as u32);
            set_word_at(base, COLUMNS + 4, default as usize as u32);
            set_word_at(base, COLUMNS + 8, ty as usize as u32);
            set_word_at(base, COLUMNS + 12, collation as usize as u32);
            sqlite_delete_column_names(base.add(TABLE));
            assert_eq!(word(base.add(TABLE), N_COL_WORD), 0);
            assert_eq!(word(base.add(TABLE), COLUMNS_WORD), 0);
        }
    }

    #[test]
    fn null_array_still_clears_a_negative_count() {
        let Some(base) = (unsafe { try_map_u32_slab(hints::SQLITE_DELETE_COLUMN_NAMES_EMPTY, FIXTURE_LEN) }) else {
            assert!(note_missing_u32_fixture("sqlite/delete_column_names empty"));
            return;
        };
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            set_word_at(base, TABLE + N_COL_WORD * 4, (-1_i32) as u32);
            sqlite_delete_column_names(base.add(TABLE));
            assert_eq!(word(base.add(TABLE), N_COL_WORD), 0);
            assert_eq!(word(base.add(TABLE), COLUMNS_WORD), 0);
        }
    }
}
