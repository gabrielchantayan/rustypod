//! Construct SQLite KeyInfo from an expression list.
//!
//! `key_info_from_expr_list` — original: `FUN_082d76a8` at load address
//! `0x082d76a8`. Raw `osos.dec` words establish the exact 152-byte extent
//! `0x082d76a8..0x082d7740`; the following `push` begins a distinct function.
//! A whole-image ARM decode finds four direct inbound `bl` callers
//! (`0x08367e88`, `0x0838317c`, `0x08383238`, `0x08383424`), all plain and no
//! predicated calls. The body itself makes two unconditional calls:
//! `db_malloc_zero` and `expr_coll_seq`.
//!
//! This is SQLite 3.5.9's `sqlite3KeyInfoFromExprList`: allocate a target
//! KeyInfo with one collation word and one sort-order byte per expression,
//! inherit the connection default collation for expressions without one, and
//! copy every `ExprList_item.sortOrder` byte.
//!
//! Deliberate deviation: target pointers remain `u32` words rather than host
//! pointers, so the firmware's +0x0c list and KeyInfo offsets stay valid on
//! 64-bit host fixtures.

use core::ptr;

use super::expr_coll_seq::expr_coll_seq;
use super::mem::db_malloc_zero;

const LIST_COUNT_OFFSET: usize = 0x00;
const LIST_ITEMS_OFFSET: usize = 0x0c;
const LIST_ITEM_SIZE: usize = 0x0c;
const LIST_ITEM_EXPR_OFFSET: usize = 0x00;
const LIST_ITEM_SORT_ORDER_OFFSET: usize = 0x08;
const DB_DEFAULT_COLLATION_OFFSET: usize = 0x2c;
const DB_DATABASES_OFFSET: usize = 0x08;
const DATABASE_SCHEMA_OFFSET: usize = 0x14;
const SCHEMA_ENCODING_OFFSET: usize = 0x59;
const KEY_INFO_COUNT_OFFSET: usize = 0x08;
const KEY_INFO_SORT_ORDER_OFFSET: usize = 0x0c;
const KEY_INFO_COLLATIONS_OFFSET: usize = 0x10;
const KEY_INFO_ENCODING_OFFSET: usize = 0x04;

/// `sqlite3KeyInfoFromExprList`: build target-layout KeyInfo for `list`.
///
/// # Safety
/// `parse` must have a target-width database word at +0x00. `list` must have
/// a signed count at +0x00 and `count` readable 12-byte items at its target
/// word +0x0c. Each non-NULL expression must satisfy `expr_coll_seq`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn key_info_from_expr_list(parse: *mut u8, list: *const u8) -> *mut u8 {
    let count = (list.add(LIST_COUNT_OFFSET) as *const i32).read();
    let db = (parse as *const u32).read() as usize as *mut u8;
    let bytes = count.wrapping_mul(5).wrapping_add(20);
    let key_info = db_malloc_zero(db, bytes);
    if key_info.is_null() {
        return ptr::null_mut();
    }

    (key_info.add(KEY_INFO_COUNT_OFFSET) as *mut i32).write(count);
    let databases = (db.add(DB_DATABASES_OFFSET) as *const u32).read() as usize as *const u8;
    let schema = (databases.add(DATABASE_SCHEMA_OFFSET) as *const u32).read() as usize as *const u8;
    key_info.add(KEY_INFO_ENCODING_OFFSET).write(schema.add(SCHEMA_ENCODING_OFFSET).read());
    let sort_order = key_info.add(KEY_INFO_COLLATIONS_OFFSET).wrapping_offset(count as isize * 4);
    (key_info.add(KEY_INFO_SORT_ORDER_OFFSET) as *mut u32).write(sort_order as usize as u32);

    let items = (list.add(LIST_ITEMS_OFFSET) as *const u32).read() as usize as *const u8;
    let default_collation = (db.add(DB_DEFAULT_COLLATION_OFFSET) as *const u32).read();
    let mut i = 0i32;
    while i < count {
        let item = items.add(i as usize * LIST_ITEM_SIZE);
        let expr = (item.add(LIST_ITEM_EXPR_OFFSET) as *const u32).read() as usize as *mut _;
        let collation = expr_coll_seq(parse.cast(), expr) as usize as u32;
        (key_info.add(KEY_INFO_COLLATIONS_OFFSET + i as usize * 4) as *mut u32)
            .write(if collation == 0 { default_collation } else { collation });
        sort_order.add(i as usize).write(item.add(LIST_ITEM_SORT_ORDER_OFFSET).read());
        i = i.wrapping_add(1);
    }
    key_info
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::mock_heap;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::sqlite::mem::{MALLOC_FAILED_OFFSET};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_EXPR_LIST_KEY_INFO, 0x2000).map(|p| p as usize)
    });

    fn try_slab() -> Option<*mut u8> { (*SLAB).map(|address| address as *mut u8) }

    #[test]
    fn builds_inline_arrays_and_uses_default_collation_for_null_expressions() {
        let _test = TEST_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let _heap = mock_heap();
        unsafe {
            let parse = slab.add(0x100);
            let db = slab.add(0x200);
            parse.cast::<u32>().write(db as u32);
            db.add(MALLOC_FAILED_OFFSET).write(0);
            let databases = slab.add(0x280);
            let schema = slab.add(0x2c0);
            db.add(DB_DATABASES_OFFSET).cast::<u32>().write(databases as u32);
            databases.add(DATABASE_SCHEMA_OFFSET).cast::<u32>().write(schema as u32);
            schema.add(SCHEMA_ENCODING_OFFSET).write(1);
            db.add(DB_DEFAULT_COLLATION_OFFSET).cast::<u32>().write(slab.add(0x300) as u32);
            let list = slab.add(0x400);
            list.cast::<i32>().write(2);
            let items = slab.add(0x500);
            list.add(LIST_ITEMS_OFFSET).cast::<u32>().write(items as u32);
            items.cast::<u32>().write(0);
            items.add(LIST_ITEM_SORT_ORDER_OFFSET).write(1);
            items.add(LIST_ITEM_SIZE).cast::<u32>().write(0);
            items.add(LIST_ITEM_SIZE + LIST_ITEM_SORT_ORDER_OFFSET).write(0);
            let payload = slab.add(0x800);
            let _allocator = install_recorder(payload);

            let key_info = key_info_from_expr_list(parse, list);
            assert_eq!(key_info, payload);
            assert_eq!(realloc_log(), std::vec![(0, 30)]);
            assert_eq!(key_info.add(KEY_INFO_COUNT_OFFSET).cast::<i32>().read(), 2);
            assert_eq!(key_info.add(KEY_INFO_ENCODING_OFFSET).read(), 1);
            assert_eq!(key_info.add(KEY_INFO_SORT_ORDER_OFFSET).cast::<u32>().read(), key_info.add(24) as u32);
            assert_eq!(key_info.add(KEY_INFO_COLLATIONS_OFFSET).cast::<u32>().read(), slab.add(0x300) as u32);
            assert_eq!(key_info.add(KEY_INFO_COLLATIONS_OFFSET + 4).cast::<u32>().read(), slab.add(0x300) as u32);
            assert_eq!([key_info.add(24).read(), key_info.add(25).read()], [1, 0]);
        }
    }

    #[test]
    fn allocation_failure_returns_null_before_list_walk() {
        let _test = TEST_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        unsafe {
            let parse = slab.add(0x100);
            let db = slab.add(0x200);
            parse.cast::<u32>().write(db as u32);
            db.add(MALLOC_FAILED_OFFSET).write(0);
            let list = slab.add(0x400);
            list.cast::<i32>().write(3);
            list.add(LIST_ITEMS_OFFSET).cast::<u32>().write(0);
            let _allocator = install_recorder(ptr::null_mut());

            assert!(key_info_from_expr_list(parse, list).is_null());
            assert_eq!(realloc_log(), std::vec![(0, 35)]);
            assert_eq!(db.add(MALLOC_FAILED_OFFSET).read(), 1);
        }
    }
}
