//! Fault cursors belonging to B-trees with open write transactions.
//!
//! `btree_trip_write_cursors` is retailOS `FUN_082d6cb4` at load address
//! `0x082d6cb4`. Raw ARM establishes the complete 84-byte extent
//! `0x082d6cb4..0x082d6d08`: the next separately linked function begins with
//! `push {r4,lr}` at `0x082d6d08`. There are two inbound unconditional plain
//! `bl` calls (`0x0838b1e0`, `0x0838b254`) and no inbound predicated calls.
//! The body has one plain `bl` to `btree_in_write_trans` and one predicated
//! `blne` to `btree_trip_all_cursors`.
//!
//! This is SQLite rollback preparation: scan the signed `sqlite3.nDb` count,
//! and fault every cursor in each non-null B-tree whose `inTrans` byte equals
//! `TRANS_WRITE`, using `SQLITE_ABORT` (4). Deliberate deviation: `aDb` and
//! `Db.pBt` stay target-width `u32` words, preserving retail offsets on 64-bit
//! host fixtures.

use crate::sqlite::btree_in_trans::btree_in_write_trans;
use crate::sqlite::btree_trip_all_cursors::btree_trip_all_cursors;

const DATABASE_COUNT_OFFSET: usize = 0x04;
const DATABASES_OFFSET: usize = 0x08;
const DATABASE_RECORD_SIZE: usize = 0x18;
const DATABASE_BTREE_OFFSET: usize = 0x04;
const SQLITE_ABORT: i32 = 4;

#[inline(always)]
unsafe fn target_pointer(at: *const u8) -> *mut u8 {
    at.cast::<u32>().read() as usize as *mut u8
}

/// `sqlite3BtreeTripAllCursors` rollback preparation — retailOS
/// `FUN_082d6cb4` @ `0x082d6cb4` (84 bytes; one outbound plain `bl`, one
/// outbound predicated `blne`).
///
/// `database` must name a target-layout `sqlite3` object. Only B-trees in an
/// exact write transaction have their cursor lists faulted; null and read-only
/// slots remain untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_trip_write_cursors(database: *mut u8) {
    let mut index = 0i32;
    while index < database.add(DATABASE_COUNT_OFFSET).cast::<i32>().read() {
        let record = target_pointer(database.add(DATABASES_OFFSET))
            .add(index as usize * DATABASE_RECORD_SIZE);
        let btree = target_pointer(record.add(DATABASE_BTREE_OFFSET));
        if !btree.is_null() && btree_in_write_trans(btree) != 0 {
            btree_trip_all_cursors(btree, SQLITE_ABORT);
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const DATABASES: usize = 0x100;
    const WRITE_BTREE: usize = 0x200;
    const READ_BTREE: usize = 0x300;
    const SHARED: usize = 0x400;
    const CURSOR: usize = 0x500;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_TRIP_WRITE_CURSORS, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<*mut u8> {
        let base = (*SLAB)? as *mut u8;
        base.write_bytes(0, SLAB_LEN);
        Some(base)
    }

    unsafe fn set_pointer(base: *mut u8, offset: usize, value: *mut u8) {
        base.add(offset).cast::<u32>().write(value as usize as u32);
    }

    #[test]
    fn faults_only_write_transaction_cursors() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(database) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_trip_write_cursors"));
            return;
        };
        unsafe {
            let databases = database.add(DATABASES);
            let write_btree = database.add(WRITE_BTREE);
            let read_btree = database.add(READ_BTREE);
            let shared = database.add(SHARED);
            let cursor = database.add(CURSOR);
            database.add(DATABASE_COUNT_OFFSET).cast::<i32>().write(3);
            set_pointer(database, DATABASES_OFFSET, databases);
            set_pointer(databases, DATABASE_BTREE_OFFSET, write_btree);
            set_pointer(databases.add(DATABASE_RECORD_SIZE), DATABASE_BTREE_OFFSET, read_btree);
            set_pointer(databases.add(2 * DATABASE_RECORD_SIZE), DATABASE_BTREE_OFFSET, core::ptr::null_mut());
            write_btree.add(0x08).write(2);
            set_pointer(write_btree, 0x04, shared);
            set_pointer(shared, 0x08, cursor);
            set_pointer(cursor, 0x08, core::ptr::null_mut());
            cursor.add(0x43).write(0xa5);
            cursor.add(0x50).cast::<i32>().write(-1);
            read_btree.add(0x08).write(1);

            btree_trip_write_cursors(database);

            assert_eq!(cursor.add(0x43).read(), 3);
            assert_eq!(cursor.add(0x50).cast::<i32>().read(), SQLITE_ABORT);
            assert_eq!(read_btree.add(0x08).read(), 1);
        }
    }

    #[test]
    fn nonpositive_database_count_never_reads_database_array() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(database) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_trip_write_cursors"));
            return;
        };
        unsafe {
            set_pointer(database, DATABASES_OFFSET, 1usize as *mut u8);
            for count in [0i32, -1, i32::MIN] {
                database.add(DATABASE_COUNT_OFFSET).cast::<i32>().write(count);
                btree_trip_write_cursors(database);
            }
        }
    }
}
