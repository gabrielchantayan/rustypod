//! SQLite's shared-cache table-lock list.
//!
//! `btree_lock_table` — original: `FUN_082d8574` @ 0x082d8574 (184 bytes;
//! 1 unconditional plain `bl`, no predicated `bl`, verified from raw
//! `osos.dec`).
//!
//! `sqlite3BtreeLockTable` bypasses the lock list for non-sharable handles.
//! Its single-connection exclusive-mode exception also bypasses the list for
//! a write lock on table 1. Otherwise it finds (or allocates) the matching
//! 16-byte `BtLock`, links a new record at the shared object's head, and
//! raises its one-byte lock mode when the requested mode is greater.
//!
//! Deliberate deviation: the target's 32-bit `BtShared.pLock` and
//! `BtLock.pNext` fields remain u32 words, so host fixtures map below 4 GiB;
//! the allocation itself uses the existing `sqlite3_malloc_zero` port.

use super::mem::sqlite3_malloc_zero;

const BTREE_DATABASE_OFFSET: usize = 0x00;
const BTREE_SHARED_OFFSET: usize = 0x04;
const BTREE_SHARABLE_OFFSET: usize = 0x09;
const DATABASE_FLAGS_OFFSET: usize = 0x0c;
const DATABASE_EXCLUSIVE_FLAG: u32 = 0x4000;
const SHARED_LOCK_LIST_OFFSET: usize = 0x58;
const LOCK_BTREE_OFFSET: usize = 0x00;
const LOCK_TABLE_OFFSET: usize = 0x04;
const LOCK_MODE_OFFSET: usize = 0x08;
const LOCK_NEXT_OFFSET: usize = 0x0c;
const LOCK_SIZE: i32 = 0x10;
const SQLITE_NOMEM: u32 = 7;

#[inline(always)]
unsafe fn target_pointer(at: *const u8) -> *mut u8 {
    at.cast::<u32>().read() as usize as *mut u8
}

/// btree_lock_table — original: `FUN_082d8574` @ 0x082d8574 (184 bytes;
/// 1 unconditional plain `bl`, no predicated `bl`).
///
/// SQLite's `sqlite3BtreeLockTable`: retain the strongest requested lock for
/// `(btree, table)` in `BtShared.pLock`. The special exclusive-mode write lock
/// for schema table 1 needs no record. Returns `SQLITE_NOMEM` only when the
/// 16-byte zeroed lock allocation fails.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_lock_table(btree: *mut u8, table: u32, lock_mode: u32) -> u32 {
    if btree.add(BTREE_SHARABLE_OFFSET).read() == 0 {
        return 0;
    }

    let database = target_pointer(btree.add(BTREE_DATABASE_OFFSET));
    let is_exclusive = !database.is_null()
        && (database.add(DATABASE_FLAGS_OFFSET).cast::<u32>().read() & DATABASE_EXCLUSIVE_FLAG) != 0;
    if is_exclusive && lock_mode == 1 && table == 1 {
        return 0;
    }

    let shared = target_pointer(btree.add(BTREE_SHARED_OFFSET));
    let mut lock = target_pointer(shared.add(SHARED_LOCK_LIST_OFFSET));
    while !lock.is_null() {
        let lock_table = lock.add(LOCK_TABLE_OFFSET).cast::<u32>().read();
        let lock_btree = if lock_table == table {
            target_pointer(lock.add(LOCK_BTREE_OFFSET))
        } else {
            core::ptr::null_mut()
        };
        if lock_table == table && lock_btree == btree {
            break;
        }
        lock = target_pointer(lock.add(LOCK_NEXT_OFFSET));
    }

    if lock.is_null() {
        lock = sqlite3_malloc_zero(LOCK_SIZE);
        if lock.is_null() {
            return SQLITE_NOMEM;
        }
        lock.add(LOCK_BTREE_OFFSET).cast::<u32>().write(btree as usize as u32);
        lock.add(LOCK_TABLE_OFFSET).cast::<u32>().write(table);
        lock.add(LOCK_NEXT_OFFSET)
            .cast::<u32>()
            .write(target_pointer(shared.add(SHARED_LOCK_LIST_OFFSET)) as usize as u32);
        shared.add(SHARED_LOCK_LIST_OFFSET).cast::<u32>().write(lock as usize as u32);
    }

    if (lock.add(LOCK_MODE_OFFSET).read() as u32) < lock_mode {
        lock.add(LOCK_MODE_OFFSET).write(lock_mode as u8);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const BTREE_OFFSET: usize = 0x100;
    const SHARED_OFFSET: usize = 0x200;
    const DATABASE_OFFSET: usize = 0x300;
    const LOCK_OFFSET: usize = 0x400;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_LOCK_TABLE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8)> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0xa5, FIXTURE_LEN);
        let btree = base.add(BTREE_OFFSET);
        let shared = base.add(SHARED_OFFSET);
        let database = base.add(DATABASE_OFFSET);
        let lock = base.add(LOCK_OFFSET);
        btree.add(BTREE_DATABASE_OFFSET).cast::<u32>().write(database as usize as u32);
        btree.add(BTREE_SHARED_OFFSET).cast::<u32>().write(shared as usize as u32);
        btree.add(BTREE_SHARABLE_OFFSET).write(1);
        shared.add(SHARED_LOCK_LIST_OFFSET).cast::<u32>().write(0);
        Some((btree, shared, database, lock))
    }

    #[test]
    fn non_sharable_and_exclusive_schema_write_skip_allocation() {
        let _fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some((btree, _, database, _)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("btree_lock_table");
            return;
        };
        unsafe { btree.add(BTREE_SHARABLE_OFFSET).write(0) };
        assert_eq!(unsafe { btree_lock_table(btree, 9, 2) }, 0);

        unsafe {
            btree.add(BTREE_SHARABLE_OFFSET).write(1);
            database.add(DATABASE_FLAGS_OFFSET).cast::<u32>().write(DATABASE_EXCLUSIVE_FLAG);
        }
        assert_eq!(unsafe { btree_lock_table(btree, 1, 1) }, 0);
    }

    #[test]
    fn allocates_links_and_strengthens_matching_lock() {
        let _fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some((btree, shared, _, lock)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("btree_lock_table");
            return;
        };
        let _allocator_guard = install_recorder(lock);

        assert_eq!(unsafe { btree_lock_table(btree, 7, 1) }, 0);
        assert_eq!(realloc_log(), std::vec![(0, LOCK_SIZE)]);
        assert_eq!(unsafe { target_pointer(shared.add(SHARED_LOCK_LIST_OFFSET)) }, lock);
        assert_eq!(unsafe { target_pointer(lock.add(LOCK_BTREE_OFFSET)) }, btree);
        assert_eq!(unsafe { lock.add(LOCK_TABLE_OFFSET).cast::<u32>().read() }, 7);
        assert_eq!(unsafe { lock.add(LOCK_MODE_OFFSET).read() }, 1);

        assert_eq!(unsafe { btree_lock_table(btree, 7, 3) }, 0);
        assert_eq!(realloc_log(), std::vec![(0, LOCK_SIZE)]);
        assert_eq!(unsafe { lock.add(LOCK_MODE_OFFSET).read() }, 3);

        // The ARM `cmp` is full-width, followed by a byte store.
        assert_eq!(unsafe { btree_lock_table(btree, 7, 0x100) }, 0);
        assert_eq!(unsafe { lock.add(LOCK_MODE_OFFSET).read() }, 0);
        assert_eq!(unsafe { btree_lock_table(btree, 7, 1) }, 0);
        assert_eq!(unsafe { lock.add(LOCK_MODE_OFFSET).read() }, 1);
    }

    #[test]
    fn allocation_failure_returns_sqlite_nomem() {
        let _fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some((btree, _, _, _)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("btree_lock_table");
            return;
        };
        let _allocator_guard = install_recorder(core::ptr::null_mut());
        assert_eq!(unsafe { btree_lock_table(btree, 7, 1) }, SQLITE_NOMEM);
        assert_eq!(realloc_log(), std::vec![(0, LOCK_SIZE)]);
    }
}
