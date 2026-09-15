//! Checking whether another cursor holds a conflicting SQLite read lock.
//!
//! `check_read_locks` — original: `FUN_082c28a0` @ 0x082c28a0 (152 bytes,
//! `0x082c28a0..0x082c2934`). Decoding every ARM B/BL-immediate word in
//! `osos.dec` finds five inbound direct calls, all unconditional `bl`, at
//! 0x082bdbd8, 0x083709d4, 0x08370f50, 0x08371654, and 0x08372a90; no
//! predicated inbound call. Its sole outbound call is caller-gated `blne`
//! to `btree_move_to_root` @ 0x082d9b00.
//!
//! This is SQLite 3.5.x `checkReadLocks`: scan the shared b-tree's cursor
//! chain for another valid cursor on `root_page`. A read cursor conflicts
//! when it belongs to the same database, or its database has not enabled
//! `SQLITE_ReadUncommitted`; a write cursor on a different page is reset to
//! its root. Deliberate deviation: target-layout pointers remain `u32` words
//! rather than host pointers, so the ARM offsets remain valid on 64-bit hosts.

use crate::sqlite::move_to_root::btree_move_to_root;

const BTREE_DB: usize = 0x00;
const BTREE_SHARED: usize = 0x04;
const SHARED_CURSOR: usize = 0x08;
const DB_FLAGS: usize = 0x0c;
const CURSOR_BTREE: usize = 0x00;
const CURSOR_NEXT: usize = 0x08;
const CURSOR_ROOT_PAGE: usize = 0x14;
const CURSOR_PAGE: usize = 0x18;
const CURSOR_WRITE_FLAG: usize = 0x40;
const CURSOR_STATE: usize = 0x43;
const PAGE_NUMBER: usize = 0x4c;
const CURSOR_VALID: u8 = 1;
const SQLITE_READ_UNCOMMITTED: u32 = 0x4000;
const SQLITE_LOCKED: i32 = 6;

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(base.add(offset).cast::<u32>().read())
}

/// `check_read_locks` — original: `FUN_082c28a0` @ 0x082c28a0 (152 bytes;
/// five verified unconditional inbound `bl` calls).
///
/// Scan `btree`'s shared cursor list for valid cursors on `root_page`, excluding
/// `exclude`. Returns `SQLITE_LOCKED` when a conflicting read cursor exists;
/// otherwise resets displaced write cursors and returns zero. All pointers must
/// satisfy the retail target's layout and non-null invariants.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn check_read_locks(btree: *mut u8, root_page: u32, exclude: *mut u8) -> i32 {
    let db = read_u32(btree, BTREE_DB);
    let shared = read_u32(btree, BTREE_SHARED) as usize as *mut u8;
    let mut cursor = read_u32(shared, SHARED_CURSOR) as usize as *mut u8;

    while !cursor.is_null() {
        if cursor != exclude
            && cursor.add(CURSOR_STATE).read() == CURSOR_VALID
            && read_u32(cursor, CURSOR_ROOT_PAGE) == root_page
        {
            if cursor.add(CURSOR_WRITE_FLAG).read() == 0 {
                let cursor_btree = read_u32(cursor, CURSOR_BTREE) as usize as *mut u8;
                let cursor_db = read_u32(cursor_btree, BTREE_DB);
                if cursor_db == db || read_u32(cursor_db as usize as *const u8, DB_FLAGS) & SQLITE_READ_UNCOMMITTED == 0 {
                    return SQLITE_LOCKED;
                }
            } else {
                let page = read_u32(cursor, CURSOR_PAGE) as usize as *mut u8;
                if read_u32(page, PAGE_NUMBER) != root_page {
                    btree_move_to_root(cursor);
                }
            }
        }
        cursor = read_u32(cursor, CURSOR_NEXT) as usize as *mut u8;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_CHECK_READ_LOCKS, FIXTURE_LEN).map(|p| p as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn put_word(base: *mut u8, offset: usize, value: usize) {
        base.add(offset).cast::<u32>().write((value as u32).to_le());
    }

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8, *mut u8)> {
        let base = *FIXTURE.as_ref()? as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        let btree = base;
        let shared = base.add(0x100);
        let cursor = base.add(0x200);
        let other_btree = base.add(0x300);
        let other_db = base.add(0x400);
        put_word(btree, BTREE_DB, other_db as usize);
        put_word(btree, BTREE_SHARED, shared as usize);
        put_word(shared, SHARED_CURSOR, cursor as usize);
        put_word(cursor, CURSOR_BTREE, other_btree as usize);
        put_word(other_btree, BTREE_DB, other_db as usize);
        cursor.add(CURSOR_STATE).write(CURSOR_VALID);
        put_word(cursor, CURSOR_ROOT_PAGE, 7);
        Some((btree, cursor, other_btree, other_db, shared))
    }

    #[test]
    fn locks_same_database_read_cursor_but_excludes_requested_cursor() {
        let _guard = TEST_LOCK.lock();
        let Some((btree, cursor, _, _, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/check_read_locks"));
            return;
        };
        assert_eq!(unsafe { check_read_locks(btree, 7, core::ptr::null_mut()) }, SQLITE_LOCKED);
        assert_eq!(unsafe { check_read_locks(btree, 7, cursor) }, 0);
    }

    #[test]
    fn permits_read_uncommitted_cursor_from_another_database() {
        let _guard = TEST_LOCK.lock();
        let Some((btree, _, other_btree, other_db, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/check_read_locks"));
            return;
        };
        let current_db = unsafe { other_db.add(0x80) };
        unsafe {
            put_word(btree, BTREE_DB, current_db as usize);
            put_word(other_btree, BTREE_DB, other_db as usize);
            put_word(other_db, DB_FLAGS, SQLITE_READ_UNCOMMITTED as usize);
        }
        assert_eq!(unsafe { check_read_locks(btree, 7, core::ptr::null_mut()) }, 0);
    }
}
