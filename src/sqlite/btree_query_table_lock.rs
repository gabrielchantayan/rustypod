//! Check whether a shared-cache table lock can be acquired — retailOS
//! `FUN_082e8980` at `0x082e8980` (136 bytes; 3 direct plain-`bl` callers,
//! no predicated callers).
//!
//! Raw ARM starts at `0x082e8980` and ends with `bx lr` at `0x082e8a04`; the
//! independent table-lock routine begins at `0x082e8a08`. It has no outgoing
//! `bl` or predicated-`bl` instructions. SQLite's `queryTableLock` rejects a
//! sharable handle if another connection owns the shared cache, then scans the
//! table-lock list when the transaction flags or requested lock require it.
//! A matching existing read lock is compatible; every other matching lock is
//! `SQLITE_LOCKED` (6). Deliberate deviation: none; target-width pointers are
//! read as u32 words so target field offsets remain exact on host fixtures.

const BTREE_PBT: usize = 0x00;
const BTREE_SHARED: usize = 0x04;
const BTREE_SHARABLE: usize = 0x09;
const BTSHARED_TABLE_LOCKS: usize = 0x58;
const BTSHARED_OWNER: usize = 0x5c;
const BTREE_TRANS_FLAGS: usize = 0x0c;
const TABLE_LOCK_BTREE: usize = 0x00;
const TABLE_LOCK_ROOT_PAGE: usize = 0x04;
const TABLE_LOCK_KIND: usize = 0x08;
const TABLE_LOCK_NEXT: usize = 0x0c;
const TRANS_WRITE: u32 = 0x4000;
const SQLITE_LOCKED: u32 = 6;

#[inline(always)]
unsafe fn target_pointer(at: *const u8) -> *mut u8 {
    at.cast::<u32>().read() as usize as *mut u8
}

/// `sqlite3BtreeQueryTableLock` — original: `FUN_082e8980` @ `0x082e8980`
/// (136 bytes; 3 direct plain-`bl` callers, 0 predicated).
///
/// Returns `SQLITE_LOCKED` when a sharable B-tree's shared cache is owned by
/// another connection or already has an incompatible lock on `root_page`.
/// `btree` and its target-layout pointer fields must be valid whenever the raw
/// ARM dereferences them; there are no NULL guards beyond those in the body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_query_table_lock(
    btree: *mut u8,
    root_page: u32,
    lock_kind: u32,
) -> u32 {
    let shared = target_pointer(btree.add(BTREE_SHARED));
    if btree.add(BTREE_SHARABLE).read() == 0 {
        return 0;
    }
    let owner = target_pointer(shared.add(BTSHARED_OWNER));
    if !owner.is_null() && owner != btree {
        return SQLITE_LOCKED;
    }

    let pager = target_pointer(btree.add(BTREE_PBT));
    let flags = if pager.is_null() {
        0
    } else {
        pager.add(BTREE_TRANS_FLAGS).cast::<u32>().read()
    };
    if !pager.is_null() && flags & TRANS_WRITE != 0 && lock_kind != 2 && root_page != 1 {
        return 0;
    }

    let mut table_lock = target_pointer(shared.add(BTSHARED_TABLE_LOCKS));
    while !table_lock.is_null() {
        if target_pointer(table_lock.add(TABLE_LOCK_BTREE)) != btree
            && table_lock.add(TABLE_LOCK_ROOT_PAGE).cast::<u32>().read() == root_page
            && (u32::from(table_lock.add(TABLE_LOCK_KIND).read()) != lock_kind || lock_kind != 1)
        {
            return SQLITE_LOCKED;
        }
        table_lock = target_pointer(table_lock.add(TABLE_LOCK_NEXT));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const BTREE: usize = 0x000;
    const SHARED: usize = 0x100;
    const PAGER: usize = 0x200;
    const OTHER_BTREE: usize = 0x300;
    const LOCK: usize = 0x400;

    unsafe fn word(base: *mut u8, offset: usize, value: *mut u8) {
        base.add(offset).cast::<u32>().write(value as usize as u32);
    }

    #[test]
    fn query_table_lock_preserves_owner_transaction_and_lock_compatibility() {
        let Some(base) = try_map_u32_slab(hints::SQLITE_BTREE_QUERY_TABLE_LOCK, SLAB_LEN) else {
            assert!(note_missing_u32_fixture("sqlite/btree_query_table_lock"));
            return;
        };
        unsafe {
            let btree = base.add(BTREE);
            let shared = base.add(SHARED);
            let pager = base.add(PAGER);
            let other_btree = base.add(OTHER_BTREE);
            let table_lock = base.add(LOCK);
            word(base, BTREE + BTREE_SHARED, shared);
            word(base, BTREE + BTREE_PBT, pager);
            btree.add(BTREE_SHARABLE).write(0);
            assert_eq!(btree_query_table_lock(btree, 7, 2), 0);

            btree.add(BTREE_SHARABLE).write(1);
            word(base, SHARED + BTSHARED_OWNER, other_btree);
            assert_eq!(btree_query_table_lock(btree, 7, 1), SQLITE_LOCKED);
            word(base, SHARED + BTSHARED_OWNER, btree);

            pager.add(BTREE_TRANS_FLAGS).cast::<u32>().write(TRANS_WRITE);
            word(base, SHARED + BTSHARED_TABLE_LOCKS, table_lock);
            word(base, LOCK + TABLE_LOCK_BTREE, other_btree);
            table_lock.add(TABLE_LOCK_ROOT_PAGE).cast::<u32>().write(7);
            table_lock.add(TABLE_LOCK_KIND).write(2);
            assert_eq!(btree_query_table_lock(btree, 7, 1), 0);
            table_lock.add(TABLE_LOCK_ROOT_PAGE).cast::<u32>().write(1);
            assert_eq!(btree_query_table_lock(btree, 1, 1), SQLITE_LOCKED);

            pager.add(BTREE_TRANS_FLAGS).cast::<u32>().write(0);
            table_lock.add(TABLE_LOCK_ROOT_PAGE).cast::<u32>().write(7);
            table_lock.add(TABLE_LOCK_KIND).write(1);
            assert_eq!(btree_query_table_lock(btree, 7, 1), 0);
            table_lock.add(TABLE_LOCK_KIND).write(2);
            assert_eq!(btree_query_table_lock(btree, 7, 1), SQLITE_LOCKED);
        }
    }
}
