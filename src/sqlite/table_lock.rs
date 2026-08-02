//! The parse context's shared-cache table-lock list.
//!
//! - `vdbe_add_table_lock` — original: `FUN_08385084` @ 0x08385084
//!   (176 bytes, 0x08385084..0x08385133 in the raw image).
//!   SQLite's `sqlite3TableLock`.
//!
//! While the code generator walks a statement it records every
//! (database, root page) pair the statement will touch, so that the VDBE
//! prologue can emit an `OP_TableLock` per entry before any cursor is
//! opened. The list is a flat, unsorted `TableLock[]` hanging off the
//! parse context and grown one element at a time; duplicates are folded
//! on insertion instead of at emit time, and a read lock already present
//! is promoted to a write lock in place.
//!
//! The only early-out is a negative database index — the sentinel the
//! code generator passes for "no database", e.g. an ephemeral or
//! transient table. There is no shared-cache feature test here: this
//! build compiled `SQLITE_OMIT_SHARED_CACHE` off, so the bookkeeping runs
//! unconditionally.
//!
//! Deliberate deviations from the original instruction stream:
//!
//! - The growth request is `(count + 1) * size_of::<TableLock>()` rather
//!   than the original's literal `lsl #4`. The two are the same on the
//!   32-bit target (statically asserted below); on a 64-bit test host the
//!   struct widens and the request widens with it, which is what keeps
//!   the fixtures honest.
//! - `Parse` and `TableLock` are typed `#[repr(C)]` records rather than
//!   raw byte offsets, so the pointer fields cannot overlap on a 64-bit
//!   host. The original offsets are asserted on the 32-bit target.
//! - The explicit `db->mallocFailed = 1` on the failure path is kept even
//!   though [`db_realloc_or_free`] has already set it. It is what the
//!   original writes, and it is what makes the failure path correct if
//!   the allocator seam is ever rewired.

use crate::sqlite::mem::{db_realloc_or_free, set_malloc_failed};

/// One entry of the parse context's lock list (SQLite's `TableLock`).
///
/// 16 bytes on target: two words, the write flag, three bytes of
/// padding, then the borrowed table name.
#[repr(C)]
pub struct TableLock {
    /// +0x00: index of the attached database holding the table.
    pub i_db: i32,
    /// +0x04: root page of the table being locked.
    pub i_tab: i32,
    /// +0x08: non-zero when a write lock is required.
    pub is_write_lock: u8,
    /// +0x09..+0x0c: padding ahead of the name pointer.
    pub _pad_09: [u8; 3],
    /// +0x0c: table name, borrowed from the schema for error messages.
    pub z_name: *const u8,
}

/// The fields of SQLite's `Parse` this helper touches. The unmodeled
/// +0x04..+0x13b span keeps the lock list at its recovered offsets.
#[repr(C)]
pub struct Parse {
    /// +0x000: the owning connection (`sqlite3 *`).
    pub db: *mut u8,
    /// +0x004..+0x13c: unmodeled.
    pub _gap_04: [u8; 0x13c - 0x04],
    /// +0x13c: number of entries in [`Parse::a_table_lock`].
    pub n_table_lock: i32,
    /// +0x140: the lock list, heap-owned by the parse context.
    pub a_table_lock: *mut TableLock,
}

// The original's layout, asserted on the 32-bit target. On a 64-bit host
// the pointer fields widen and these shift — harmless, because every
// access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<TableLock>() == 0x10);
    assert!(core::mem::offset_of!(TableLock, is_write_lock) == 0x08);
    assert!(core::mem::offset_of!(TableLock, z_name) == 0x0c);
    assert!(core::mem::offset_of!(Parse, n_table_lock) == 0x13c);
    assert!(core::mem::offset_of!(Parse, a_table_lock) == 0x140);
};

/// vdbe_add_table_lock — original: `FUN_08385084` @ 0x08385084
/// (176 bytes; 6 `bl` call sites).
///
/// `sqlite3TableLock`: record that the statement being compiled needs a
/// lock on root page `table_index` of database `database_index`.
///
/// A negative `database_index` is ignored. An entry for the same
/// (database, root page) pair already in the list is not duplicated —
/// its flag becomes the boolean OR of the old flag and `is_write_lock`,
/// so a read lock can be promoted but never demoted. Otherwise the list
/// is grown by one element through [`db_realloc_or_free`] and the entry
/// appended; `table_name` is borrowed, not copied.
///
/// Note the asymmetry the original has and this port preserves: the
/// in-place update *normalizes* the flag to 0 or 1, while a freshly
/// appended entry stores the low byte of `is_write_lock` verbatim
/// (`strb`). Every call site passes 0 or 1, so the two agree in practice.
///
/// On allocation failure the list pointer is cleared, the count is reset
/// to zero — the whole list is discarded, since the old block has been
/// freed — and `db->mallocFailed` is set.
///
/// # Safety
/// `parse` must point to a writable recovered `Parse` whose `db` names a
/// live connection and whose `a_table_lock` names `n_table_lock` valid
/// [`TableLock`] records (or is NULL when the count is zero).
/// `table_name` must outlive the parse context.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_add_table_lock(
    parse: *mut Parse,
    database_index: i32,
    table_index: i32,
    is_write_lock: i32,
    table_name: *const u8,
) {
    if database_index < 0 {
        return;
    }

    let locks = (*parse).a_table_lock;
    let count = (*parse).n_table_lock;
    for index in 0..count {
        let lock = locks.offset(index as isize);
        if (*lock).i_db == database_index && (*lock).i_tab == table_index {
            (*lock).is_write_lock = ((*lock).is_write_lock as i32 | is_write_lock != 0) as u8;
            return;
        }
    }

    let bytes = count.wrapping_add(1).wrapping_mul(core::mem::size_of::<TableLock>() as i32);
    let grown = db_realloc_or_free((*parse).db, locks as *mut u8, bytes) as *mut TableLock;
    (*parse).a_table_lock = grown;
    if grown.is_null() {
        (*parse).n_table_lock = 0;
        set_malloc_failed((*parse).db);
        return;
    }

    let slot = (*parse).n_table_lock;
    (*parse).n_table_lock = slot.wrapping_add(1);
    let lock = grown.offset(slot as isize);
    (*lock).i_db = database_index;
    (*lock).i_tab = table_index;
    (*lock).is_write_lock = is_write_lock as u8;
    (*lock).z_name = table_name;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log, Connection};
    use std::vec::Vec;

    const ENTRY: i32 = core::mem::size_of::<TableLock>() as i32;

    fn empty_lock() -> TableLock {
        TableLock {
            i_db: -0x5a5a,
            i_tab: -0x5a5a,
            is_write_lock: 0xa5,
            _pad_09: [0xa5; 3],
            z_name: core::ptr::null(),
        }
    }

    /// A parse context whose lock list lives in a fixed-capacity buffer,
    /// so the recording allocator can hand the same block back and the
    /// existing entries survive the "resize" the way a real realloc
    /// leaves them.
    struct Context {
        parse: Parse,
        table: Vec<TableLock>,
    }

    impl Context {
        fn new(capacity: usize) -> Self {
            let mut table = Vec::new();
            for _ in 0..capacity {
                table.push(empty_lock());
            }
            let parse = Parse {
                db: core::ptr::null_mut(),
                _gap_04: [0; 0x13c - 0x04],
                n_table_lock: 0,
                a_table_lock: core::ptr::null_mut(),
            };
            Context { parse, table }
        }

        /// Seeds the first `locks.len()` slots and points the context at
        /// the buffer.
        fn seed(&mut self, db: *mut u8, locks: &[(i32, i32, u8)]) {
            for (slot, &(i_db, i_tab, is_write_lock)) in locks.iter().enumerate() {
                self.table[slot] =
                    TableLock { i_db, i_tab, is_write_lock, _pad_09: [0; 3], z_name: b"seed\0".as_ptr() };
            }
            self.parse.db = db;
            self.parse.n_table_lock = locks.len() as i32;
            self.parse.a_table_lock = self.table.as_mut_ptr();
        }

        fn detach(&mut self, db: *mut u8) {
            self.parse.db = db;
            self.parse.n_table_lock = 0;
            self.parse.a_table_lock = core::ptr::null_mut();
        }

        fn buffer(&mut self) -> *mut TableLock {
            self.table.as_mut_ptr()
        }

        fn ptr(&mut self) -> *mut Parse {
            &mut self.parse
        }

        fn entry(&self, slot: usize) -> &TableLock {
            &self.table[slot]
        }
    }

    #[test]
    fn a_negative_database_index_is_ignored() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut db = Connection::healthy();
        let mut ctx = Context::new(4);
        ctx.detach(db.ptr());

        unsafe { vdbe_add_table_lock(ctx.ptr(), -1, 3, 1, b"t\0".as_ptr()) };

        assert!(realloc_log().is_empty(), "the sentinel never reaches the allocator");
        assert_eq!(ctx.parse.n_table_lock, 0);
        assert!(ctx.parse.a_table_lock.is_null());
        assert_eq!(db.failed_flag(), 0);
    }

    #[test]
    fn the_first_lock_grows_the_list_from_nothing() {
        let mut ctx = Context::new(4);
        let block = ctx.buffer();
        let _guard = install_recorder(block.cast());
        let mut db = Connection::healthy();
        ctx.detach(db.ptr());
        let name = b"artist\0".as_ptr();

        unsafe { vdbe_add_table_lock(ctx.ptr(), 1, 42, 1, name) };

        assert_eq!(realloc_log(), [(0usize, ENTRY)], "one element, from a NULL list");
        assert_eq!(ctx.parse.a_table_lock, block);
        assert_eq!(ctx.parse.n_table_lock, 1);
        let entry = ctx.entry(0);
        assert_eq!((entry.i_db, entry.i_tab, entry.is_write_lock), (1, 42, 1));
        assert_eq!(entry.z_name, name, "the name is borrowed, not copied");
    }

    #[test]
    fn distinct_pairs_append_and_the_list_grows_one_element_at_a_time() {
        let mut ctx = Context::new(4);
        let block = ctx.buffer();
        let _guard = install_recorder(block.cast());
        let mut db = Connection::healthy();
        ctx.detach(db.ptr());

        unsafe { vdbe_add_table_lock(ctx.ptr(), 0, 1, 1, b"a\0".as_ptr()) };
        unsafe { vdbe_add_table_lock(ctx.ptr(), 0, 2, 0, b"b\0".as_ptr()) };
        unsafe { vdbe_add_table_lock(ctx.ptr(), 1, 1, 0, b"c\0".as_ptr()) };

        assert_eq!(
            realloc_log(),
            [(0usize, ENTRY), (block as usize, 2 * ENTRY), (block as usize, 3 * ENTRY)],
            "each miss reallocates to exactly one more element"
        );
        assert_eq!(ctx.parse.n_table_lock, 3);
        assert_eq!((ctx.entry(0).i_db, ctx.entry(0).i_tab), (0, 1));
        assert_eq!((ctx.entry(1).i_db, ctx.entry(1).i_tab), (0, 2));
        assert_eq!((ctx.entry(2).i_db, ctx.entry(2).i_tab), (1, 1));
    }

    #[test]
    fn a_matching_pair_is_folded_in_place_and_never_reallocates() {
        let mut ctx = Context::new(4);
        let block = ctx.buffer();
        let _guard = install_recorder(block.cast());
        let mut db = Connection::healthy();
        ctx.seed(db.ptr(), &[(0, 1, 0), (2, 7, 0)]);

        unsafe { vdbe_add_table_lock(ctx.ptr(), 2, 7, 0, b"other\0".as_ptr()) };
        assert_eq!(ctx.entry(1).is_write_lock, 0, "a read lock stays a read lock");

        unsafe { vdbe_add_table_lock(ctx.ptr(), 2, 7, 1, b"other\0".as_ptr()) };
        assert_eq!(ctx.entry(1).is_write_lock, 1, "a read lock is promoted to a write lock");

        unsafe { vdbe_add_table_lock(ctx.ptr(), 2, 7, 0, b"other\0".as_ptr()) };
        assert_eq!(ctx.entry(1).is_write_lock, 1, "a write lock is never demoted");

        assert!(realloc_log().is_empty(), "a duplicate is folded, not appended");
        assert_eq!(ctx.parse.n_table_lock, 2);
        assert_eq!(ctx.entry(1).z_name, b"seed\0".as_ptr(), "the stored name is not replaced");
    }

    #[test]
    fn only_a_full_pair_match_folds() {
        let mut ctx = Context::new(4);
        let block = ctx.buffer();
        let _guard = install_recorder(block.cast());
        let mut db = Connection::healthy();
        ctx.seed(db.ptr(), &[(3, 9, 0)]);

        // Same database, different root page.
        unsafe { vdbe_add_table_lock(ctx.ptr(), 3, 10, 1, b"x\0".as_ptr()) };
        // Same root page, different database.
        unsafe { vdbe_add_table_lock(ctx.ptr(), 4, 9, 1, b"y\0".as_ptr()) };

        assert_eq!(ctx.parse.n_table_lock, 3);
        assert_eq!(ctx.entry(0).is_write_lock, 0, "the seed is untouched");
        assert_eq!((ctx.entry(1).i_db, ctx.entry(1).i_tab), (3, 10));
        assert_eq!((ctx.entry(2).i_db, ctx.entry(2).i_tab), (4, 9));
        assert_eq!(realloc_log(), [(block as usize, 2 * ENTRY), (block as usize, 3 * ENTRY)]);
    }

    #[test]
    fn the_appended_flag_is_truncated_while_the_folded_flag_is_normalized() {
        let mut ctx = Context::new(4);
        let block = ctx.buffer();
        let _guard = install_recorder(block.cast());
        let mut db = Connection::healthy();
        ctx.detach(db.ptr());

        // `strb` of a value whose low byte is zero appends a read lock...
        unsafe { vdbe_add_table_lock(ctx.ptr(), 0, 1, 0x100, b"a\0".as_ptr()) };
        assert_eq!(ctx.entry(0).is_write_lock, 0);

        // ...while the fold path tests the whole word and stores 1.
        unsafe { vdbe_add_table_lock(ctx.ptr(), 0, 1, 0x100, b"a\0".as_ptr()) };
        assert_eq!(ctx.entry(0).is_write_lock, 1);
    }

    /// A lock list shaped like a live tag-57 tracked block, so the
    /// `sqlite3_free` inside [`db_realloc_or_free`] can walk its header:
    /// the size cookie at +0, the padding word immediately below the
    /// payload, and a 16-byte-aligned payload.
    #[repr(C, align(16))]
    struct TrackedList([u8; 16 + 4 * 32]);

    impl TrackedList {
        fn new() -> Self {
            TrackedList([0; 16 + 4 * 32])
        }

        unsafe fn arm(&mut self) -> *mut TableLock {
            let block = self.0.as_mut_ptr();
            (block as *mut i32).write(4 * ENTRY);
            (block.add(12) as *mut u32).write(8);
            block.add(16).cast()
        }
    }

    #[test]
    fn allocation_failure_discards_a_populated_list_and_records_the_flag() {
        // Lock order matches `mem::tests::pressure()`: the allocator
        // slot first, then the mock heap the free path dispatches to.
        let _guard = install_recorder(core::ptr::null_mut());
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut db = Connection::healthy();
        let mut list = TrackedList::new();
        let mut ctx = Context::new(0);
        let block = unsafe { list.arm() };
        unsafe {
            block.write(TableLock { i_db: 0, i_tab: 1, is_write_lock: 1, _pad_09: [0; 3], z_name: core::ptr::null() });
            block.add(1).write(TableLock { i_db: 0, i_tab: 2, is_write_lock: 0, _pad_09: [0; 3], z_name: core::ptr::null() });
        }
        ctx.parse.db = db.ptr();
        ctx.parse.n_table_lock = 2;
        ctx.parse.a_table_lock = block;

        unsafe { vdbe_add_table_lock(ctx.ptr(), 5, 5, 1, b"z\0".as_ptr()) };

        assert_eq!(realloc_log(), [(block as usize, 3 * ENTRY)], "the growth was attempted");
        assert!(ctx.parse.a_table_lock.is_null(), "the freed block is not retained");
        assert_eq!(ctx.parse.n_table_lock, 0, "the whole list is discarded");
        assert_eq!(db.failed_flag(), 1);
    }

    #[test]
    fn an_already_failed_connection_never_reaches_the_allocator() {
        let mut ctx = Context::new(4);
        let block = ctx.buffer();
        let _guard = install_recorder(block.cast());
        let mut db = Connection::failed();
        ctx.detach(db.ptr());

        unsafe { vdbe_add_table_lock(ctx.ptr(), 0, 2, 1, b"z\0".as_ptr()) };

        assert!(realloc_log().is_empty(), "db_realloc short-circuits on a failed connection");
        assert!(ctx.parse.a_table_lock.is_null());
        assert_eq!(ctx.parse.n_table_lock, 0);
        assert_eq!(db.failed_flag(), 1);
    }
}
