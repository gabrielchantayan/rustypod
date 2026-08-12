//! The value constructor — how the engine creates a fresh NULL
//! `Mem`/`sqlite3_value`.
//!
//! - `sqlite_value_new` — original: `FUN_083866c0` @ 0x083866c0 (44
//!   bytes; 5 `bl` call sites, binary-scanned). Upstream SQLite 3.5.9's
//!   `sqlite3ValueNew` (`Mem *sqlite3ValueNew(sqlite3 *db)` in
//!   vdbemem.c).
//!
//! Algorithm: allocate a zeroed 0x28-byte `Mem` on the connection with
//! `sqlite3DbMallocZero` @ 0x08374998 (ported as
//! [`db_malloc_zero`](super::mem::db_malloc_zero), called directly) and
//! return NULL verbatim when it fails — the sticky
//! `db->mallocFailed` latch is the allocator's job, not this
//! function's, so the whole OOM contract is the NULL return. On
//! success stamp the value as a NULL datum: `flags = MEM_Null` (1) at
//! +0x1c (`strh`), `type = SQLITE_NULL` (5) at +0x1e (`strb`), and the
//! owning connection at +0x10; every other field stays zero from the
//! allocator's zero-fill. A NULL `db` is legal — `db_malloc_zero`
//! tolerates it (straight to the heap, nothing to latch) and the
//! back-pointer store simply lands NULL; FUN_0838fe88 relies on
//! exactly that.
//!
//! Call sites (binary-scanned):
//!
//! - 0x08376718 — `sqlite_error` (`sqlite/error.rs`): lazily creates
//!   the connection's cached error value `pErr`.
//! - 0x08386578 and 0x08386640 — FUN_08386524 (408 bytes): formats a
//!   message into a fresh value and installs it with
//!   `sqlite3ValueSetStr` @ 0x083866ec; on a NULL here it latches
//!   `db->mallocFailed` itself, frees through `sqlite3ValueFree` @
//!   0x08386504, and returns SQLITE_NOMEM (7).
//! - 0x082bea64 — FUN_082be9e8 (232 bytes): a user-function result
//!   bridge — when the callback word at +0xc0 is set it builds a fresh
//!   value, fills it with `sqlite3ValueSetStr`, converts it with
//!   `sqlite3ValueText` @ 0x08386718, hands the text to the callback,
//!   and frees the value.
//! - 0x0838fe98 — FUN_0838fe88 (120 bytes): the only caller passing
//!   db == NULL.
//!
//! `Mem` fields pinned by the `strhne/strbne/strne` triple (matches the
//! layout `sqlite/mem_release.rs` documents):
//!
//! ```text
//! +0x10 db      *mut sqlite3   owning connection (NULL allowed)
//! +0x1c flags   u16            MEM_Null = 0x1
//! +0x1e type    u8             SQLITE_NULL = 5
//! ```
//!
//! Deviations:
//! - The allocator *is* ported and is called directly, per the porting
//!   rules; there is no dispatch seam in this file.
//! - This port is the shipped default of the `SQLITE_VALUE_NEW`
//!   dispatch slot in `sqlite/error.rs` (that module's documented
//!   "the real port should replace this default when it lands"
//!   pattern — the same swap `sqlite/expr_new.rs` made when
//!   `sqlite/expr_delete.rs` landed); the slot stays so host tests can
//!   install recording mocks, and the old OOM-shaped stub is retained
//!   there for them.

use super::mem::db_malloc_zero;

/// `sizeof(Mem)` in the original (`mov r1,#0x28`).
pub const MEM_SIZE: i32 = 0x28;

/// Byte offset of `Mem.db` (original: `strne r4,[r0,#0x10]`).
pub const MEM_DB_OFFSET: usize = 0x10;

/// Byte offset of `Mem.flags` (original: `strhne r1,[r0,#0x1c]`).
pub const MEM_FLAGS_OFFSET: usize = 0x1c;

/// Byte offset of `Mem.type` (original: `strbne r1,[r0,#0x1e]`).
pub const MEM_TYPE_OFFSET: usize = 0x1e;

/// The `MEM_Null` flag stamped into `Mem.flags` (original:
/// `movne r1,#0x1`).
pub const MEM_NULL: u16 = 0x1;

/// The `SQLITE_NULL` type tag stamped into `Mem.type` (original:
/// `movne r1,#0x5`).
pub const SQLITE_NULL: u8 = 5;

/// sqlite_value_new — original: `FUN_083866c0` @ 0x083866c0 (44 bytes).
///
/// `sqlite3ValueNew`: allocate a zeroed `Mem` on connection `db` and
/// initialize it as a NULL value owned by `db`. Returns NULL on
/// allocation failure (with `db->mallocFailed` latched by the
/// allocator when `db` is non-NULL).
///
/// Register usage: r0 = db (saved in r4), r1 = 0x28 for the `bl
/// 0x08374998`, r0 = the new value (or NULL) on return.
///
/// # Safety
/// When `db` is non-NULL it must name a live `sqlite3` connection
/// (its `mallocFailed` byte at +0x1e is read, and written on failure).
/// The returned pointer names a 0x28-byte block owned by the caller.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_value_new(db: *mut u8) -> *mut u8 {
    let value = db_malloc_zero(db, MEM_SIZE);
    if !value.is_null() {
        (value.add(MEM_FLAGS_OFFSET) as *mut u16).write(MEM_NULL);
        (value.add(MEM_TYPE_OFFSET) as *mut u8).write(SQLITE_NULL);
        (value.add(MEM_DB_OFFSET) as *mut *mut u8).write(db);
    }
    value
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::mem::tests::{install_recorder, realloc_log, Connection};
    use super::super::mem::{DB_MEM_OPS, DEFAULT_DB_MEM_OPS};
    use super::*;
    use std::vec::Vec;

    /// Aligned stand-in for a heap `Mem`, seeded so the zero-fill is
    /// observable.
    #[repr(align(8))]
    struct MemBlock([u8; MEM_SIZE as usize]);

    /// Restore the real allocator slots while the OPS_LOCK guard is
    /// still held (the `sqlite/parse_expr.rs` convention).
    unsafe fn restore_allocator() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
    }

    /// Independent reference model of the original: zero the block,
    /// then flags = MEM_Null, type = SQLITE_NULL, db = the connection.
    fn reference_value_new(seed: &[u8; MEM_SIZE as usize], db: *mut u8) -> Vec<u8> {
        let _ = seed; // the zero-fill erases the seed; kept to mirror the port's input
        let mut model = std::vec![0u8; MEM_SIZE as usize];
        model[MEM_FLAGS_OFFSET..MEM_FLAGS_OFFSET + 2].copy_from_slice(&MEM_NULL.to_ne_bytes());
        model[MEM_TYPE_OFFSET] = SQLITE_NULL;
        let db_bytes = (db as usize).to_ne_bytes();
        model[MEM_DB_OFFSET..MEM_DB_OFFSET + db_bytes.len()].copy_from_slice(&db_bytes);
        model
    }

    #[test]
    fn a_successful_allocation_stamps_the_null_value_shape() {
        for seed in [0x00u8, 0xa5, 0xff, 0x5a] {
            let mut block = MemBlock([seed; MEM_SIZE as usize]);
            let guard = install_recorder(block.0.as_mut_ptr());
            let mut db = Connection::healthy();
            let db_ptr = db.ptr();
            unsafe {
                let value = sqlite_value_new(db_ptr);
                assert_eq!(value, block.0.as_mut_ptr(), "seed {seed:#04x}");
                assert_eq!(realloc_log(), std::vec![(0, MEM_SIZE)], "one 0x28-byte allocation");
                assert_eq!((value.add(MEM_FLAGS_OFFSET) as *const u16).read(), MEM_NULL);
                assert_eq!(value.add(MEM_TYPE_OFFSET).read(), SQLITE_NULL);
                assert_eq!((value.add(MEM_DB_OFFSET) as *const *mut u8).read(), db_ptr);
                assert_eq!(
                    block.0.to_vec(),
                    reference_value_new(&[seed; MEM_SIZE as usize], db_ptr),
                    "whole block matches the reference model (seed {seed:#04x})",
                );
                assert_eq!(db.failed_flag(), 0, "no failure is latched on success");
                restore_allocator();
            }
            drop(guard);
        }
    }

    #[test]
    fn an_allocation_failure_returns_null_and_latches_malloc_failed() {
        let guard = install_recorder(core::ptr::null_mut());
        let mut db = Connection::healthy();
        unsafe {
            assert!(sqlite_value_new(db.ptr()).is_null());
            assert_eq!(realloc_log(), std::vec![(0, MEM_SIZE)], "the heap was tried once");
            assert_eq!(db.failed_flag(), 1, "the allocator latches the sticky OOM byte");
            restore_allocator();
        }
        drop(guard);
    }

    #[test]
    fn an_already_failed_connection_short_circuits_the_heap() {
        let mut block = MemBlock([0xa5; MEM_SIZE as usize]);
        let guard = install_recorder(block.0.as_mut_ptr());
        let mut db = Connection::failed();
        unsafe {
            assert!(sqlite_value_new(db.ptr()).is_null());
            assert!(realloc_log().is_empty(), "the heap must not be touched");
            assert_eq!(db.failed_flag(), 1);
            restore_allocator();
        }
        drop(guard);
    }

    #[test]
    fn a_null_connection_gets_a_value_with_a_null_back_pointer() {
        let mut block = MemBlock([0xff; MEM_SIZE as usize]);
        let guard = install_recorder(block.0.as_mut_ptr());
        unsafe {
            let value = sqlite_value_new(core::ptr::null_mut());
            assert_eq!(value, block.0.as_mut_ptr(), "db == NULL goes straight to the heap");
            assert_eq!(realloc_log(), std::vec![(0, MEM_SIZE)]);
            assert_eq!(
                (value.add(MEM_DB_OFFSET) as *const *mut u8).read(),
                core::ptr::null_mut(),
                "the back-pointer store lands NULL",
            );
            assert_eq!((value.add(MEM_FLAGS_OFFSET) as *const u16).read(), MEM_NULL);
            assert_eq!(value.add(MEM_TYPE_OFFSET).read(), SQLITE_NULL);
            restore_allocator();
        }
        drop(guard);
    }

    #[test]
    fn a_null_connection_with_a_down_heap_fails_without_anything_to_latch() {
        let guard = install_recorder(core::ptr::null_mut());
        unsafe {
            assert!(sqlite_value_new(core::ptr::null_mut()).is_null());
            assert_eq!(
                realloc_log(),
                std::vec![(0, MEM_SIZE)],
                "no short-circuit: there is no connection flag to consult",
            );
            restore_allocator();
        }
        drop(guard);
    }
}
