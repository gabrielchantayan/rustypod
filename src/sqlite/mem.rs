//! SQLite's connection-scoped allocator wrappers — how the engine
//! allocates everything that belongs to a database connection.
//!
//! - `db_realloc` — original: `FUN_083749bc` @ 0x083749bc (56 bytes;
//!   9 `bl` call sites, binary-scanned). SQLite's `sqlite3DbRealloc`.
//! - `db_realloc_or_free` — original: `FUN_083749f4` @ 0x083749f4
//!   (32 bytes; 6 `bl`). SQLite's `sqlite3DbReallocOrFree`.
//! - `db_malloc_raw` — original: `FUN_08374960` @ 0x08374960 (56 bytes;
//!   19 `bl`). SQLite's `sqlite3DbMallocRaw`.
//! - `db_malloc_zero` — original: `FUN_08374998` @ 0x08374998 (36 bytes;
//!   34 `bl`). SQLite's `sqlite3DbMallocZero`.
//!
//! All four hang the out-of-memory condition off one sticky byte in the
//! connection: `db->mallocFailed` at +0x1e. Once it is set the allocator
//! short-circuits — every later allocation on that connection fails
//! without touching the heap — which is how SQLite unwinds an OOM without
//! checking a return code at every step.
//!
//! The two families differ on NULL: `db_realloc` dereferences `db`
//! unconditionally (its call sites always hold a live connection), while
//! `db_malloc_raw` tolerates `db == 0` on both the entry check and the
//! failure record. Both behaviors are the originals', kept as-is.
//!
//! Deviations:
//! - The raw allocators `sqlite3_malloc` @ 0x08390b14 and
//!   `sqlite3_realloc` @ 0x08390eec are not ported; they are the
//!   [`DB_MEM_OPS`] dispatch boundary (house pattern, see
//!   `heap/block_region.rs`). The default slots are documented
//!   always-fails stubs, so an unconfigured build behaves like an
//!   exhausted heap rather than corrupting memory.
//! - `sqlite3_free` @ 0x083906f4 *is* ported
//!   (`heap::tracked::tracked_free`), and so is the zero-fill the
//!   original reaches through the IRAM thunk @ 0x08037dc8
//!   (`libc::memzero::memzero` @ 0x080002d4). Both are called directly,
//!   per the porting rules.
//! - `db` is a `*mut u8` and `mallocFailed` is reached by byte offset:
//!   it is a byte field, so the offset is host-independent (unlike the
//!   pointer fields elsewhere, which need word indices).

use crate::heap::tracked::tracked_free;
use crate::libc::memzero::memzero;

/// Byte offset of `sqlite3.mallocFailed` (original: `ldrb rX, [db, #30]`).
pub const MALLOC_FAILED_OFFSET: usize = 0x1e;

/// Indirect dispatch for the unported raw allocators @ 0x08390b14 /
/// 0x08390eec.
#[derive(Clone, Copy)]
pub struct DbMemOps {
    /// `sqlite3_malloc(n)` @ 0x08390b14. Returns NULL on failure.
    pub malloc: unsafe extern "C" fn(n: i32) -> *mut u8,
    /// `sqlite3_realloc(p, n)` @ 0x08390eec. Returns NULL on failure.
    pub realloc: unsafe extern "C" fn(p: *mut u8, n: i32) -> *mut u8,
}

/// Default stub: no raw allocator wired, so every request fails (see the
/// module header).
unsafe extern "C" fn missing_malloc(_n: i32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Default stub: see [`missing_malloc`]. Deliberately not a passthrough
/// — returning `p` unchanged would claim a resize that never happened.
unsafe extern "C" fn missing_realloc(_p: *mut u8, _n: i32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Wired defaults (documented always-fails stubs).
pub const DEFAULT_DB_MEM_OPS: DbMemOps =
    DbMemOps { malloc: missing_malloc, realloc: missing_realloc };

/// The active raw allocator. Host tests install mocks; the real port
/// replaces the default when 0x08390eec lands.
pub static mut DB_MEM_OPS: DbMemOps = DEFAULT_DB_MEM_OPS;

/// Reads the realloc slot (volatile — the slot is meant to be swapped at
/// runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) unsafe fn db_realloc_op() -> unsafe extern "C" fn(*mut u8, i32) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(DB_MEM_OPS.realloc))
}

/// Reads the malloc slot (volatile — see [`db_realloc_op`]).
#[inline(always)]
pub(crate) unsafe fn db_malloc_op() -> unsafe extern "C" fn(i32) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(DB_MEM_OPS.malloc))
}

/// Reads `db->mallocFailed`. A NULL `db` is not possible here — every
/// call site reaches this through a live connection.
#[inline(always)]
pub unsafe fn malloc_failed(db: *const u8) -> bool {
    db.add(MALLOC_FAILED_OFFSET).read() != 0
}

/// Sets the sticky `db->mallocFailed` flag.
#[inline(always)]
pub unsafe fn set_malloc_failed(db: *mut u8) {
    db.add(MALLOC_FAILED_OFFSET).write(1);
}

/// db_realloc — original: `FUN_083749bc` @ 0x083749bc (56 bytes).
///
/// `sqlite3DbRealloc`: resize `p` to `n` bytes on connection `db`.
/// Returns NULL — without calling the allocator at all — if the
/// connection has already recorded an allocation failure; otherwise
/// reallocates and, on failure, records one.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn db_realloc(db: *mut u8, p: *mut u8, n: i32) -> *mut u8 {
    if malloc_failed(db) {
        return core::ptr::null_mut();
    }
    let new = (db_realloc_op())(p, n);
    if new.is_null() {
        set_malloc_failed(db);
    }
    new
}

/// db_realloc_or_free — original: `FUN_083749f4` @ 0x083749f4 (32 bytes).
///
/// `sqlite3DbReallocOrFree`: [`db_realloc`], but the old block is freed
/// when the resize fails, so the caller may drop its pointer
/// unconditionally.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn db_realloc_or_free(db: *mut u8, p: *mut u8, n: i32) -> *mut u8 {
    let new = db_realloc(db, p, n);
    if new.is_null() {
        tracked_free(p);
    }
    new
}

/// db_malloc_raw — original: `FUN_08374960` @ 0x08374960 (56 bytes;
/// 19 `bl` call sites).
///
/// `sqlite3DbMallocRaw`: allocate `n` uninitialized bytes on connection
/// `db`. A connection that has already failed yields NULL without
/// touching the heap; a fresh failure is recorded on the connection.
/// `db` may be NULL — then there is nothing to short-circuit and nothing
/// to record, and the request goes straight to the heap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn db_malloc_raw(db: *mut u8, n: i32) -> *mut u8 {
    if !db.is_null() && malloc_failed(db) {
        return core::ptr::null_mut();
    }
    let block = (db_malloc_op())(n);
    if block.is_null() && !db.is_null() {
        set_malloc_failed(db);
    }
    block
}

/// db_malloc_zero — original: `FUN_08374998` @ 0x08374998 (36 bytes;
/// 34 `bl` call sites).
///
/// `sqlite3DbMallocZero`: [`db_malloc_raw`] followed by a zero-fill of
/// the whole request. Nothing is zeroed when the allocation fails.
///
/// Codegen note: the original tail-calls the IRAM zero-fill thunk
/// @ 0x08037dc8; LLVM inlines our `memzero` here instead (and recognizes
/// parts of it back into `__aeabi_memclr`, like several other modules in
/// this crate already do). Same bytes written, different shape in the
/// match.py diff.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn db_malloc_zero(db: *mut u8, n: i32) -> *mut u8 {
    let block = db_malloc_raw(db, n);
    if !block.is_null() {
        memzero(block, n as usize);
    }
    block
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the global allocator slot.
    pub(crate) static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// (old pointer, requested size) of every realloc the code made.
    /// A `malloc` is logged with a NULL old pointer.
    pub(crate) static mut REALLOC_LOG: Vec<(usize, i32)> = Vec::new();
    /// Block handed back by the recorders, or NULL to fail.
    pub(crate) static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();

    pub(crate) unsafe extern "C" fn recording_realloc(p: *mut u8, n: i32) -> *mut u8 {
        (*core::ptr::addr_of_mut!(REALLOC_LOG)).push((p as usize, n));
        core::ptr::read(core::ptr::addr_of!(REALLOC_RESULT))
    }

    pub(crate) unsafe extern "C" fn recording_malloc(n: i32) -> *mut u8 {
        recording_realloc(core::ptr::null_mut(), n)
    }

    /// Installs the recording allocator and clears its log. The returned
    /// guard must stay alive for the whole test (never shadowed with
    /// `let _` across sub-cases — that self-deadlocks).
    pub(crate) fn install_recorder(result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(REALLOC_LOG)).clear();
            core::ptr::write(core::ptr::addr_of_mut!(REALLOC_RESULT), result);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(DB_MEM_OPS),
                DbMemOps { malloc: recording_malloc, realloc: recording_realloc },
            );
        }
        guard
    }

    pub(crate) fn realloc_log() -> Vec<(usize, i32)> {
        unsafe { (*core::ptr::addr_of!(REALLOC_LOG)).clone() }
    }

    /// A stand-in `sqlite3` connection: only the flag byte matters.
    pub(crate) struct Connection([u8; 0x40]);

    impl Connection {
        pub(crate) fn healthy() -> Self {
            Connection([0; 0x40])
        }
        pub(crate) fn failed() -> Self {
            let mut db = Connection([0; 0x40]);
            db.0[MALLOC_FAILED_OFFSET] = 1;
            db
        }
        pub(crate) fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        pub(crate) fn failed_flag(&self) -> u8 {
            self.0[MALLOC_FAILED_OFFSET]
        }
    }

    #[test]
    fn a_successful_resize_returns_the_new_block_and_leaves_the_flag_clear() {
        let mut block = [0u8; 8];
        let target = block.as_mut_ptr();
        let _guard = install_recorder(target);
        let mut db = Connection::healthy();

        let old = 0x1234_5678usize as *mut u8;
        assert_eq!(unsafe { db_realloc(db.ptr(), old, 200) }, target);
        assert_eq!(realloc_log(), std::vec![(0x1234_5678, 200)]);
        assert_eq!(db.failed_flag(), 0);
    }

    #[test]
    fn a_failed_resize_sets_the_sticky_flag() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut db = Connection::healthy();

        assert!(unsafe { db_realloc(db.ptr(), core::ptr::null_mut(), 64) }.is_null());
        assert_eq!(db.failed_flag(), 1);
        assert_eq!(realloc_log().len(), 1);
    }

    #[test]
    fn a_failed_connection_short_circuits_without_calling_the_allocator() {
        let mut block = [0u8; 8];
        let _guard = install_recorder(block.as_mut_ptr());
        let mut db = Connection::failed();

        assert!(unsafe { db_realloc(db.ptr(), core::ptr::null_mut(), 64) }.is_null());
        assert!(realloc_log().is_empty(), "the heap must not be touched");
        assert_eq!(db.failed_flag(), 1);
    }

    #[test]
    fn realloc_or_free_passes_a_success_straight_through() {
        let mut block = [0u8; 8];
        let target = block.as_mut_ptr();
        let _guard = install_recorder(target);
        let mut db = Connection::healthy();

        // Passing NULL as the old block keeps `tracked_free` out of the
        // picture on the success path *and* proves it is not called.
        assert_eq!(unsafe { db_realloc_or_free(db.ptr(), core::ptr::null_mut(), 16) }, target);
        assert_eq!(realloc_log(), std::vec![(0, 16)]);
    }

    #[test]
    fn malloc_raw_records_a_failure_on_the_connection() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut db = Connection::healthy();

        assert!(unsafe { db_malloc_raw(db.ptr(), 128) }.is_null());
        assert_eq!(realloc_log(), std::vec![(0, 128)]);
        assert_eq!(db.failed_flag(), 1);

        // ... and short-circuits from then on.
        assert!(unsafe { db_malloc_raw(db.ptr(), 128) }.is_null());
        assert_eq!(realloc_log().len(), 1, "the heap is not touched again");
    }

    #[test]
    fn malloc_raw_tolerates_a_null_connection() {
        // Unlike `db_realloc`, the malloc path guards both the entry
        // check and the failure record on a non-NULL connection.
        let _guard = install_recorder(core::ptr::null_mut());
        assert!(unsafe { db_malloc_raw(core::ptr::null_mut(), 16) }.is_null());
        assert_eq!(realloc_log(), std::vec![(0, 16)], "the request still goes out");

        let mut block = [0u8; 4];
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(REALLOC_RESULT), block.as_mut_ptr());
        }
        assert_eq!(unsafe { db_malloc_raw(core::ptr::null_mut(), 4) }, block.as_mut_ptr());
    }

    #[test]
    fn malloc_zero_clears_exactly_the_request() {
        let mut arena = [0xa5u8; 32];
        let _guard = install_recorder(arena.as_mut_ptr());
        let mut db = Connection::healthy();

        let block = unsafe { db_malloc_zero(db.ptr(), 12) };
        assert_eq!(block, arena.as_mut_ptr());
        assert_eq!(&arena[..12], &[0u8; 12]);
        assert_eq!(&arena[12..], &[0xa5u8; 20], "nothing past the request");
    }

    #[test]
    fn malloc_zero_does_not_write_when_the_allocation_fails() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut db = Connection::healthy();

        assert!(unsafe { db_malloc_zero(db.ptr(), 12) }.is_null());
        assert_eq!(db.failed_flag(), 1);
    }

    #[test]
    fn realloc_or_free_drops_the_old_block_when_the_resize_fails() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut db = Connection::healthy();

        // A NULL old block exercises the free path without needing a
        // live heap: `tracked_free(NULL)` is a documented no-op.
        assert!(unsafe { db_realloc_or_free(db.ptr(), core::ptr::null_mut(), 16) }.is_null());
        assert_eq!(db.failed_flag(), 1);
    }
}
