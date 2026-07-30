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
//! - `sqlite3_realloc` — original: `FUN_08390eec` @ 0x08390eec (284
//!   bytes; 5 `bl`). SQLite's `sqlite3_realloc`, the raw tracked-heap
//!   resize the `db_*` wrappers dispatch to.
//!
//! The `db_*` four hang the out-of-memory condition off one sticky byte in the
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
//! - The raw allocator `sqlite3_malloc` @ 0x08390b14 is not ported; it
//!   is the [`DB_MEM_OPS`]`.malloc` dispatch boundary (house pattern,
//!   see `heap/block_region.rs`). The default slot is a documented
//!   always-fails stub, so an unconfigured build behaves like an
//!   exhausted heap rather than corrupting memory. `sqlite3_realloc`
//!   @ 0x08390eec *is* ported (below) and is the wired `.realloc`
//!   default; its NULL-pointer branch reaches the same stub through
//!   the malloc slot, exactly like the original's tail branch.
//! - `sqlite3_free` @ 0x083906f4 *is* ported
//!   (`heap::tracked::tracked_free`), and so is the zero-fill the
//!   original reaches through the IRAM thunk @ 0x08037dc8
//!   (`libc::memzero::memzero` @ 0x080002d4). Both are called directly,
//!   per the porting rules.
//! - `db` is a `*mut u8` and `mallocFailed` is reached by byte offset:
//!   it is a byte field, so the offset is host-independent (unlike the
//!   pointer fields elsewhere, which need word indices).

use crate::heap::tracked::{
    tracked_free, tracked_stats_warn_soft_limit, ALLOC_STATS, BLOCK_HEADER_SIZE, TAG_TRACKED,
};
use crate::heap::veneers::realloc_wrapper;
use crate::libc::memmove::memmove;
use crate::libc::memzero::memzero;

/// Byte offset of `sqlite3.mallocFailed` (original: `ldrb rX, [db, #30]`).
pub const MALLOC_FAILED_OFFSET: usize = 0x1e;

/// Indirect dispatch for the raw allocator @ 0x08390b14 (unported) and
/// the ported realloc @ 0x08390eec.
#[derive(Clone, Copy)]
pub struct DbMemOps {
    /// `sqlite3_malloc(n)` @ 0x08390b14. Returns NULL on failure.
    pub malloc: unsafe extern "C" fn(n: i32) -> *mut u8,
    /// `sqlite3_realloc(p, n)` @ 0x08390eec. Returns NULL on failure.
    /// The wired default is the ported [`sqlite3_realloc`].
    pub realloc: unsafe extern "C" fn(p: *mut u8, n: i32) -> *mut u8,
}

/// Default stub: no raw allocator wired, so every request fails (see the
/// module header).
unsafe extern "C" fn missing_malloc(_n: i32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Wired defaults: the malloc slot is the documented always-fails stub
/// (the entry @ 0x08390b14 is still unported); the realloc slot is the
/// ported [`sqlite3_realloc`], whose NULL-pointer branch reaches the
/// same stub through the malloc slot — an unconfigured build still
/// behaves like an exhausted heap for fresh allocations.
pub const DEFAULT_DB_MEM_OPS: DbMemOps =
    DbMemOps { malloc: missing_malloc, realloc: sqlite3_realloc };

/// The active raw allocator. Host tests install mocks; on target the
/// realloc slot is the real port and the malloc slot stays a stub until
/// 0x08390b14 lands.
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

/// Indirect dispatch for the memory-pressure helper [`sqlite3_realloc`]
/// shares with the malloc entry @ 0x08390b14 that is still unported
/// (house ops-slot pattern: an indirect call in place of the original's
/// `bl`, so host tests can record and swap). The default reproduces the
/// original's at-rest behavior (see the slot). The family's other
/// pressure helper — the soft-limit warn @ 0x0837d67c — is ported
/// ([`tracked_stats_warn_soft_limit`]) and called directly.
#[derive(Clone, Copy)]
pub struct AllocPressureOps {
    /// Allocation-deny schedule @ 0x08378a44: countdown-driven failure
    /// injection whose 0x14-byte records live in the stats block at
    /// +0x0c. While a record is active the check drains its countdown,
    /// then denies (returns 1) until the record's denial budget runs
    /// out. The records are BSS-zero at rest — inactive — so the
    /// default stub returns 0 (proceed). Always called with slot 0.
    pub alloc_deny_check: unsafe extern "C" fn(slot: i32) -> i32,
}

/// Default stub: the at-rest schedule is inactive, so the original
/// check @ 0x08378a44 falls through to its `mov r0, #0`.
unsafe extern "C" fn alloc_deny_check_inactive(_slot: i32) -> i32 {
    0
}

/// Wired default (the at-rest behavior — see the slot doc).
pub const DEFAULT_ALLOC_PRESSURE_OPS: AllocPressureOps =
    AllocPressureOps { alloc_deny_check: alloc_deny_check_inactive };

/// The active pressure helper. Host tests install a recorder and
/// restore the default.
pub static mut ALLOC_PRESSURE_OPS: AllocPressureOps = DEFAULT_ALLOC_PRESSURE_OPS;

/// Reads the pressure table (volatile — see [`db_realloc_op`]).
#[inline(always)]
fn alloc_pressure_ops() -> AllocPressureOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ALLOC_PRESSURE_OPS)) }
}

/// sqlite3_realloc — original: `FUN_08390eec` @ 0x08390eec (284 bytes;
/// 5 `bl` call sites, binary-scanned).
///
/// SQLite's `sqlite3_realloc`, the tag-57 tracked-heap resize:
///
/// - `p == NULL` tail-branches to the malloc entry @ 0x08390b14
///   (`ldmiaeq` + `beq`) — dispatched here through the
///   [`DB_MEM_OPS`]`.malloc` slot, whose wired value IS that entry.
/// - `n <= 0` (signed) frees `p` with sqlite3_free @ 0x083906f4 (the
///   ported [`tracked_free`], called directly) and returns NULL — a
///   zero resize is a free, not a zero-byte allocation.
/// - Otherwise it recovers the block (`pad` at p-4, `base = p - pad`,
///   `raw = base - 8`, `old_size` at raw+0 — the layout `heap::tracked`
///   documents) and runs the soft-limit check: UNGATED, unlike the
///   malloc entry — no callback-word test and no stats-lock arm — so
///   whenever `current + n - old_size >= soft_limit` (signed i64) it
///   warns with `n - old_size` through the ported
///   [`tracked_stats_warn_soft_limit`] @ 0x0837d67c (called directly).
/// - The allocation-deny schedule (slot 0) may then refuse the resize
///   outright: NULL without touching the heap.
/// - The raw resize is `realloc_tag57(raw, n + 44)` — the veneer chain
///   0x08391d34 → 0x08081688 → `realloc_wrapper` @ 0x080edbf0 with
///   (tag 57, copy-on-move 1) — retried once after a `warn(n)` when the
///   heap comes up empty.
/// - On success the tracked header is rebuilt in the new block
///   (raw+4 = `n >> 31`, raw+0 = n, `data = (raw + 8 + 36) & !31`), the
///   old payload is copied from its old alignment to the new one — the
///   FULL old size, even when shrinking, so a shrink can run the copy
///   past the new block's end (the original's behavior, kept as-is)
///   through the ROM thunk @ 0x08037e00 (here the ported [`memmove`],
///   the same ADS algorithm) — and the new pad word lands at data-4
///   only after the copy.
/// - Accounting: `current += (i64)(i32)(n - old_size)`, and the peak is
///   raised to current when current grew past it. Returns the
///   32-byte-aligned payload.
///
/// Deviations:
/// - The accounting block is the [`ALLOC_STATS`] static instead of the
///   literal 0x08adc2c0 (the `heap::tracked` module simplification).
/// - The unported helpers (the malloc entry, the deny schedule)
///   dispatch through ops slots whose defaults reproduce the at-rest
///   behavior; the ported callees ([`tracked_free`],
///   [`tracked_stats_warn_soft_limit`], [`realloc_wrapper`],
///   [`memmove`]) are called directly, per the porting rules.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_realloc(p: *mut u8, n: i32) -> *mut u8 {
    if p.is_null() {
        return (db_malloc_op())(n);
    }
    if n <= 0 {
        tracked_free(p);
        return core::ptr::null_mut();
    }
    let pressure = alloc_pressure_ops();
    let old_pad = (p.sub(4) as *const u32).read() as usize;
    let base = p.sub(old_pad);
    let raw = base.sub(BLOCK_HEADER_SIZE);
    let old_size = (raw as *const i32).read();
    let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
    let new_current = (*stats)
        .current_bytes
        .wrapping_add(n as i64)
        .wrapping_sub(old_size as i64);
    if new_current >= (*stats).soft_limit {
        tracked_stats_warn_soft_limit(n.wrapping_sub(old_size));
    }
    if (pressure.alloc_deny_check)(0) != 0 {
        return core::ptr::null_mut();
    }
    let mut new_raw = realloc_wrapper(raw, n as usize + 0x24 + 8, TAG_TRACKED, 1);
    if new_raw.is_null() {
        tracked_stats_warn_soft_limit(n);
        new_raw = realloc_wrapper(raw, n as usize + 0x24 + 8, TAG_TRACKED, 1);
        if new_raw.is_null() {
            return core::ptr::null_mut();
        }
    }
    (new_raw.add(4) as *mut i32).write(n >> 31);
    let new_base = new_raw.add(BLOCK_HEADER_SIZE);
    let new_data = ((new_base as usize + 0x24) & !31) as *mut u8;
    let new_pad = new_data as usize - new_base as usize;
    (new_raw as *mut i32).write(n);
    let old_payload = new_data.offset(old_pad as isize - new_pad as isize);
    memmove(new_data, old_payload, old_size as u32 as usize);
    (new_data.sub(4) as *mut u32).write(new_pad as u32);
    let delta = n.wrapping_sub(old_size) as i64;
    (*stats).current_bytes = (*stats).current_bytes.wrapping_add(delta);
    if (*stats).peak_bytes < (*stats).current_bytes {
        (*stats).peak_bytes = (*stats).current_bytes;
    }
    new_data
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

    // ---- sqlite3_realloc (0x08390eec) -------------------------------

    use crate::heap::tracked::{tracked_alloc_tail, TRACKED_STATS_OPS};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;

    const ARENA_SIZE: usize = 8192;

    #[repr(C, align(32))]
    struct Arena([u8; ARENA_SIZE]);

    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;
    /// (block, requested size) of every live arena allocation (bump
    /// allocator; 8-byte steps so successive blocks land on different
    /// 32-byte phases and the tracked pad changes between them).
    static mut LIVE_BLOCKS: [(usize, usize); 16] = [(0, 0); 16];
    static mut LIVE_COUNT: usize = 0;
    /// Realloc attempts left to fail before the arena relents (-1: never).
    static mut REALLOC_FAILS_LEFT: i32 = -1;
    static mut REALLOC_COUNT: usize = 0;
    /// (ptr, size, tag, copy_on_move) of the last arena realloc.
    static mut LAST_REALLOC: (usize, usize, usize, usize) = (0, 0, 0, 0);
    static mut FREED_LOG: Vec<(usize, usize)> = Vec::new();
    static mut WARN_LOG: Vec<i32> = Vec::new();
    static mut DENY_LOG: Vec<i32> = Vec::new();
    static mut DENY_RESULT: i32 = 0;
    /// What the deny recorder observed: had a warn already been logged?
    static mut DENY_AFTER_WARN: bool = false;

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = ARENA_USED;
        let aligned = (size + 7) & !7;
        if used + aligned > ARENA_SIZE || LIVE_COUNT >= 16 {
            return core::ptr::null_mut();
        }
        ARENA_USED = used + aligned;
        let block = core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(used);
        LIVE_BLOCKS[LIVE_COUNT] = (block as usize, size);
        LIVE_COUNT += 1;
        block
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(FREED_LOG)).push((ptr as usize, tag));
    }

    unsafe extern "C" fn arena_realloc(
        heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        size: usize,
        a3: usize,
        a4: usize,
    ) -> *mut u8 {
        REALLOC_COUNT += 1;
        LAST_REALLOC = (ptr as usize, size, a3, a4);
        if REALLOC_FAILS_LEFT > 0 {
            REALLOC_FAILS_LEFT -= 1;
            return core::ptr::null_mut();
        }
        let mut old_size = 0usize;
        for i in 0..LIVE_COUNT {
            if LIVE_BLOCKS[i].0 == ptr as usize {
                old_size = LIVE_BLOCKS[i].1;
            }
        }
        let new = arena_alloc(heap, size, a3);
        if !new.is_null() {
            // copy-on-move: the heap preserves the raw block's bytes.
            // The bump allocator never reuses space, so the full old
            // allocation (not just the new size) can be carried over —
            // the ported code reads the old payload out of it.
            core::ptr::copy_nonoverlapping(ptr, new, old_size);
        }
        new
    }

    /// Records the soft-limit callback invocations the ported warn
    /// helper @ 0x0837d67c makes (installed into the
    /// TRACKED_STATS_OPS.invoke_soft_limit_callback slot).
    unsafe extern "C" fn recording_warn(
        _callback: u32,
        _callback_arg: u32,
        _current_bytes: i64,
        size: i32,
    ) {
        (*core::ptr::addr_of_mut!(WARN_LOG)).push(size);
    }

    unsafe extern "C" fn recording_deny(slot: i32) -> i32 {
        DENY_AFTER_WARN = !(*core::ptr::addr_of!(WARN_LOG)).is_empty();
        (*core::ptr::addr_of_mut!(DENY_LOG)).push(slot);
        DENY_RESULT
    }

    /// Serializes the realloc tests: the mem OPS_LOCK first, then the
    /// veneers mock-heap lock (no other test takes both, so the order
    /// cannot cycle). Installs the arena heap and the pressure
    /// recorders, and resets the stats block.
    struct Pressure {
        _mem: MutexGuard<'static, ()>,
        _heap: MutexGuard<'static, ()>,
    }

    fn pressure() -> Pressure {
        let mem = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap = crate::heap::veneers::tests::mock_heap();
        unsafe {
            ARENA_USED = 0;
            LIVE_COUNT = 0;
            REALLOC_FAILS_LEFT = -1;
            REALLOC_COUNT = 0;
            LAST_REALLOC = (0, 0, 0, 0);
            DENY_RESULT = 0;
            DENY_AFTER_WARN = false;
            (*core::ptr::addr_of_mut!(FREED_LOG)).clear();
            (*core::ptr::addr_of_mut!(WARN_LOG)).clear();
            (*core::ptr::addr_of_mut!(DENY_LOG)).clear();
            ALLOC_STATS.soft_limit = 0;
            // Nonzero sentinel callback word: the ported warn helper
            // @ 0x0837d67c gates on it before invoking, and the
            // recorder below stands in for the `blx` (a real code
            // address does not survive the u32 word on a 64-bit host).
            ALLOC_STATS.soft_limit_callback = 1;
            ALLOC_STATS.soft_limit_callback_arg = 0;
            ALLOC_STATS.soft_limit_callback_active = 0;
            ALLOC_STATS.lock_flag = 0;
            ALLOC_STATS.current_bytes = 0;
            ALLOC_STATS.peak_bytes = 0;
            let ops = core::ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = arena_alloc;
            (*ops).free = arena_free;
            (*ops).realloc = arena_realloc;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(ALLOC_PRESSURE_OPS),
                AllocPressureOps { alloc_deny_check: recording_deny },
            );
            let stats_ops = core::ptr::addr_of_mut!(TRACKED_STATS_OPS);
            (*stats_ops).invoke_soft_limit_callback = recording_warn;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
        }
        Pressure { _mem: mem, _heap: heap }
    }

    /// Recovers the raw block the way `tracked_free` does.
    unsafe fn raw_of(payload: *mut u8) -> *mut u8 {
        let pad = (payload.sub(4) as *const u32).read() as usize;
        payload.sub(pad).sub(BLOCK_HEADER_SIZE)
    }

    /// Builds a live tracked block through the real alloc tail
    /// @ 0x08390b8c and returns (raw, payload).
    unsafe fn make_block(size: i32) -> (*mut u8, *mut u8) {
        let payload = tracked_alloc_tail(size);
        assert!(!payload.is_null());
        (raw_of(payload), payload)
    }

    fn freed_log() -> Vec<(usize, usize)> {
        unsafe { (*core::ptr::addr_of!(FREED_LOG)).clone() }
    }

    fn warn_log() -> Vec<i32> {
        unsafe { (*core::ptr::addr_of!(WARN_LOG)).clone() }
    }

    fn deny_log() -> Vec<i32> {
        unsafe { (*core::ptr::addr_of!(DENY_LOG)).clone() }
    }

    /// p == NULL tail-branches to the malloc entry @ 0x08390b14 —
    /// dispatched through the DB_MEM_OPS.malloc slot.
    #[test]
    fn a_null_pointer_tail_calls_the_malloc_slot() {
        let mut block = [0u8; 8];
        let _guard = install_recorder(block.as_mut_ptr());

        assert_eq!(unsafe { sqlite3_realloc(core::ptr::null_mut(), 64) }, block.as_mut_ptr());
        assert_eq!(realloc_log(), std::vec![(0, 64)]);

        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(REALLOC_RESULT), core::ptr::null_mut());
        }
        assert!(unsafe { sqlite3_realloc(core::ptr::null_mut(), 32) }.is_null());
        assert_eq!(realloc_log().len(), 2, "a failed malloc comes back NULL");
    }

    /// n <= 0 (signed) is sqlite3_free + NULL — a zero resize is a
    /// free, not a zero-byte allocation.
    #[test]
    fn a_zero_or_negative_size_frees_and_returns_null() {
        let _f = pressure();
        unsafe {
            let (raw, payload) = make_block(40);
            assert_eq!(ALLOC_STATS.current_bytes, 40);
            assert!(sqlite3_realloc(payload, 0).is_null());
            assert_eq!(freed_log(), std::vec![(raw as usize, 57)]);
            assert_eq!(ALLOC_STATS.current_bytes, 0, "the free subtracts the cookie");

            let (raw2, payload2) = make_block(24);
            assert!(sqlite3_realloc(payload2, -8).is_null());
            assert_eq!(freed_log(), std::vec![(raw as usize, 57), (raw2 as usize, 57)]);
            assert_eq!(ALLOC_STATS.current_bytes, 0);
        }
    }

    /// The deny schedule refuses the resize before the heap is touched
    /// — and the UNGATED soft-limit warn runs before it.
    #[test]
    fn the_deny_schedule_refuses_without_touching_the_heap() {
        let _f = pressure();
        unsafe {
            let (_raw, payload) = make_block(32);
            ALLOC_STATS.soft_limit = 1; // force the entry warn
            DENY_RESULT = 1;

            assert!(sqlite3_realloc(payload, 64).is_null());
            assert_eq!(deny_log(), std::vec![0], "always slot 0");
            assert!(DENY_AFTER_WARN, "the soft-limit warn runs before the deny check");
            assert_eq!(warn_log(), std::vec![32], "the entry warn gets n - old_size");
            assert_eq!(REALLOC_COUNT, 0, "the heap is not touched");
            assert!(freed_log().is_empty(), "the old block survives");
            assert_eq!(ALLOC_STATS.current_bytes, 32, "no accounting on refusal");
        }
    }

    /// A grow resizes the raw block (tag 57, copy-on-move 1, n + 44),
    /// rebuilds the tracked header, preserves the payload across the
    /// re-alignment shift and accounts the delta — without ever arming
    /// the stats lock (unlike the malloc entry).
    #[test]
    fn a_grow_rebuilds_the_block_preserves_the_payload_and_accounts() {
        let _f = pressure();
        unsafe {
            let (raw, payload) = make_block(32);
            for i in 0..32usize {
                payload.add(i).write(i as u8);
            }
            ALLOC_STATS.current_bytes = 100;
            ALLOC_STATS.peak_bytes = 100;
            ALLOC_STATS.soft_limit = i64::MAX;

            let new_payload = sqlite3_realloc(payload, 80);
            assert!(!new_payload.is_null());
            assert_eq!(new_payload as usize % 32, 0, "payload stays 32-aligned");
            assert_eq!(REALLOC_COUNT, 1);
            assert_eq!(
                LAST_REALLOC,
                (raw as usize, 80 + 44, 57, 1),
                "realloc_tag57(raw, n + 44) with copy-on-move"
            );
            let new_raw = raw_of(new_payload);
            assert_eq!((new_raw as *const i32).read(), 80);
            assert_eq!((new_raw.add(4) as *const i32).read(), 0);
            for i in 0..32usize {
                assert_eq!(new_payload.add(i).read(), i as u8, "byte {i}");
            }
            assert_eq!(ALLOC_STATS.current_bytes, 148, "current += n - old_size");
            assert_eq!(ALLOC_STATS.peak_bytes, 148, "peak follows current up");
            assert_eq!(ALLOC_STATS.lock_flag, 0, "realloc never arms the stats lock");
            assert!(warn_log().is_empty(), "below the limit: no entry warn");
        }
    }

    /// The copy length is the FULL old size even when shrinking — the
    /// original can run the memmove past the shrunk block's end.
    #[test]
    fn a_shrink_still_copies_the_full_old_size() {
        let _f = pressure();
        unsafe {
            let (_raw, payload) = make_block(64);
            for i in 0..64usize {
                payload.add(i).write((i ^ 0xa5) as u8);
            }
            ALLOC_STATS.current_bytes = 200;
            ALLOC_STATS.peak_bytes = 0x1_0000;
            ALLOC_STATS.soft_limit = i64::MAX;

            let new_payload = sqlite3_realloc(payload, 16);
            assert!(!new_payload.is_null());
            let new_raw = raw_of(new_payload);
            assert_eq!((new_raw as *const i32).read(), 16);
            for i in 0..64usize {
                assert_eq!(new_payload.add(i).read(), (i ^ 0xa5) as u8, "byte {i}: all 64 copied");
            }
            assert_eq!(ALLOC_STATS.current_bytes, 200 - 48, "the delta is signed");
            assert_eq!(ALLOC_STATS.peak_bytes, 0x1_0000, "the peak never lowers");
        }
    }

    /// A failed resize warns with n and retries exactly once; a second
    /// failure yields NULL and leaves the old block and the counters
    /// untouched.
    #[test]
    fn a_failed_resize_warns_and_retries_once() {
        let _f = pressure();
        unsafe {
            ALLOC_STATS.soft_limit = i64::MAX; // keep the entry warn out of the log
            let (_raw, payload) = make_block(32);
            REALLOC_FAILS_LEFT = 1;
            let new_payload = sqlite3_realloc(payload, 96);
            assert!(!new_payload.is_null());
            assert_eq!(REALLOC_COUNT, 2, "first attempt, then the retry");
            assert_eq!(warn_log(), std::vec![96], "warn(n) fires between the attempts");

            let (_raw2, payload2) = make_block(16);
            REALLOC_FAILS_LEFT = 2;
            REALLOC_COUNT = 0;
            (*core::ptr::addr_of_mut!(WARN_LOG)).clear();
            let before = ALLOC_STATS.current_bytes;
            assert!(sqlite3_realloc(payload2, 48).is_null());
            assert_eq!(REALLOC_COUNT, 2, "no third attempt");
            assert_eq!(warn_log(), std::vec![48]);
            assert!(freed_log().is_empty(), "the old block is NOT freed on failure");
            assert_eq!(ALLOC_STATS.current_bytes, before, "no accounting on failure");
        }
    }

    /// The delta is the 32-bit `n - old_size` sign-extended into the
    /// i64 counter (adds/adc ..asr #31): it carries and borrows across
    /// the 32-bit boundary.
    #[test]
    fn the_delta_accounting_is_a_full_sixty_four_bit_add() {
        let _f = pressure();
        unsafe {
            ALLOC_STATS.soft_limit = i64::MAX;
            let (_raw, payload) = make_block(8);
            ALLOC_STATS.current_bytes = 0xffff_ffff;
            ALLOC_STATS.peak_bytes = 0;
            let grown = sqlite3_realloc(payload, 16);
            assert!(!grown.is_null());
            assert_eq!(ALLOC_STATS.current_bytes, 0x1_0000_0007);
            assert_eq!(ALLOC_STATS.peak_bytes, 0x1_0000_0007);

            ALLOC_STATS.current_bytes = 0x1_0000_0000;
            let shrunk = sqlite3_realloc(grown, 8);
            assert!(!shrunk.is_null());
            assert_eq!(ALLOC_STATS.current_bytes, 0xffff_fff8, "borrow across the boundary");
        }
    }

    /// The payload survives the re-alignment shift at every raw-block
    /// skew the heap can produce (the tracked pad changes between the
    /// old and the new block, so the memmove really shifts).
    #[test]
    fn the_payload_survives_realignment_at_every_skew() {
        let _f = pressure();
        unsafe {
            ALLOC_STATS.soft_limit = i64::MAX;
            for skew in 0..8usize {
                ARENA_USED = skew * 4;
                LIVE_COUNT = 0;
                let (_raw, payload) = make_block(24);
                for i in 0..24usize {
                    payload.add(i).write((i * 7 + skew) as u8);
                }
                let new_payload = sqlite3_realloc(payload, 56);
                assert!(!new_payload.is_null(), "skew={skew}");
                assert_eq!(new_payload as usize % 32, 0, "skew={skew}");
                let new_raw = raw_of(new_payload);
                assert_eq!((new_raw as *const i32).read(), 56, "skew={skew}");
                assert_eq!((new_raw.add(4) as *const i32).read(), 0, "skew={skew}");
                for i in 0..24usize {
                    assert_eq!(
                        new_payload.add(i).read(),
                        (i * 7 + skew) as u8,
                        "skew={skew} byte {i}"
                    );
                }
            }
        }
    }

    /// The wired defaults: DB_MEM_OPS.realloc is this port, the deny
    /// stub reproduces the at-rest schedule (proceed), and the ported
    /// warn helper is a no-op with the at-rest NULL callback.
    #[test]
    fn the_default_wiring_is_the_port_with_at_rest_pressure_stubs() {
        let _f = pressure();
        unsafe {
            assert_eq!(DEFAULT_DB_MEM_OPS.realloc as usize, sqlite3_realloc as usize);
            assert_eq!((DEFAULT_ALLOC_PRESSURE_OPS.alloc_deny_check)(0), 0);

            // At rest the callback word is NULL: the real warn helper
            // returns before the invoke slot — nothing is recorded.
            ALLOC_STATS.soft_limit_callback = 0;
            tracked_stats_warn_soft_limit(64);
            assert!(warn_log().is_empty(), "NULL callback: the warn is a no-op");

            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(ALLOC_PRESSURE_OPS),
                DEFAULT_ALLOC_PRESSURE_OPS,
            );
            let (_raw, payload) = make_block(16);
            let grown = sqlite3_realloc(payload, 40);
            assert!(!grown.is_null(), "the at-rest defaults let the resize through");
        }
    }
}
