//! Result-column counting — how a prepared statement (re)sizes the
//! column-name/decltype array that
//! [`vdbe_set_col_name`](super::vdbe_set_col_name::vdbe_set_col_name)
//! writes into.
//!
//! - `vdbe_set_num_cols` — original: `FUN_0838d090` @ 0x0838d090
//!   (112 bytes, 0x0838d090..0x0838d100; **20 `bl` call sites**, all
//!   unconditional, binary-scanned from osos.dec — no predicated or
//!   tail-`b` entries). Upstream SQLite's `sqlite3VdbeSetNumCols`
//!   (`void sqlite3VdbeSetNumCols(Vdbe *p, int nResColumn)` in
//!   vdbeaux.c). It immediately follows `sqlite3VdbeSetColName` @
//!   0x0838d004 (ported, `sqlite/vdbe_set_col_name.rs`); extent from
//!   functions.csv and the listing — 0x0838d0fc is
//!   `ldmia sp!,{r4,r5,r6,pc}` and 0x0838d100 is the next function.
//!
//! ### Algorithm
//!
//! ```text
//! 0838d090:  stmdb sp!,{r4,r5,r6,lr}
//!            r4 = p, r6 = nResColumn
//! 0838d098:  ldr  r0,[r0,#0xec]        ; old nResColumn
//! 0838d0a0:  mov  r1,r0, lsl #0x1      ; old count * COLNAME_N (2)
//! 0838d0a4:  ldr  r0,[r4,#0x28]        ; old aColName
//! 0838d0a8:  mov  r2,#0x1              ; freebuffer = 1
//! 0838d0ac:  bl   0x083675c0           ; releaseMemArray(old, n, 1)
//! 0838d0b0:  ldr  r0,[r4,#0x28]
//! 0838d0b4:  bl   0x083906f4           ; sqlite3_free(old array)
//! 0838d0b8:  mov  r5,r6, lsl #0x1      ; n = nResColumn * COLNAME_N
//! 0838d0bc:  mov  r0,#0x28
//! 0838d0c0:  mul  r1,r0,r5             ; n * sizeof(Mem)
//! 0838d0c4:  str  r6,[r4,#0xec]        ; nResColumn stored FIRST
//! 0838d0c8:  ldr  r0,[r4,#0x0]         ; p->db
//! 0838d0cc:  bl   0x08374998           ; db_malloc_zero(db, n*0x28)
//! 0838d0d4:  str  r0,[r4,#0x28]        ; aColName = block (maybe NULL)
//! 0838d0d8:  ldmiaeq sp!,{r4,r5,r6,pc} ; OOM: done
//! 0838d0e0:  subs r2,r5,#0x0           ; while (n-- > 0), signed:
//! 0838d0e4:  strhgt r1,[r0,#0x1c]      ;   mem.flags = MEM_Null (1)
//! 0838d0e8:  ldrgt r2,[r4,#0x0]        ;   db re-loaded each pass
//! 0838d0f0:  strgt r2,[r0,#0x10]!      ;   mem.db = db
//! 0838d0f4:  addgt r0,r0,#0x18         ;   mem += 0x10! + 0x18 = 0x28
//! 0838d0f8:  bgt  0x0838d0e0
//! ```
//!
//! The old array's `Mem` guts are released with the old column count
//! (times the two name planes), the array block itself is freed
//! unconditionally (`sqlite3_free`'s own NULL guard covers a fresh
//! statement), the new count lands in `nResColumn` (+0xec) **before**
//! the allocation is attempted — so a failed resize still leaves the
//! statement claiming the new column count with a NULL array — and the
//! zeroed replacement is stamped one `Mem` at a time: `flags` = 1
//! (`MEM_Null`, `mov r1,#0x1`) at +0x1c, the owning connection at
//! +0x10, advancing 0x28 bytes. The loop is signed (`subs`/`bgt`): a
//! zero or negative count stamps nothing.
//!
//! ### Deviations
//!
//! - `releaseMemArray` @ 0x083675c0 IS ported
//!   ([`release_mem_array`](super::release_mem_array::release_mem_array))
//!   and is the shipped default of the [`SQLITE_MEM_ARRAY_RELEASE`]
//!   dispatch static (the `sqlite/value_set_str.rs` pattern). The slot
//!   stays so host tests can install recording mocks; the old no-op
//!   stub ([`missing_mem_array_release`]) is retained for tests that
//!   explicitly need an unconfigured callee.
//! - `sqlite3_free` @ 0x083906f4 IS ported
//!   ([`tracked_free`](crate::heap::tracked::tracked_free)) and
//!   `sqlite3DbMallocZero` @ 0x08374998 IS ported
//!   ([`db_malloc_zero`](super::mem::db_malloc_zero)); both are called
//!   directly, per the porting rules.
//! - `Vdbe` and [`Mem`] are `#[repr(C)]` structs with named fields
//!   rather than byte offsets, so the pointer fields stay disjoint on
//!   a 64-bit test host; the original's offsets are statically
//!   asserted on 32-bit targets in `sqlite/vdbe.rs`.

use super::mem::db_malloc_zero;
use super::value_new::{MEM_NULL, MEM_SIZE};
use super::vdbe::{Mem, Vdbe};
use crate::heap::tracked::tracked_free;

/// The `freebuffer` argument the original passes (`mov r2,#0x1`): the
/// callee releases each `Mem`'s guts with `sqlite3VdbeMemRelease`
/// rather than the bulk extern release.
pub const RELEASE_GUTS: i32 = 1;

/// `releaseMemArray(mem, n, freebuffer)` @ 0x083675c0: release the
/// dynamic resources of the `n` 40-byte `Mem`s starting at `mem`.
/// NULL `mem` or zero `n` returns immediately (the callee's own
/// guard).
pub type MemArrayReleaseFn = unsafe extern "C" fn(mem: *mut u8, n: i32, freebuffer: i32);

/// The no-op stub retained for host tests that explicitly need an
/// unconfigured `releaseMemArray` (a call is observably the original's
/// NULL-array/zero-count early-out; the old array block is freed by
/// the caller either way, so only the `Mem` guts' ledger entries
/// differ). The shipped default is the real port,
/// [`super::release_mem_array::release_mem_array`].
pub(crate) unsafe extern "C" fn missing_mem_array_release(
    _mem: *mut u8,
    _n: i32,
    _freebuffer: i32,
) {
}

/// Active `releaseMemArray` dispatch slot. The default is the real
/// port, [`super::release_mem_array::release_mem_array`]; host tests
/// still install recording replacements ([`missing_mem_array_release`]
/// remains available for them).
pub static mut SQLITE_MEM_ARRAY_RELEASE: MemArrayReleaseFn =
    super::release_mem_array::release_mem_array;

/// Read the array-release slot volatile so its default remains
/// replaceable.
#[inline(always)]
pub(crate) unsafe fn mem_array_release_op() -> MemArrayReleaseFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_MEM_ARRAY_RELEASE))
}

/// vdbe_set_num_cols — original: `FUN_0838d090` @ 0x0838d090 (112
/// bytes; 20 `bl` call sites).
///
/// `sqlite3VdbeSetNumCols`: resize the statement's column-name array
/// to `n_res_column` columns (times the two name planes). The old
/// array's `Mem` guts are released and the block freed; the new count
/// is stored before a zeroed replacement of `n_res_column * COLNAME_N
/// * 0x28` bytes is allocated on the connection — NULL on OOM, which
/// ends the call — and each fresh `Mem` is stamped `flags` =
/// `MEM_Null`, `db` = the owning connection.
///
/// Register usage: r0 = p (saved in r4), r1 = n_res_column (saved in
/// r6), r5 = the element count `n_res_column << 1`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_set_num_cols(p: *mut Vdbe, n_res_column: i32) {
    (mem_array_release_op())(
        (*p).a_col_name as *mut u8,
        (*p).n_res_column << 1,
        RELEASE_GUTS,
    );
    tracked_free((*p).a_col_name as *mut u8);
    (*p).n_res_column = n_res_column;
    let n = n_res_column << 1;
    let mem = db_malloc_zero((*p).db, n * MEM_SIZE) as *mut Mem;
    (*p).a_col_name = mem;
    if mem.is_null() {
        return;
    }
    let mut col = mem;
    let mut remaining = n;
    while remaining > 0 {
        (*col).flags = MEM_NULL;
        (*col).db = (*p).db;
        remaining -= 1;
        col = col.add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::mem::tests::{recording_realloc, Connection, OPS_LOCK};
    use super::super::mem::{DbMemOps, DB_MEM_OPS, DEFAULT_DB_MEM_OPS};
    use super::super::vdbe::COLNAME_N;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use core::mem::MaybeUninit;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Every release/free/allocate the code under test triggered, in
    /// order — one log across the three seams so the original's call
    /// order is observable.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Release(usize, i32, i32),
        Free(usize, usize),
        Malloc(i32),
    }

    static mut EVENTS: Vec<Event> = Vec::new();
    /// Block the recording malloc hands back, or NULL to fail.
    static mut MALLOC_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_mem_array_release(mem: *mut u8, n: i32, freebuffer: i32) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Release(mem as usize, n, freebuffer));
    }

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Free(ptr as usize, tag));
    }

    unsafe extern "C" fn recording_malloc(n: i32) -> *mut u8 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Malloc(n));
        core::ptr::read(core::ptr::addr_of!(MALLOC_RESULT))
    }

    /// Serializes against the other allocator-swapping tests (mem's
    /// OPS_LOCK first, then the veneer mock-heap lock — the order
    /// `sqlite/mem.rs`'s pressure tests establish), routes all three
    /// seams into the event log, and hands the recording malloc
    /// `malloc_result`. The guards must stay alive for the whole test.
    fn bench(malloc_result: *mut u8) -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::write(core::ptr::addr_of_mut!(MALLOC_RESULT), malloc_result);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(DB_MEM_OPS),
                DbMemOps { malloc: recording_malloc, realloc: recording_realloc },
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SQLITE_MEM_ARRAY_RELEASE),
                recording_mem_array_release,
            );
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        }
        (mem_guard, heap_guard)
    }

    /// Restore the shipped defaults while the bench guards are still
    /// held (the `sqlite/value_new.rs` convention).
    unsafe fn restore() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_MEM_ARRAY_RELEASE),
            super::super::release_mem_array::release_mem_array,
        );
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`), as
    /// `sqlite/mem_release.rs`'s tests build one: raw block at offset
    /// 0 of a 32-aligned buffer, payload at raw + 32, pad word
    /// 32 - 8 = 24.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new() -> Self {
            let mut block = TrackedBlock([0; 64]);
            block.0[0..4].copy_from_slice(&24i32.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }
        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn payload(&mut self) -> *mut u8 {
            // In-bounds by construction (64-byte block, payload at 32).
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    /// Room for the replacement array on a 64-bit host, where `Mem`'s
    /// pointer fields widen the stride past the original's 0x28:
    /// 8 columns' worth (2 planes) at any host stride.
    #[repr(align(8))]
    struct NewArray([u8; 512]);

    /// A statement whose old array is `old` (or NULL).
    struct Statement {
        db: Connection,
        vdbe: Vdbe,
    }

    impl Statement {
        fn new(old: *mut u8, old_columns: i32) -> Self {
            let mut vdbe = unsafe { MaybeUninit::<Vdbe>::zeroed().assume_init() };
            vdbe.a_col_name = old as *mut Mem;
            vdbe.n_res_column = old_columns;
            let mut db = Connection::healthy();
            vdbe.db = db.ptr();
            Statement { db, vdbe }
        }
        /// Re-pin `db` (the struct moved after `new()` returned) and
        /// hand out the `Vdbe`.
        fn ptr(&mut self) -> *mut Vdbe {
            self.vdbe.db = self.db.ptr();
            &mut self.vdbe
        }
    }

    #[test]
    fn the_old_array_is_released_then_freed_then_the_new_one_allocated() {
        let mut new_block = NewArray([0; 512]);
        let new_ptr = new_block.0.as_mut_ptr();
        let _guards = bench(new_ptr);
        let mut old_block = TrackedBlock::new();
        let (old_raw, old_payload) = (old_block.raw(), old_block.payload());
        let mut stmt = Statement::new(old_payload, 3);
        unsafe {
            vdbe_set_num_cols(stmt.ptr(), 2);
            assert_eq!(
                events(),
                std::vec![
                    Event::Release(old_payload as usize, 3 * COLNAME_N, RELEASE_GUTS),
                    Event::Free(old_raw as usize, TAG_TRACKED),
                    Event::Malloc(2 * COLNAME_N * MEM_SIZE),
                ],
                "release guts (old count * two planes), free the block, then allocate"
            );
            assert_eq!(stmt.vdbe.n_res_column, 2);
            assert_eq!(stmt.vdbe.a_col_name, new_ptr as *mut Mem);
            restore();
        }
    }

    #[test]
    fn the_new_count_is_stored_even_when_the_allocation_fails() {
        let _guards = bench(core::ptr::null_mut());
        let mut stmt = Statement::new(core::ptr::null_mut(), 0);
        unsafe {
            vdbe_set_num_cols(stmt.ptr(), 5);
            assert_eq!(stmt.vdbe.n_res_column, 5, "stored before the malloc, kept after it");
            assert!(stmt.vdbe.a_col_name.is_null(), "the NULL result is stored");
            assert_eq!(
                events(),
                std::vec![
                    Event::Release(0, 0, RELEASE_GUTS),
                    Event::Malloc(5 * COLNAME_N * MEM_SIZE),
                ],
                "no free for a NULL old array; the heap was still tried"
            );
            assert_eq!(stmt.db.failed_flag(), 1, "the allocator latches the sticky OOM byte");
            restore();
        }
    }

    #[test]
    fn a_failed_connection_still_releases_and_frees_the_old_array() {
        let _guards = bench(core::ptr::null_mut());
        let mut old_block = TrackedBlock::new();
        let (old_raw, old_payload) = (old_block.raw(), old_block.payload());
        let mut stmt = Statement::new(old_payload, 1);
        stmt.db = Connection::failed();
        unsafe {
            vdbe_set_num_cols(stmt.ptr(), 4);
            assert_eq!(
                events(),
                std::vec![
                    Event::Release(old_payload as usize, COLNAME_N, RELEASE_GUTS),
                    Event::Free(old_raw as usize, TAG_TRACKED),
                ],
                "teardown runs before the short-circuited allocator is consulted"
            );
            assert_eq!(stmt.vdbe.n_res_column, 4);
            assert!(stmt.vdbe.a_col_name.is_null());
            restore();
        }
    }

    #[test]
    fn each_new_mem_is_stamped_null_with_the_connection_back_pointer() {
        for n_res_column in [1, 2, 3, 6] {
            let mut new_block = NewArray([0xa5; 512]);
            let new_ptr = new_block.0.as_mut_ptr();
            let guards = bench(new_ptr);
            let mut stmt = Statement::new(core::ptr::null_mut(), 0);
            unsafe {
                vdbe_set_num_cols(stmt.ptr(), n_res_column);
                let base = stmt.vdbe.a_col_name;
                assert_eq!(base, new_ptr as *mut Mem, "n={n_res_column}");
                let db_ptr = stmt.db.ptr();
                for i in 0..(n_res_column * COLNAME_N) as isize {
                    let col = &*base.offset(i);
                    assert_eq!(col.flags, MEM_NULL, "n={n_res_column} element {i}: MEM_Null");
                    assert_eq!(col.db, db_ptr, "n={n_res_column} element {i}: owned by db");
                }
                restore();
            }
            drop(guards);
        }
    }

    #[test]
    fn zero_columns_still_goes_through_the_allocator_and_stamps_nothing() {
        let _guards = bench(core::ptr::null_mut());
        let mut old_block = TrackedBlock::new();
        let (old_raw, old_payload) = (old_block.raw(), old_block.payload());
        let mut stmt = Statement::new(old_payload, 2);
        unsafe {
            vdbe_set_num_cols(stmt.ptr(), 0);
            assert_eq!(
                events(),
                std::vec![
                    Event::Release(old_payload as usize, 2 * COLNAME_N, RELEASE_GUTS),
                    Event::Free(old_raw as usize, TAG_TRACKED),
                    Event::Malloc(0),
                ],
                "the zero-byte request reaches the heap, as in the original"
            );
            assert_eq!(stmt.vdbe.n_res_column, 0);
            assert!(stmt.vdbe.a_col_name.is_null(), "the failed zero request stores NULL");
            restore();
        }
    }

    #[test]
    fn the_callee_seam_ships_the_real_port() {
        // Serialize against this module's recording installs: they
        // hold mem's OPS_LOCK and the mock-heap guard for the whole
        // swap (in this order), so taking both here makes the read
        // race-free.
        let _mem_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap_guard = mock_heap();
        unsafe {
            assert_eq!(
                mem_array_release_op() as usize,
                super::super::release_mem_array::release_mem_array as usize,
                "0x083675c0 is ported and is the seam's shipped default",
            );
        }
    }
}
