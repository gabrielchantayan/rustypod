//! The Mem-array teardown — how the VDBE releases the dynamic guts of
//! a run of `Mem` values without freeing the array block itself.
//!
//! - `release_mem_array` — original: `FUN_083675c0` @ 0x083675c0 (92
//!   bytes, 0x083675c0..0x0836761c; **6 `bl` call sites**, all
//!   unconditional, binary-scanned from osos.dec — 0x08044ccc,
//!   0x08386db0, 0x08386ddc, 0x0838afdc, 0x0838b6b4 and the
//!   [`vdbe_set_num_cols`](super::vdbe_set_num_cols::vdbe_set_num_cols)
//!   site @ 0x0838d0ac — no predicated or tail-`b` entries). Upstream
//!   SQLite 3.5.9's `releaseMemArray` (vdbeaux.c):
//!   `void releaseMemArray(Mem *p, int N, int freebuffer)`. The next
//!   function starts at 0x0836761c (`cmp r0,#0x0`), matching the
//!   functions.csv extent.
//!
//! ### Algorithm
//!
//! ```text
//! 083675c0:  stmdb sp!,{r4,r5,r6,r7,r8,r9,r10,lr}
//! 083675c4:  movs r4,r0               ; r4 = mem; NULL?
//! 083675c8:  mov  r5,r1               ; r5 = n
//! 083675cc:  cmpne r5,#0x0            ; n == 0?
//! 083675d0:  mov  r7,r2               ; r7 = freebuffer
//! 083675d4:  ldmiaeq sp!,{r4-r10,pc}  ; NULL mem or zero n: done
//! 083675d8:  ldr  r6,[r4,#0x10]       ; db = mem->db (first Mem's)
//! 083675dc:  mov  r9,#0x1             ; MEM_Null
//! 083675e0:  ldrb r8,[r6,#0x1e]       ; saved = db->mallocFailed
//! 083675e4:  b    0x08367608          ; enter at the count check
//!      loop:  cmp  r7,#0x0
//!             mov  r0,r4
//!             beq  0x083675fc
//! 083675f4:  bl   0x0838c04c          ; freebuffer: mem_release(mem)
//!             b    0x08367600
//! 083675fc:  bl   0x0838c074          ; else: mem_extern_release(mem)
//! 08367600:  strh r9,[r4,#0x1c]       ; mem->flags = MEM_Null
//! 08367604:  add  r4,r4,#0x28         ; mem += sizeof(Mem)
//! 08367608:  subs r0,r5,#0x0          ; flags from the OLD n
//! 0836760c:  sub  r5,r5,#0x1          ; n--
//! 08367610:  bgt  loop                ; signed: while (old n > 0)
//! 08367614:  strb r8,[r6,#0x1e]       ; db->mallocFailed = saved
//! 08367618:  ldmia sp!,{r4-r10,pc}
//! ```
//!
//! NULL `mem` or zero `n` returns before anything is touched. Otherwise
//! the owning connection is taken from the FIRST `Mem`'s `db` field
//! (+0x10) and its sticky `mallocFailed` byte (+0x1e) is saved, so the
//! releases below — which free memory and could latch OOM mid-teardown —
//! never leak a failure state into the caller: the byte is restored
//! after the walk. Each of the `n` `Mem`s is then released per the mode
//! flag: any nonzero `freebuffer` runs the full guts release @
//! 0x0838c04c (`sqlite3VdbeMemRelease` — extern release, `zMalloc`
//! free, field NULLing), exactly zero runs only the extern release @
//! 0x0838c074 (`vdbeMemClearExternAndSetNull` — aggregate finalize or
//! `xDel` destructor, `zMalloc` kept). Each released `Mem` is stamped
//! `flags` = `MEM_Null` (1) at +0x1c and the walk advances 0x28 bytes.
//! The loop is signed (`subs`/`bgt` on the pre-decrement count), so a
//! negative `n` releases nothing — though the `db` save/restore around
//! it still runs (only the `n == 0` early-out skips it).
//!
//! ### Deviations
//!
//! - Both callees ARE ported and are called directly, per the porting
//!   rules: [`mem_release`](super::mem_release::mem_release) @
//!   0x0838c04c and
//!   [`mem_extern_release`](super::mem_extern_release::mem_extern_release)
//!   @ 0x0838c074. No dispatch seams are introduced here.
//! - Like the whole release cluster (`sqlite/mem_release.rs`,
//!   `sqlite/value_free.rs`), the port speaks the original's raw byte
//!   offsets — 0x28 stride, `db` at +0x10, `flags` at +0x1c — rather
//!   than the typed `repr(C)` [`Mem`](super::vdbe::Mem), whose pointer
//!   fields widen on a 64-bit host. The two views coincide on the
//!   32-bit target (statically asserted in `sqlite/vdbe.rs`), and only
//!   the raw view lets the ported callees see the same element the
//!   caller released.
//! - This port is the shipped default of
//!   [`SQLITE_MEM_ARRAY_RELEASE`](super::vdbe_set_num_cols::SQLITE_MEM_ARRAY_RELEASE),
//!   replacing the documented no-op stub; the slot stays so host tests
//!   can install recording mocks.

use super::mem::MALLOC_FAILED_OFFSET;
use super::mem_extern_release::mem_extern_release;
use super::mem_release::mem_release;
use super::value_new::{MEM_DB_OFFSET, MEM_FLAGS_OFFSET, MEM_NULL, MEM_SIZE};

/// release_mem_array — original: `FUN_083675c0` @ 0x083675c0 (92
/// bytes; 6 `bl` call sites).
///
/// `releaseMemArray`: release the dynamic resources of the `n` 40-byte
/// `Mem`s starting at `mem`. NULL `mem` or zero `n` returns
/// immediately; a negative `n` walks nothing but still brackets the
/// (empty) walk with the `db->mallocFailed` save/restore. Each visited
/// `Mem` goes to [`mem_release`] when `freebuffer` is nonzero, to
/// [`mem_extern_release`] when it is exactly zero, and is stamped
/// `flags` = `MEM_Null` either way.
///
/// Register usage: r4 = the walking `mem`, r5 = the count, r6 = `db`,
/// r7 = `freebuffer`, r8 = the saved `mallocFailed` byte, r9 = 1
/// (`MEM_Null`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_mem_array(mem: *mut u8, n: i32, freebuffer: i32) {
    if mem.is_null() || n == 0 {
        return;
    }
    let db = (mem.add(MEM_DB_OFFSET) as *const *mut u8).read();
    let saved_malloc_failed = db.add(MALLOC_FAILED_OFFSET).read();
    let mut cell = mem;
    let mut remaining = n;
    while remaining > 0 {
        if freebuffer != 0 {
            mem_release(cell);
        } else {
            mem_extern_release(cell);
        }
        (cell.add(MEM_FLAGS_OFFSET) as *mut u16).write(MEM_NULL);
        cell = cell.add(MEM_SIZE as usize);
        remaining -= 1;
    }
    db.add(MALLOC_FAILED_OFFSET).write(saved_malloc_failed);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::mem::tests::Connection;
    use super::super::mem_extern_release::mem_extern_release;
    use super::super::mem_release::{FLAG_DYN, X_DEL_OFFSET, Z_MALLOC_OFFSET, Z_OFFSET};
    use super::super::vdbe_set_num_cols::{mem_array_release_op, SQLITE_MEM_ARRAY_RELEASE};
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes this module's tests: they share the event log and
    /// the swapped heap-free slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every destructor/free the code under test triggered, in order.
    /// `XDel(usize::MAX)` is the donor element's destructor (its `z`
    /// is unreadable — see [`MemArray::set_z`]); any other `XDel` logs
    /// the `z` it was invoked with.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        XDel(usize),
        RawFree(usize, usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();

    unsafe extern "C" fn recording_x_del(z: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::XDel(z as usize));
    }

    /// The destructor for element 0, the `db` donor: its `z` overlaps
    /// the connection pointer on a 64-bit host, so its identity is the
    /// destructor itself.
    unsafe extern "C" fn donor_x_del(_z: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::XDel(usize::MAX));
    }

    unsafe extern "C" fn recording_heap_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::RawFree(ptr as usize, tag));
    }

    /// Installs the mock heap (first — the lock order
    /// `sqlite/mem_release.rs`'s tests establish), routes frees into
    /// the event log, and clears the log. The guards must stay alive
    /// for the whole test.
    fn bench() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let heap_guard = mock_heap();
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
        }
        (heap_guard, ops_guard)
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

    /// A run of up to five `Mem` shells at the original's 0x28 stride,
    /// plus eight pad bytes: on a 64-bit host the callees'
    /// pointer-width NULL stores at +0x24 span +0x24..+0x2c, four
    /// bytes past the last element (see `sqlite/mem_release.rs`'s
    /// scratch `Mem`).
    #[repr(align(8))]
    struct MemArray([u8; 5 * 0x28 + 8]);

    impl MemArray {
        fn new() -> Self {
            MemArray([0; 5 * 0x28 + 8])
        }
        fn base(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn cell(&mut self, i: usize) -> *mut u8 {
            assert!(i < 5);
            // In-bounds: i < 5, element i spans i*0x28..(i+1)*0x28.
            unsafe { self.base().add(i * 0x28) }
        }
        fn set_word(&mut self, i: usize, offset: usize, word: *mut u8) {
            assert!(offset + core::mem::size_of::<*mut u8>() <= 0x28 + 8);
            let cell = self.cell(i);
            // In-bounds: checked above against the element-plus-pad span.
            unsafe { (cell.add(offset) as *mut *mut u8).write(word) };
        }
        fn word(&self, i: usize, offset: usize) -> *mut u8 {
            assert!(i < 5 && offset + core::mem::size_of::<*mut u8>() <= 0x28 + 8);
            // In-bounds: checked above.
            unsafe { (self.0.as_ptr().add(i * 0x28 + offset) as *const *mut u8).read() }
        }
        fn set_flags(&mut self, i: usize, flags: u16) {
            let cell = self.cell(i);
            // In-bounds: +0x1c..+0x1e lies inside the 0x28-byte element.
            unsafe { (cell.add(MEM_FLAGS_OFFSET) as *mut u16).write(flags) };
        }
        fn flags(&self, i: usize) -> u16 {
            // In-bounds: +0x1c..+0x1e lies inside the 0x28-byte element.
            unsafe { (self.0.as_ptr().add(i * 0x28 + MEM_FLAGS_OFFSET) as *const u16).read() }
        }
        fn set_db(&mut self, i: usize, db: *mut u8) {
            self.set_word(i, MEM_DB_OFFSET, db);
        }
        /// Set `z` (+0x14). Never on the element that donates `db`
        /// (element 0 — the original reads `db` only from the first
        /// `Mem`): on a 64-bit host the pointer-width `z` at +0x14
        /// overlaps the pointer-width `db` at +0x10, so a `z` write
        /// there would corrupt the connection pointer.
        fn set_z(&mut self, i: usize, z: *mut u8) {
            assert!(i != 0, "z overlaps db on the db-donor element");
            self.set_word(i, Z_OFFSET, z);
        }
    }

    /// Reference model of the original's signed `while (old n > 0)`
    /// walk: the element indices a faithful port visits, in order.
    fn reference_walk(n: i32) -> Vec<usize> {
        let mut visited = Vec::new();
        let mut remaining = n;
        while remaining > 0 {
            visited.push((n - remaining) as usize);
            remaining -= 1;
        }
        visited
    }

    #[test]
    fn a_null_array_returns_before_anything_is_touched() {
        let _guards = bench();
        unsafe { release_mem_array(core::ptr::null_mut(), 4, 1) };
        assert_eq!(events(), Vec::new(), "no destructor, no free");
    }

    #[test]
    fn a_zero_count_returns_before_the_db_is_even_read() {
        let _guards = bench();
        let mut db = Connection::healthy();
        let mut array = MemArray::new();
        array.set_db(0, db.ptr());
        array.set_flags(0, 0x2);
        // A NULL db would fault if the early-out did not precede the
        // +0x10 load; use a real one and prove the byte is untouched.
        unsafe { release_mem_array(array.base(), 0, 1) };
        assert_eq!(events(), Vec::new());
        assert_eq!(array.flags(0), 0x2, "no flags stamped");
        assert_eq!(db.failed_flag(), 0, "mallocFailed byte untouched");
    }

    #[test]
    fn a_negative_count_releases_nothing_but_brackets_the_walk() {
        let _guards = bench();
        let mut db = Connection::healthy();
        let mut array = MemArray::new();
        array.set_db(0, db.ptr());
        array.set_flags(0, 0x2);
        array.set_flags(1, 0x10);
        unsafe { release_mem_array(array.base(), -3, 1) };
        assert_eq!(events(), Vec::new(), "the signed loop runs zero times");
        assert_eq!(array.flags(0), 0x2);
        assert_eq!(array.flags(1), 0x10);
        assert_eq!(
            db.failed_flag(),
            0,
            "the save/restore around the empty walk preserves the byte"
        );
    }

    #[test]
    fn freebuffer_one_releases_every_guts_in_order_and_stamps_null() {
        let _guards = bench();
        let mut db = Connection::healthy();
        let mut blocks = [TrackedBlock::new(), TrackedBlock::new(), TrackedBlock::new()];
        let mut array = MemArray::new();
        for i in 0..3 {
            array.set_db(i, db.ptr());
            array.set_flags(i, 0x2); // MEM_Str, no MEM_Agg/MEM_Dyn
            if i != 0 {
                array.set_z(i, (0x1000 + i) as *mut u8);
            }
            array.set_word(i, X_DEL_OFFSET, (0x2000 + i) as *mut u8);
            array.set_word(i, Z_MALLOC_OFFSET, blocks[i].payload());
        }
        let raws = [blocks[0].raw(), blocks[1].raw(), blocks[2].raw()];

        unsafe { release_mem_array(array.base(), 3, 1) };

        assert_eq!(
            events(),
            raws.iter().map(|&raw| Event::RawFree(raw as usize, TAG_TRACKED)).collect::<Vec<_>>(),
            "each zMalloc freed through the tracked allocator, in array order"
        );
        for i in 0..3 {
            assert_eq!(array.flags(i), MEM_NULL, "element {i}: stamped MEM_Null");
            assert!(array.word(i, Z_OFFSET).is_null(), "element {i}: mem_release NULLed z");
            assert!(array.word(i, Z_MALLOC_OFFSET).is_null(), "element {i}: zMalloc NULLed");
            assert!(array.word(i, X_DEL_OFFSET).is_null(), "element {i}: xDel NULLed");
        }
        assert_eq!(db.failed_flag(), 0, "mallocFailed restored");
    }

    #[test]
    fn freebuffer_zero_runs_only_the_extern_release_and_keeps_z_malloc() {
        let _guards = bench();
        let mut db = Connection::healthy();
        let mut array = MemArray::new();
        let zs = [core::ptr::null_mut::<u8>(), 0x0bbb_0000usize as *mut u8];
        let x_dels = [donor_x_del as *mut u8, recording_x_del as *mut u8];
        for i in 0..2 {
            array.set_db(i, db.ptr());
            array.set_flags(i, FLAG_DYN | 0x2); // MEM_Dyn | MEM_Str
            if i != 0 {
                array.set_z(i, zs[i]);
            }
            array.set_word(i, X_DEL_OFFSET, x_dels[i]);
            // No zMalloc: on a 64-bit host the pointer-width zMalloc at
            // +0x24 overlaps xDel's upper half (+0x20..+0x28), and the
            // extern release's xDel NULL store spans it too. "zMalloc
            // is kept" is observed as the absence of any free below.
        }

        unsafe { release_mem_array(array.base(), 2, 0) };

        assert_eq!(
            events(),
            std::vec![Event::XDel(usize::MAX), Event::XDel(zs[1] as usize)],
            "each element's xDel invoked, in array order — and no zMalloc free"
        );
        for i in 0..2 {
            assert_eq!(array.flags(i), MEM_NULL, "element {i}: stamped MEM_Null");
            assert!(array.word(i, X_DEL_OFFSET).is_null(), "element {i}: xDel consumed");
        }
    }

    #[test]
    fn the_failed_byte_is_saved_before_and_restored_after_the_walk() {
        let _guards = bench();
        let mut db = Connection::healthy();
        let db_ptr = db.ptr();
        static mut DB_PTR: *mut u8 = core::ptr::null_mut();
        /// A destructor that latches OOM mid-walk, the leak the
        /// save/restore exists to contain.
        unsafe extern "C" fn oom_latching_x_del(_z: *mut u8) {
            let db = core::ptr::read(core::ptr::addr_of!(DB_PTR));
            crate::sqlite::mem::set_malloc_failed(db);
        }
        unsafe { core::ptr::write(core::ptr::addr_of_mut!(DB_PTR), db_ptr) };

        let mut array = MemArray::new();
        for i in 0..2 {
            array.set_db(i, db_ptr);
            array.set_flags(i, FLAG_DYN);
            array.set_word(i, X_DEL_OFFSET, oom_latching_x_del as *mut u8);
        }

        unsafe { release_mem_array(array.base(), 2, 0) };

        assert_eq!(
            db.failed_flag(),
            0,
            "the byte the destructors latched is rolled back to its pre-call value"
        );
    }

    #[test]
    fn the_walk_matches_a_reference_model_on_stride_order_and_flags() {
        for n in [1, 2, 5] {
            let guards = bench();
            let mut db = Connection::healthy();
            let mut array = MemArray::new();
            for i in 0..5 {
                array.set_db(i, db.ptr());
                array.set_flags(i, FLAG_DYN);
                if i == 0 {
                    array.set_word(i, X_DEL_OFFSET, donor_x_del as *mut u8);
                } else {
                    array.set_z(i, (0x4000 + i * 0x100) as *mut u8);
                    array.set_word(i, X_DEL_OFFSET, recording_x_del as *mut u8);
                }
            }
            // Sentinel flags past the released prefix must survive.
            unsafe { release_mem_array(array.base(), n, 0) };

            let visited = reference_walk(n);
            assert_eq!(
                events(),
                visited
                    .iter()
                    .map(|&i| if i == 0 { Event::XDel(usize::MAX) } else { Event::XDel(0x4000 + i * 0x100) })
                    .collect::<Vec<_>>(),
                "n={n}: exactly the model's elements, in the model's order"
            );
            for i in 0..5 {
                let expected = if visited.contains(&i) { MEM_NULL } else { FLAG_DYN };
                assert_eq!(array.flags(i), expected, "n={n} element {i}");
            }
            drop(guards);
        }
    }

    #[test]
    fn a_one_element_array_walks_exactly_once() {
        let _guards = bench();
        let mut db = Connection::healthy();
        let mut array = MemArray::new();
        array.set_db(0, db.ptr());
        array.set_flags(0, FLAG_DYN | 0x2);
        array.set_word(0, X_DEL_OFFSET, donor_x_del as *mut u8);

        unsafe { release_mem_array(array.base(), 1, 0) };

        assert_eq!(events(), std::vec![Event::XDel(usize::MAX)]);
        assert_eq!(array.flags(0), MEM_NULL);
    }

    #[test]
    fn the_shipped_dispatch_slot_default_is_this_port() {
        // Read the live slot under the mock-heap guard: that lock is
        // what vdbe_set_num_cols' tests hold while they swap it, so
        // the read cannot race a recording install.
        let _guards = bench();
        unsafe {
            assert_eq!(
                mem_array_release_op() as usize,
                release_mem_array as usize,
                "vdbe_set_num_cols' SQLITE_MEM_ARRAY_RELEASE ships the real port"
            );
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_MEM_ARRAY_RELEASE)) as usize,
                release_mem_array as usize,
            );
        }
        // And the extern-release seam this module's freebuffer=0 path
        // calls directly still ships its own port.
        use super::super::mem_release::DEFAULT_MEM_EXTERN_OPS;
        assert_eq!(
            DEFAULT_MEM_EXTERN_OPS.extern_release as usize,
            mem_extern_release as usize,
        );
    }
}
