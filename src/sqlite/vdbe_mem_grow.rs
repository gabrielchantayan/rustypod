//! Payload-space growth — how a `Mem`/`sqlite3_value` cell guarantees
//! it owns at least `n` bytes of `sqlite3_malloc`ed storage behind its
//! `z` payload, relocating (and optionally preserving) the payload when
//! the current `zMalloc` block is too small or borrowed.
//!
//! - `vdbe_mem_grow` — original: `FUN_0838bdb0` @ 0x0838bdb0
//!   (232 bytes, 0x0838bdb0..0x0838be98; **13 `bl` call sites**,
//!   binary-scanned from osos.dec — no predicated or tail branches).
//!   Upstream SQLite 3.5.9's `sqlite3VdbeMemGrow`
//!   (`int sqlite3VdbeMemGrow(Mem *pMem, int n, int preserve)` in
//!   vdbemem.c), verified line-for-line against the public 3.5.9
//!   source (only the asserts are compiled out of the firmware) with
//!   two firmware deviations called out below.
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838be94 is the closing
//! `ldmia sp!, {r4,r5,r6,pc}` and 0x0838be98 is the
//! `stmdb sp!, {r4,r5,r6,lr}` entry of `MemHandleBom`. No literal pool
//! — the capacity gate (`0x20`), the `MEM_Dyn` test (`0x40`), the
//! ownership mask (`bic #0x180`), `MEM_Null` (`1`) and both return
//! codes are all immediates.
//!
//! ### Listing
//!
//! ```text
//! 0838bdb0  stmdb sp!, {r4,r5,r6,lr}
//! 0838bdb4  mov  r4,r0              @ p_mem
//! 0838bdb8  ldr  r0,[r0,#0x24]      @ zMalloc
//! 0838bdbc  mov  r6,r2              @ preserve
//! 0838bdc0  cmp  r0,#0x0
//! 0838bdc4  mov  r5,r1              @ n (requested size)
//! 0838bdc8  beq  0x0838bdd8         @ no owned block: grow
//! 0838bdcc  bl   0x0837d374         @ sqlite3MallocSize(zMalloc)
//! 0838bdd0  cmp  r0,r5
//! 0838bdd4  bge  0x0838be34         @ capacity sufficient: skip alloc
//! 0838bdd8  cmp  r5,#0x20
//! 0838bddc  movle r5,#0x20          @ n = max(n, 32), signed
//! 0838bde0  cmp  r6,#0x0
//! 0838bde4  beq  0x0838be1c         @ !preserve: free + malloc
//! 0838bde8  ldr  r0,[r4,#0x24]
//! 0838bdec  ldr  r1,[r4,#0x14]
//! 0838bdf0  cmp  r1,r0              @ z == zMalloc?
//! 0838bdf4  bne  0x0838be1c         @ borrowed payload: free + malloc
//! 0838bdf8  ldr  r0,[r4,#0x10]      @ db
//! 0838bdfc  mov  r2,r5
//! 0838be00  bl   0x083749f4         @ db_realloc_or_free(db, zMalloc, n)
//! 0838be04  str  r0,[r4,#0x24]      @ zMalloc = grown
//! 0838be08  cmp  r0,#0x0
//! 0838be0c  str  r0,[r4,#0x14]      @ z = grown
//! 0838be10  moveq r0,#0x1
//! 0838be14  strheq r0,[r4,#0x1c]    @ realloc failed: flags = MEM_Null
//! 0838be18  b    0x0838be54         @ (payload already moved)
//! 0838be1c  ldr  r0,[r4,#0x24]
//! 0838be20  bl   0x083906f4         @ sqlite3_free(zMalloc)
//! 0838be24  ldr  r0,[r4,#0x10]      @ db
//! 0838be28  mov  r1,r5
//! 0838be2c  bl   0x08374960         @ db_malloc_raw(db, n)
//! 0838be30  str  r0,[r4,#0x24]      @ zMalloc = fresh block
//! 0838be34  cmp  r6,#0x0
//! 0838be38  ldrne r1,[r4,#0x14]     @ z
//! 0838be3c  cmpne r1,#0x0
//! 0838be40  ldrne r0,[r4,#0x24]     @ zMalloc
//! 0838be44  cmpne r0,#0x0
//! 0838be48  cmpne r1,r0
//! 0838be4c  ldrne r2,[r4,#0x18]     @ n (payload length)
//! 0838be50  blne 0x08037db0         @ __rt_memcpy(zMalloc, z, n)
//! 0838be54  ldrh r0,[r4,#0x1c]      @ flags
//! 0838be58  tst  r0,#0x40           @ MEM_Dyn?
//! 0838be5c  ldrne r1,[r4,#0x20]     @ xDel
//! 0838be60  cmpne r1,#0x0
//! 0838be64  ldrne r0,[r4,#0x14]     @ z, still the OLD payload here
//! 0838be68  blxne r1                @ xDel(z)
//! 0838be6c  ldr  r0,[r4,#0x24]
//! 0838be70  str  r0,[r4,#0x14]      @ z = zMalloc
//! 0838be74  ldrh r1,[r4,#0x1c]
//! 0838be78  cmp  r0,#0x0
//! 0838be7c  moveq r0,#0x7           @ SQLITE_NOMEM
//! 0838be80  bic  r1,r1,#0x180       @ flags &= ~(MEM_Static|MEM_Ephem)
//! 0838be84  strh r1,[r4,#0x1c]
//! 0838be88  mov  r1,#0x0
//! 0838be8c  movne r0,#0x0           @ SQLITE_OK
//! 0838be90  str  r1,[r4,#0x20]      @ xDel = NULL
//! 0838be94  ldmia sp!, {r4,r5,r6,pc}
//! ```
//!
//! ### Algorithm
//!
//! Nothing happens while the cell already owns a `zMalloc` block whose
//! tracked size (`sqlite3MallocSize`) covers the request. Otherwise the
//! request is rounded up to a 32-byte floor (signed `movle`), and:
//!
//! - `preserve && z == zMalloc` (the payload already lives in the owned
//!   block): the block is resized in place through
//!   `sqlite3DbReallocOrFree` @ 0x083749f4, which frees the old block
//!   on failure — `z` and `zMalloc` are both stamped with the result,
//!   and a failed resize stamps the whole flags halfword `MEM_Null`
//!   (1) before joining the common tail.
//! - otherwise: the old `zMalloc` is released (`sqlite3_free` @
//!   0x083906f4, NULL-tolerant) and a fresh `sqlite3DbMallocRaw` @
//!   0x08374960 block takes its place. The free runs BEFORE the
//!   malloc, so a failed malloc has already dropped the old block.
//!
//! A `preserve` grow whose payload is borrowed (`z` non-NULL, not the
//! `zMalloc` block it is about to become) then copies `n` payload
//! bytes into the owned block (`__rt_memcpy` @ 0x08037db0). An
//! externally-owned payload (`MEM_Dyn` with a non-NULL `xDel`) is
//! handed to its destructor — with the OLD `z`, the store of
//! `z = zMalloc` comes later. Finally `z = zMalloc`, the ownership
//! bits `MEM_Static | MEM_Ephem` (`0x180`) are cleared — UNCONDITIONALLY,
//! on success and failure alike — `xDel` is NULLed, and the return is
//! `SQLITE_NOMEM` (7) when `zMalloc` came back NULL, else `SQLITE_OK`.
//!
//! Call sites (binary-scanned):
//!
//! - `bl` @ 0x082b3960 — inside FUN_082b38e0.
//! - `bl` @ 0x083876d8 / 0x08388788 / 0x08389a40 — inside the 16 KB
//!   vdbe engine routine FUN_08386ef8 (three calls).
//! - `bl` @ 0x0838b7f8 / 0x0838b878 — inside FUN_0838b67c.
//! - `bl` @ 0x0838bb70 — inside `sqlite3VdbeMemMakeWriteable` @
//!   0x0838bb30.
//! - `bl` @ 0x0838bbec — inside `sqlite3VdbeMemExpandBlob` @ 0x0838bbb4.
//! - `bl` @ 0x0838bd40 — inside FUN_0838bcb4.
//! - `bl` @ 0x0838bfe4 — inside [`vdbe_mem_nul_terminate`](super::vdbe_mem_nul_terminate)
//!   @ 0x0838bfb0 (ported; its ops-slot default is this port).
//! - `bl` @ 0x0838c200 — inside [`vdbe_mem_set_str`](super::vdbe_mem_set_str)
//!   @ 0x0838c158 (ported; still dispatching through its own seam).
//! - `bl` @ 0x0838c348 — inside [`vdbe_mem_stringify`](super::vdbe_mem_stringify)
//!   @ 0x0838c32c (ported).
//! - `bl` @ 0x0838eed8 — inside FUN_0838ee8c.
//!
//! ### Deviations
//!
//! - `sqlite3MallocSize` @ 0x0837d374 (20 bytes, unported) is
//!   reproduced inline by [`tracked_block_size`]: the original's exact
//!   two-word walk of the tag-57 tracked header (`pad` at payload-4,
//!   size word at `payload - pad - 8`), NULL yielding 0. It is a pure
//!   read of the layout `heap::tracked` documents, so no ops slot.
//! - Firmware deviation from upstream 3.5.9, kept as-is: the flags
//!   mask is `bic #0x180` (`MEM_Static | MEM_Ephem`) applied
//!   UNCONDITIONALLY — upstream clears `MEM_Ephem | MEM_Static |
//!   MEM_Dyn` and only on success. Here `MEM_Dyn` (0x40) survives the
//!   grow (with `xDel` NULLed), and a failed free+malloc grow keeps
//!   the type bits instead of becoming `MEM_Null` (only the failed
//!   REALLOC arm stamps `MEM_Null`, via `strheq`).
//! - The allocator family is called directly through its ported twins:
//!   `db_realloc_or_free` @ 0x083749f4 and `db_malloc_raw` @ 0x08374960
//!   ([`super::mem`]), `tracked_free` @ 0x083906f4
//!   ([`crate::heap::tracked`]), `__rt_memcpy` @ 0x08037db0
//!   ([`crate::libc::rt_memcpy`]). `Mem` field access goes through the
//!   typed `repr(C)` struct (offsets asserted on 32-bit targets in
//!   `sqlite/vdbe.rs`).

use crate::heap::tracked::{tracked_free, BLOCK_HEADER_SIZE};
use crate::libc::rt_memcpy::__rt_memcpy;
use super::mem::{db_malloc_raw, db_realloc_or_free};
use super::mem_release::FLAG_DYN;
use super::value_new::MEM_NULL;
use super::value_set_str::SQLITE_NOMEM;
use super::vdbe::{Mem, MEM_STATIC};
use super::vdbe_mem_realify::SQLITE_OK;
use super::vdbe_mem_shallow_copy::MEM_EPHEM;

/// Minimum request the original allocates — the signed
/// `cmp r5,#0x20; movle r5,#0x20` floor.
const MIN_GROWTH: i32 = 0x20;

/// `sqlite3MallocSize` @ 0x0837d374, reproduced inline (see the module
/// header): the tag-57 tracked block's requested-size word, recovered
/// exactly the way the original walks it — `pad` at `payload - 4`,
/// size at `payload - pad - `[`BLOCK_HEADER_SIZE`]. NULL has no block,
/// so 0.
unsafe fn tracked_block_size(payload: *mut u8) -> i32 {
    if payload.is_null() {
        return 0;
    }
    let pad = (payload.sub(4) as *const u32).read() as usize;
    let raw = payload.sub(pad).sub(BLOCK_HEADER_SIZE);
    (raw as *const i32).read()
}

/// vdbe_mem_grow — original: `FUN_0838bdb0` @ 0x0838bdb0 (232 bytes;
/// 13 `bl` call sites).
///
/// `sqlite3VdbeMemGrow`: guarantee `p_mem` owns at least `size` bytes
/// of payload storage (`zMalloc`). An owned block whose tracked size
/// already covers the request is kept; otherwise the request is
/// floored to 32 bytes and the cell is regrown — by reallocating in
/// place when `preserve` is set and the payload already lives in the
/// owned block, or by freeing the old block and mallocing a fresh one.
/// A preserved payload that was borrowed is then copied (`n` bytes)
/// into the owned block; a `MEM_Dyn` payload with a destructor is
/// released through `xDel` with the OLD `z`. The tail makes `z =
/// zMalloc`, clears `MEM_Static | MEM_Ephem`, NULLs `xDel`, and
/// returns `SQLITE_NOMEM` when the grow produced no block, else
/// `SQLITE_OK`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_grow(p_mem: *mut Mem, size: i32, preserve: i32) -> i32 {
    let mut size = size;
    if (*p_mem).z_malloc.is_null() || tracked_block_size((*p_mem).z_malloc) < size {
        if size <= MIN_GROWTH {
            size = MIN_GROWTH;
        }
        if preserve != 0 && (*p_mem).z == (*p_mem).z_malloc {
            let grown = db_realloc_or_free((*p_mem).db, (*p_mem).z_malloc, size);
            (*p_mem).z_malloc = grown;
            (*p_mem).z = grown;
            if grown.is_null() {
                (*p_mem).flags = MEM_NULL;
            }
        } else {
            tracked_free((*p_mem).z_malloc);
            (*p_mem).z_malloc = db_malloc_raw((*p_mem).db, size);
        }
    }
    let z = (*p_mem).z;
    let z_malloc = (*p_mem).z_malloc;
    if preserve != 0 && !z.is_null() && !z_malloc.is_null() && z != z_malloc {
        __rt_memcpy(z_malloc, z, (*p_mem).n as usize);
    }
    if (*p_mem).flags & FLAG_DYN != 0 {
        let x_del: Option<unsafe extern "C" fn(*mut u8)> = core::mem::transmute((*p_mem).x_del);
        if let Some(x_del) = x_del {
            x_del((*p_mem).z);
        }
    }
    let z_malloc = (*p_mem).z_malloc;
    (*p_mem).z = z_malloc;
    (*p_mem).flags &= !(MEM_STATIC | MEM_EPHEM);
    let rc = if z_malloc.is_null() { SQLITE_NOMEM } else { SQLITE_OK };
    (*p_mem).x_del = core::ptr::null_mut();
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::ALLOC_STATS;
    use crate::heap::veneers::tests as heap_tests;
    use crate::sqlite::mem::{
        tests as mem_tests, AllocDenyRecord, ALLOC_DENY_SCHEDULE, ALLOC_DENY_TOTAL,
        DB_MEM_OPS, DEFAULT_ALLOC_PRESSURE_OPS, DEFAULT_DB_MEM_OPS, ALLOC_PRESSURE_OPS,
    };
    use crate::sqlite::vdbe_mem_nul_terminate::{
        vdbe_mem_nul_terminate, VdbeMemNulTerminateOps, DEFAULT_VDBE_MEM_NUL_TERMINATE_OPS,
        VDBE_MEM_NUL_TERMINATE_OPS,
    };
    use std::sync::MutexGuard;

    /// `MEM_Str`, for fixtures.
    const MEM_STR: u16 = 0x0002;
    /// `MEM_Term`, for fixtures.
    const MEM_TERM: u16 = 0x0020;
    /// Tag the tracked free hands the heap (`mov r1, #57`).
    const TAG_TRACKED: usize = 57;

    /// A fake tag-57 tracked block with the exact header layout
    /// `heap::tracked` documents AND the allocator's own placement
    /// formula: raw 32-aligned, size word at raw+0, sign word at
    /// raw+4, payload at `data = (raw + 8 + 36) & !31` = raw+32, `pad`
    /// word at data-4 (pad = data - base = 32 - 8 = 24). The real
    /// formula matters: `sqlite3_realloc` RECOMPUTES the old payload
    /// address from the raw block instead of walking the pad word.
    #[repr(C, align(32))]
    struct FakeBlock {
        size: i32,
        sign: i32,
        _pad_bytes: [u8; 20],
        pad: u32,
        payload: [u8; 96],
    }

    impl FakeBlock {
        fn new(capacity: i32) -> Self {
            FakeBlock { size: capacity, sign: 0, _pad_bytes: [0; 20], pad: 24, payload: [0xa5; 96] }
        }
        fn data(&mut self) -> *mut u8 {
            self.payload.as_mut_ptr()
        }
        /// The raw block pointer, the way `tracked_free` recovers it.
        fn raw(&mut self) -> *mut u8 {
            (self as *mut FakeBlock).cast::<u8>()
        }
    }

    /// A stand-in destructor for the `MEM_Dyn` arm.
    static mut X_DEL_LOG: std::vec::Vec<usize> = std::vec::Vec::new();

    unsafe extern "C" fn recording_x_del(z: *mut u8) {
        (*core::ptr::addr_of_mut!(X_DEL_LOG)).push(z as usize);
    }

    /// Serializes against every test that swaps `DB_MEM_OPS` /
    /// `ALLOC_PRESSURE_OPS` (they all take `mem::tests::OPS_LOCK`),
    /// installs the veneers recording heap, and resets the allocator
    /// dispatch, the deny schedule, and the accounting block to their
    /// at-rest defaults. Lock order is `mem::tests::OPS_LOCK` before
    /// the veneers lock — the same order `mem::tests::pressure()`
    /// uses, so the two fixtures cannot cycle. Held for the whole
    /// test.
    struct Bench {
        _mem: MutexGuard<'static, ()>,
        _heap: MutexGuard<'static, ()>,
    }

    /// For tests that drive the REAL allocator (the defaults wired in
    /// `DB_MEM_OPS`).
    fn bench() -> Bench {
        let mem = mem_tests::OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap = heap_tests::mock_heap();
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
        }
        reset_allocator_state();
        Bench { _mem: mem, _heap: heap }
    }

    /// For tests that record the `DB_MEM_OPS` slots instead:
    /// [`mem_tests::install_recorder`] takes the mem lock (same order
    /// as [`bench`]) and swaps in the recording allocator.
    fn recorder_bench(result: *mut u8) -> Bench {
        let mem = mem_tests::install_recorder(result);
        let heap = heap_tests::mock_heap();
        reset_allocator_state();
        Bench { _mem: mem, _heap: heap }
    }

    /// The at-rest pressure/schedule/stats state. `DB_MEM_OPS` is
    /// deliberately not touched: [`bench`] wants the defaults,
    /// [`recorder_bench`] the recording swap it just installed.
    fn reset_allocator_state() {
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(ALLOC_PRESSURE_OPS),
                DEFAULT_ALLOC_PRESSURE_OPS,
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(ALLOC_DENY_SCHEDULE),
                [AllocDenyRecord {
                    countdown: 0,
                    deny_budget: 0,
                    benign_denies: 0,
                    deny_count: 0,
                    active: 0,
                    benign_mode: 0,
                }],
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!(ALLOC_DENY_TOTAL), 0);
            let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
            (*stats).current_bytes = 0;
            (*stats).peak_bytes = 0;
            (*stats).lock_flag = 0;
            (*stats).soft_limit = 0;
            (*stats).soft_limit_callback = 0;
            (*stats).soft_limit_callback_active = 0;
            (*core::ptr::addr_of_mut!(X_DEL_LOG)).clear();
        }
    }

    /// A `Mem` with distinguishable garbage in every field, so an
    /// unintended write shows up as a mismatch.
    fn garbage_mem(flags: u16, n: i32) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z: 0x0bad_2000usize as *mut u8,
            n,
            flags,
            value_type: 0x5b,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    #[test]
    fn sufficient_owned_capacity_grows_nothing() {
        let _bench = recorder_bench(0x0bad_5000usize as *mut u8);
        let mut block = FakeBlock::new(64);
        let z = block.data();
        let mut mem = garbage_mem(MEM_STR | MEM_TERM | MEM_STATIC | MEM_EPHEM, 17);
        mem.z = z;
        mem.z_malloc = z;
        mem.x_del = core::ptr::null_mut();

        assert_eq!(unsafe { vdbe_mem_grow(&mut mem, 8, 1) }, SQLITE_OK);
        assert_eq!(mem.z, z, "the owned block is kept");
        assert_eq!(mem.z_malloc, z);
        assert_eq!(mem.n, 17, "grow never touches the payload length");
        assert_eq!(mem.flags, MEM_STR | MEM_TERM, "ownership bits cleared, the rest kept");
        assert!(mem.x_del.is_null());
        assert!(mem_tests::realloc_log().is_empty(), "no allocator call at all");
        assert_eq!(unsafe { &*core::ptr::addr_of!(X_DEL_LOG) }.len(), 0);
    }

    #[test]
    fn requests_at_or_below_32_round_up_to_the_floor() {
        let mut target = [0u8; 64];
        let _bench = recorder_bench(target.as_mut_ptr());
        let mut db = mem_tests::Connection::healthy();

        for (request, expected) in [(1, 32), (0, 32), (-5, 32), (32, 32), (33, 33), (100, 100)] {
            let mut mem = garbage_mem(MEM_STR, 0);
            mem.db = db.ptr();
            mem.z = core::ptr::null_mut();
            mem.z_malloc = core::ptr::null_mut();
            mem.x_del = core::ptr::null_mut();
            assert_eq!(
                unsafe { vdbe_mem_grow(&mut mem, request, 0) },
                SQLITE_OK,
                "request={request}"
            );
            assert_eq!(
                mem_tests::realloc_log().last().copied(),
                Some((0, expected)),
                "request={request}"
            );
            assert_eq!(mem.z, target.as_mut_ptr(), "request={request}");
            assert_eq!(mem.z_malloc, target.as_mut_ptr(), "request={request}");
        }
    }

    #[test]
    fn preserve_on_a_null_owned_block_takes_the_realloc_arm() {
        let mut target = [0u8; 64];
        let _bench = recorder_bench(target.as_mut_ptr());
        let mut db = mem_tests::Connection::healthy();

        // z == z_malloc == NULL satisfies the realloc arm's test.
        let mut mem = garbage_mem(MEM_STR, 0);
        mem.db = db.ptr();
        mem.z = core::ptr::null_mut();
        mem.z_malloc = core::ptr::null_mut();
        mem.x_del = core::ptr::null_mut();
        assert_eq!(unsafe { vdbe_mem_grow(&mut mem, 10, 1) }, SQLITE_OK);
        assert_eq!(mem_tests::realloc_log(), std::vec![(0, 32)]);
        assert_eq!(mem.z, target.as_mut_ptr());
        assert_eq!(mem.z_malloc, target.as_mut_ptr());
    }

    #[test]
    fn preserve_with_owned_buffer_reallocates_in_place() {
        let mut target = [0u8; 128];
        let _bench = recorder_bench(target.as_mut_ptr());
        let mut db = mem_tests::Connection::healthy();
        let mut block = FakeBlock::new(32);
        let z = block.data();
        let mut mem = garbage_mem(MEM_STR | MEM_STATIC, 9);
        mem.db = db.ptr();
        mem.z = z;
        mem.z_malloc = z;
        mem.x_del = core::ptr::null_mut();

        assert_eq!(unsafe { vdbe_mem_grow(&mut mem, 100, 1) }, SQLITE_OK);
        assert_eq!(
            mem_tests::realloc_log(),
            std::vec![(z as usize, 100)],
            "the old owned block is resized, not freed + malloced"
        );
        assert_eq!(mem.z, target.as_mut_ptr());
        assert_eq!(mem.z_malloc, target.as_mut_ptr());
        assert_eq!(mem.flags, MEM_STR, "MEM_Static cleared");
        assert!(mem.x_del.is_null());
        assert_eq!(heap_tests::free_log().0, 0, "a successful resize frees nothing");
    }

    #[test]
    fn preserve_with_borrowed_payload_copies_into_the_fresh_block() {
        let mut target = [0u8; 64];
        let _bench = recorder_bench(target.as_mut_ptr());
        let mut db = mem_tests::Connection::healthy();
        let payload = *b"hello world";
        let mut mem = garbage_mem(MEM_STR | MEM_EPHEM, 5);
        mem.db = db.ptr();
        mem.z = payload.as_ptr() as *mut u8;
        mem.z_malloc = core::ptr::null_mut();
        mem.x_del = core::ptr::null_mut();

        assert_eq!(unsafe { vdbe_mem_grow(&mut mem, 10, 1) }, SQLITE_OK);
        assert_eq!(mem_tests::realloc_log(), std::vec![(0, 32)]);
        assert_eq!(&target[..5], b"hello", "n payload bytes are preserved");
        assert_eq!(&target[5..], &[0u8; 59][..], "only n bytes are copied");
        assert_eq!(mem.z, target.as_mut_ptr(), "z now lives in the owned block");
        assert_eq!(mem.z_malloc, target.as_mut_ptr());
        assert_eq!(mem.flags, MEM_STR, "MEM_Ephem cleared");
    }

    #[test]
    fn no_preserve_frees_the_owned_block_and_skips_the_copy() {
        let mut target = [0u8; 64];
        let _bench = recorder_bench(target.as_mut_ptr());
        let mut db = mem_tests::Connection::healthy();
        let mut block = FakeBlock::new(32);
        block.payload[..5].copy_from_slice(b"abcde");
        let z = block.data();
        let raw = block.raw();
        let mut mem = garbage_mem(MEM_STR, 5);
        mem.db = db.ptr();
        mem.z = z;
        mem.z_malloc = z;
        mem.x_del = core::ptr::null_mut();

        assert_eq!(unsafe { vdbe_mem_grow(&mut mem, 64, 0) }, SQLITE_OK);
        let (free_calls, freed, tag) = heap_tests::free_log();
        assert_eq!(free_calls, 1, "the old block is released first");
        assert_eq!(freed, raw);
        assert_eq!(tag, TAG_TRACKED);
        assert_eq!(mem_tests::realloc_log(), std::vec![(0, 64)]);
        assert_eq!(&target[..5], &[0u8; 5], "no preserve: the payload is NOT copied");
        assert_eq!(mem.z, target.as_mut_ptr());
        assert_eq!(mem.z_malloc, target.as_mut_ptr());
    }

    #[test]
    fn failed_realloc_nulls_the_cell_and_reports_nomem() {
        let _bench = recorder_bench(core::ptr::null_mut());
        let mut db = mem_tests::Connection::healthy();
        let mut block = FakeBlock::new(32);
        let z = block.data();
        let raw = block.raw();
        let mut mem = garbage_mem(MEM_STR | MEM_TERM, 9);
        mem.db = db.ptr();
        mem.z = z;
        mem.z_malloc = z;
        mem.x_del = core::ptr::null_mut();

        assert_eq!(unsafe { vdbe_mem_grow(&mut mem, 100, 1) }, SQLITE_NOMEM);
        assert!(mem.z.is_null(), "the failed-or-free result is stamped");
        assert!(mem.z_malloc.is_null());
        assert_eq!(mem.flags, MEM_NULL, "the realloc arm's strheq: the whole halfword");
        assert_eq!(db.failed_flag(), 1, "the connection records the failure");
        let (free_calls, freed, _) = heap_tests::free_log();
        assert_eq!(free_calls, 1, "ReallocOrFree drops the old block");
        assert_eq!(freed, raw);
    }

    #[test]
    fn failed_malloc_keeps_the_type_bits_and_reports_nomem() {
        let _bench = recorder_bench(core::ptr::null_mut());
        let mut db = mem_tests::Connection::healthy();
        let payload = *b"ephemeral";
        let mut mem = garbage_mem(MEM_STR | MEM_STATIC | MEM_EPHEM, 9);
        mem.db = db.ptr();
        mem.z = payload.as_ptr() as *mut u8;
        mem.z_malloc = core::ptr::null_mut();
        mem.x_del = core::ptr::null_mut();

        assert_eq!(unsafe { vdbe_mem_grow(&mut mem, 10, 0) }, SQLITE_NOMEM);
        assert!(mem.z.is_null());
        assert!(mem.z_malloc.is_null());
        assert_eq!(
            mem.flags,
            MEM_STR,
            "firmware deviation: the unconditional bic clears the ownership bits \
             but does NOT stamp MEM_Null on the malloc arm"
        );
        assert!(mem.x_del.is_null());
        assert_eq!(db.failed_flag(), 1);
    }

    #[test]
    fn dynamic_payload_is_destructed_with_the_old_z() {
        let _bench = bench();
        let mut block = FakeBlock::new(64);
        let z_malloc = block.data();
        let external = *b"world!";
        let z = external.as_ptr() as *mut u8;
        let mut mem = garbage_mem(MEM_STR | FLAG_DYN, 5);
        mem.z = z;
        mem.z_malloc = z_malloc;
        mem.x_del = recording_x_del as *mut u8;

        assert_eq!(unsafe { vdbe_mem_grow(&mut mem, 10, 1) }, SQLITE_OK);
        assert_eq!(
            unsafe { &*core::ptr::addr_of!(X_DEL_LOG) }.as_slice(),
            &[z as usize],
            "xDel runs once, on the OLD z (the z = zMalloc store comes later)"
        );
        assert_eq!(&block.payload[..5], b"world", "the payload moved into the owned block");
        assert_eq!(mem.z, z_malloc);
        assert_eq!(mem.z_malloc, z_malloc);
        assert_eq!(
            mem.flags,
            MEM_STR | FLAG_DYN,
            "firmware deviation: bic #0x180 leaves MEM_Dyn set"
        );
        assert!(mem.x_del.is_null(), "the destructor slot is cleared either way");
    }

    /// The just-ported `vdbe_mem_nul_terminate` reaches this grow
    /// through its ops slot: install the real port (the wired default)
    /// and drive both the in-place and the regrow paths end to end.
    /// Takes the terminator's own lock so its recording-mock tests
    /// cannot swap the slot under us.
    #[test]
    fn nul_terminate_integration_through_the_real_grow() {
        let _bench = bench();
        let _nt = crate::sqlite::vdbe_mem_nul_terminate::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_NUL_TERMINATE_OPS),
                VdbeMemNulTerminateOps { grow: vdbe_mem_grow },
            );
        }
        let mut db = mem_tests::Connection::healthy();

        // In-place: the owned block already has room for the trailer.
        let mut block = FakeBlock::new(64);
        block.payload[..3].copy_from_slice(b"abc");
        let z = block.data();
        let mut mem = garbage_mem(MEM_STR, 3);
        mem.db = db.ptr();
        mem.z = z;
        mem.z_malloc = z;
        mem.x_del = core::ptr::null_mut();
        assert_eq!(unsafe { vdbe_mem_nul_terminate(&mut mem) }, SQLITE_OK);
        assert_eq!(mem.z, z, "capacity sufficient: no relocation");
        assert_eq!(&block.payload[3..5], &[0, 0], "the double NUL trailer");
        assert_eq!(&block.payload[..3], b"abc", "the payload is intact");
        assert_eq!(mem.flags, MEM_STR | MEM_TERM);

        // Regrow: 4 bytes owned, 5 needed — the realloc arm moves the
        // cell into a real tracked block. The ported sqlite3_realloc
        // relies on the heap's copy-on-move (it finds the old payload
        // INSIDE the new raw block), which the veneers recording
        // realloc does not do — so this half installs a bump realloc
        // that copies the raw block, the way mem.rs's arena does.
        #[repr(align(32))]
        struct Arena([u8; 512]);
        static mut ARENA: Arena = Arena([0; 512]);
        static mut ARENA_USED: usize = 0;
        static mut COPY_LOG: std::vec::Vec<(usize, usize)> = std::vec::Vec::new();
        unsafe extern "C" fn copying_realloc(
            _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
            ptr: *mut u8,
            size: usize,
            _tag: usize,
            _copy_on_move: usize,
        ) -> *mut u8 {
            (*core::ptr::addr_of_mut!(COPY_LOG)).push((ptr as usize, size));
            let used = ARENA_USED;
            let aligned = (size + 31) & !31;
            if used + aligned > 512 {
                return core::ptr::null_mut();
            }
            ARENA_USED = used + aligned;
            let new = core::ptr::addr_of_mut!(ARENA).cast::<u8>().add(used);
            // The tracked raw block is `old requested size + 44` bytes.
            let old_size = (ptr as *const i32).read() as usize;
            core::ptr::copy_nonoverlapping(ptr, new, old_size + 0x24 + 8);
            new
        }
        unsafe {
            ARENA_USED = 0;
            (*core::ptr::addr_of_mut!(COPY_LOG)).clear();
            let heap_ops = core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS);
            (*heap_ops).realloc = copying_realloc;
        }
        let mut small = FakeBlock::new(4);
        small.payload[..3].copy_from_slice(b"xyz");
        let old = small.data();
        let old_raw = small.raw();
        let mut mem = garbage_mem(MEM_STR, 3);
        mem.db = db.ptr();
        mem.z = old;
        mem.z_malloc = old;
        mem.x_del = core::ptr::null_mut();
        assert_eq!(unsafe { vdbe_mem_nul_terminate(&mut mem) }, SQLITE_OK);
        assert!(!mem.z.is_null() && mem.z != old, "the grow relocated the payload");
        assert_eq!(mem.z, mem.z_malloc);
        unsafe {
            assert_eq!(*mem.z, b'x');
            assert_eq!(*mem.z.add(1), b'y');
            assert_eq!(*mem.z.add(2), b'z');
            assert_eq!(*mem.z.add(3), 0, "z[n]");
            assert_eq!(*mem.z.add(4), 0, "z[n+1]");
        }
        assert_eq!(mem.flags, MEM_STR | MEM_TERM);
        assert_eq!(
            unsafe { &*core::ptr::addr_of!(COPY_LOG) }.as_slice(),
            &[(old_raw as usize, 32 + 0x24 + 8)],
            "the regrow went through the heap realloc with the tracked size"
        );

        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_NUL_TERMINATE_OPS),
                DEFAULT_VDBE_MEM_NUL_TERMINATE_OPS,
            );
        }
    }
}
