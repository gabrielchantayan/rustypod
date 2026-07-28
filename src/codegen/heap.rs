//! The JIT code generator's block arena — `cg_heap_t` in Vincent's
//! `codegen.h`. Every IR object (virtual registers, instructions,
//! register lists) is bump-allocated out of it and nothing is ever freed
//! individually; the whole arena dies with the module.
//!
//! Ported here (call counts binary-scanned from osos.dec, not osos.asm):
//!
//! - `cg_heap_alloc` — original: `FUN_082c1a08` @ 0x082c1a08 (112 bytes;
//!   **19 `bl` + 1 tail `b` call sites**). The bump allocator, and the
//!   blocker that kept the whole IR cluster unported.
//! - `cg_heap_block_create` — original: `FUN_082c56e4` @ 0x082c56e4
//!   (52 bytes; 2 `bl` call sites — `cg_heap_alloc` and
//!   `cg_heap_create`). Allocates one 16-byte block header plus its
//!   payload.
//! - `cg_heap_create` — original: `FUN_082c1a78` @ 0x082c1a78 (40 bytes).
//!   Allocates the 8-byte arena head and its first block.
//! - `cg_heap_destroy` — original: `FUN_082c1aa0` @ 0x082c1aa0
//!   (60 bytes). Walks the block chain freeing payload and header, then
//!   frees the arena head.
//!
//! Layout (both structures are exactly the sizes the originals `malloc`):
//!
//! ```text
//! cg_heap_block_t (16 bytes on target)
//!   +0x00  next      previous block, newest first
//!   +0x04  base      payload from malloc(total)
//!   +0x08  total     payload capacity
//!   +0x0c  current   bytes handed out so far
//!
//! cg_heap_t (8 bytes on target)
//!   +0x00  current     newest block
//!   +0x04  block_size  default payload size for new blocks
//! ```
//!
//! `cg_heap_alloc`'s algorithm, exactly as the assembly has it:
//! round the request up to a multiple of 8; if `total - current` is
//! (unsigned) less than that, create a fresh block of
//! `max(heap->block_size, rounded)` bytes and push it on the front of the
//! chain; then carve `base + current`, advance `current`, **zero the
//! carved bytes** (`bl 0x08037dc8`, the ROM thunk to `memzero`
//! @ 0x220002d4 — the mirror of osos `memzero` @ 0x080002d4) and return
//! it. The zero-fill is load-bearing for the IR: neither
//! `cg_virtual_reg_create` nor `cg_inst_create_base` ever writes the
//! record's `next` link, so list termination depends on it.
//!
//! Growth never reuses the space left in the old block; it is simply
//! abandoned. There are no NULL checks anywhere in the original — a
//! failed `malloc` faults on the first field store — and the port keeps
//! that (it is the original's contract, and the arena is only used by the
//! JIT, which runs with the GL heap warm).
//!
//! Deviations:
//! - `malloc`/`free`/`memzero` are reached through the [`CG_HEAP_OPS`]
//!   dispatch table instead of direct `bl`s, the same pattern as
//!   heap/veneers.rs and runtime/malloc_rt.rs. Every default is the real
//!   port (`malloc` @ 0x0802edac, `free` @ 0x0802edc8, `memzero`
//!   @ 0x080002d4); host tests swap in a host allocator because the wired
//!   `malloc` bottoms out in the retailOS heap core, whose default heap
//!   lives at the fixed target address 0x08a1a710.
//! - `CgHeapBlock`/`CgHeap` are `#[repr(C)]` structs rather than
//!   word-indexed blobs: their layout is fully recovered, so on the
//!   ARMv5TE target they reproduce the original 16/8-byte records exactly
//!   (`size_of` folds to the originals' `mov r0, #16` / `mov r0, #8`),
//!   while on a 64-bit host the fields stay disjoint.
//! - `total - current` is a `wrapping_sub`, matching the original's
//!   unsigned `sub`; it cannot underflow in practice (`current <= total`
//!   is an invariant of the bump) but a debug-build panic would be a
//!   behavior change.

/// Allocation granularity of the arena: `bic r5, r0, #7` after
/// `add r0, r1, #7`.
const CG_HEAP_ALIGN: usize = 8;

/// One arena block: a `malloc`ed payload plus the bump cursor over it.
/// 16 bytes on the ARMv5TE target, matching the original's `malloc(16)`.
#[repr(C)]
pub struct CgHeapBlock {
    /// The block this one superseded (the chain runs newest to oldest).
    pub next: *mut CgHeapBlock,
    /// Payload base, from `malloc(total)`.
    pub base: *mut u8,
    /// Payload capacity in bytes.
    pub total: usize,
    /// Bytes handed out of this block so far.
    pub current: usize,
}

/// The arena head. 8 bytes on the ARMv5TE target, matching the
/// original's `malloc(8)`.
#[repr(C)]
pub struct CgHeap {
    /// Newest block; allocations are carved from this one.
    pub current: *mut CgHeapBlock,
    /// Payload size used for blocks created after the first.
    pub block_size: usize,
}

/// Indirect dispatch for the three C-runtime entry points the arena
/// calls, so host tests can supply an allocator (see the module header).
#[derive(Clone, Copy)]
pub struct CgHeapOps {
    /// `malloc` @ 0x0802edac.
    pub alloc: unsafe extern "C" fn(size: usize) -> *mut u8,
    /// `free` @ 0x0802edc8.
    pub free: unsafe extern "C" fn(ptr: *mut u8),
    /// `memzero` @ 0x080002d4, reached in the original through the ROM
    /// thunk 0x08037dc8 -> 0x220002d4.
    pub zero: unsafe extern "C" fn(dst: *mut u8, len: usize) -> *mut u8,
}

/// Wired defaults: the real ports of every callee.
pub const DEFAULT_CG_HEAP_OPS: CgHeapOps = CgHeapOps {
    alloc: crate::runtime::malloc_rt::malloc,
    free: crate::runtime::malloc_rt::free,
    zero: crate::libc::memzero::memzero,
};

/// The active C-runtime bindings for the arena. Host tests replace this;
/// on target it stays at the wired defaults.
pub static mut CG_HEAP_OPS: CgHeapOps = DEFAULT_CG_HEAP_OPS;

/// Volatile read of the ops table — without it LLVM constant-folds the
/// indirect calls back to the defaults and inlines them.
#[inline(always)]
fn cg_heap_ops() -> CgHeapOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CG_HEAP_OPS)) }
}

/// cg_heap_block_create — original: `FUN_082c56e4` @ 0x082c56e4
/// (52 bytes, 2 call sites).
///
/// `malloc`s a 16-byte header and a `size`-byte payload, then initializes
/// the header to an empty block with no successor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_heap_block_create(size: usize) -> *mut CgHeapBlock {
    let ops = cg_heap_ops();
    let block = (ops.alloc)(core::mem::size_of::<CgHeapBlock>()) as *mut CgHeapBlock;
    let base = (ops.alloc)(size);
    // Original: `stmib r4, {r0, r5}` — base then total, then current, then next.
    (*block).base = base;
    (*block).total = size;
    (*block).current = 0;
    (*block).next = core::ptr::null_mut();
    block
}

/// cg_heap_create — original: `FUN_082c1a78` @ 0x082c1a78 (40 bytes).
///
/// `malloc`s the 8-byte arena head, gives it a first block of
/// `block_size` bytes and remembers `block_size` as the default size for
/// later blocks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_heap_create(block_size: usize) -> *mut CgHeap {
    let heap = (cg_heap_ops().alloc)(core::mem::size_of::<CgHeap>()) as *mut CgHeap;
    let block = cg_heap_block_create(block_size);
    (*heap).current = block;
    (*heap).block_size = block_size;
    heap
}

/// cg_heap_alloc — original: `FUN_082c1a08` @ 0x082c1a08 (112 bytes,
/// 19 `bl` + 1 tail `b` call sites).
///
/// Bump-allocates `size` bytes, rounded up to 8, from the newest block,
/// pushing a fresh `max(block_size, rounded)`-byte block on the chain
/// first when the current one cannot satisfy the request. The returned
/// range is always zeroed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_heap_alloc(heap: *mut CgHeap, size: usize) -> *mut u8 {
    let rounded = (size + (CG_HEAP_ALIGN - 1)) & !(CG_HEAP_ALIGN - 1);

    let block = (*heap).current;
    if (*block).total.wrapping_sub((*block).current) < rounded {
        let mut fresh_size = (*heap).block_size;
        if fresh_size < rounded {
            fresh_size = rounded;
        }
        let fresh = cg_heap_block_create(fresh_size);
        (*fresh).next = (*heap).current;
        (*heap).current = fresh;
    }

    let block = (*heap).current;
    let carved = (*block).base.add((*block).current);
    (*block).current += rounded;
    (cg_heap_ops().zero)(carved, rounded);
    carved
}

/// cg_heap_destroy — original: `FUN_082c1aa0` @ 0x082c1aa0 (60 bytes).
///
/// Frees every block's payload and header, newest first, then the arena
/// head itself (the original tail-branches into `free` for that last
/// one).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_heap_destroy(heap: *mut CgHeap) {
    let ops = cg_heap_ops();
    let mut block = (*heap).current;
    while !block.is_null() {
        let base = (*block).base;
        let next = (*block).next;
        (ops.free)(base);
        (ops.free)(block as *mut u8);
        block = next;
    }
    (ops.free)(heap as *mut u8);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::alloc::{alloc as host_alloc_raw, dealloc as host_dealloc_raw, Layout};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the shared ops table across tests.
    static LOCK: Mutex<()> = Mutex::new(());

    /// Header the recording allocator prepends so `free` can rebuild the
    /// layout (16 bytes keeps the payload 16-aligned).
    const HDR: usize = 16;

    static mut ALLOC_SIZES: Vec<usize> = Vec::new();
    static mut FREED: Vec<usize> = Vec::new();

    unsafe extern "C" fn recording_alloc(size: usize) -> *mut u8 {
        (*core::ptr::addr_of_mut!(ALLOC_SIZES)).push(size);
        let layout = Layout::from_size_align(size + HDR, 16).unwrap();
        let raw = host_alloc_raw(layout);
        assert!(!raw.is_null());
        (raw as *mut usize).write(size);
        // Poison the payload so the arena's zero-fill is observable.
        core::ptr::write_bytes(raw.add(HDR), 0xa5, size);
        raw.add(HDR)
    }

    unsafe extern "C" fn recording_free(ptr: *mut u8) {
        (*core::ptr::addr_of_mut!(FREED)).push(ptr as usize);
        let raw = ptr.sub(HDR);
        let size = (raw as *mut usize).read();
        host_dealloc_raw(raw, Layout::from_size_align(size + HDR, 16).unwrap());
    }

    fn setup() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*core::ptr::addr_of_mut!(FREED)).clear();
            core::ptr::addr_of_mut!(CG_HEAP_OPS).write(CgHeapOps {
                alloc: recording_alloc,
                free: recording_free,
                // The real port stays wired: the zero-fill is behavior.
                zero: DEFAULT_CG_HEAP_OPS.zero,
            });
        }
        guard
    }

    fn teardown() {
        unsafe { core::ptr::addr_of_mut!(CG_HEAP_OPS).write(DEFAULT_CG_HEAP_OPS) };
    }

    fn alloc_sizes() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(ALLOC_SIZES)).clone() }
    }

    fn round8(n: usize) -> usize {
        (n + 7) & !7
    }

    #[test]
    fn create_makes_one_empty_block_of_the_requested_size() {
        let _g = setup();
        unsafe {
            let heap = cg_heap_create(256);
            assert_eq!(
                alloc_sizes(),
                std::vec![core::mem::size_of::<CgHeap>(), core::mem::size_of::<CgHeapBlock>(), 256],
                "arena head, block header, block payload"
            );
            assert_eq!((*heap).block_size, 256);
            let block = (*heap).current;
            assert!((*block).next.is_null());
            assert_eq!((*block).total, 256);
            assert_eq!((*block).current, 0);
            cg_heap_destroy(heap);
        }
        teardown();
    }

    #[test]
    fn allocations_bump_contiguously_and_round_up_to_eight() {
        let _g = setup();
        unsafe {
            let heap = cg_heap_create(1024);
            let base = (*(*heap).current).base;
            let mut expected = 0usize;
            // Every residue mod 8, including 0 (which must not round up).
            for size in [1usize, 8, 9, 16, 7, 40, 36, 20, 0, 63, 64] {
                let p = cg_heap_alloc(heap, size);
                assert_eq!(p, base.add(expected), "request {size} placement");
                expected += round8(size);
                assert_eq!((*(*heap).current).current, expected);
            }
            assert_eq!(alloc_sizes().len(), 3, "no block grew");
            cg_heap_destroy(heap);
        }
        teardown();
    }

    #[test]
    fn carved_bytes_are_zeroed_over_the_rounded_length() {
        let _g = setup();
        unsafe {
            let heap = cg_heap_create(256);
            // The payload arrived poisoned with 0xa5.
            let p = cg_heap_alloc(heap, 13);
            for i in 0..round8(13) {
                assert_eq!(p.add(i).read(), 0, "byte {i} must be zeroed");
            }
            assert_eq!(p.add(round8(13)).read(), 0xa5, "past the rounded length");
            cg_heap_destroy(heap);
        }
        teardown();
    }

    #[test]
    fn an_exact_fit_does_not_grow_but_one_byte_more_does() {
        let _g = setup();
        unsafe {
            let heap = cg_heap_create(64);
            let first = (*heap).current;
            // total - current == rounded is `bcs` -> no growth.
            cg_heap_alloc(heap, 64);
            assert_eq!((*heap).current, first, "exact fit stays in the block");
            assert_eq!(alloc_sizes().len(), 3);

            cg_heap_alloc(heap, 1);
            assert_ne!((*heap).current, first, "no room left: a block was pushed");
            assert_eq!(
                alloc_sizes()[3..],
                [core::mem::size_of::<CgHeapBlock>(), 64],
                "new block takes the arena's default size"
            );
            assert_eq!((*(*heap).current).next, first, "newest block heads the chain");
            assert_eq!((*first).current, 64, "the old block keeps its cursor");
            cg_heap_destroy(heap);
        }
        teardown();
    }

    #[test]
    fn a_request_larger_than_the_block_size_sizes_the_new_block() {
        let _g = setup();
        unsafe {
            let heap = cg_heap_create(32);
            cg_heap_alloc(heap, 32); // fills the first block exactly
            let p = cg_heap_alloc(heap, 100);
            assert_eq!(
                alloc_sizes()[3..],
                [core::mem::size_of::<CgHeapBlock>(), round8(100)],
                "max(block_size, rounded) = 104"
            );
            assert_eq!((*(*heap).current).total, round8(100));
            assert_eq!((*(*heap).current).current, round8(100));
            assert_eq!(p, (*(*heap).current).base);
            cg_heap_destroy(heap);
        }
        teardown();
    }

    #[test]
    fn growth_abandons_the_tail_of_the_old_block() {
        let _g = setup();
        unsafe {
            let heap = cg_heap_create(64);
            let first = (*heap).current;
            cg_heap_alloc(heap, 40); // 24 bytes left over
            cg_heap_alloc(heap, 32); // does not fit -> new block
            assert_ne!((*heap).current, first);
            assert_eq!((*first).current, 40, "the leftover 24 bytes are abandoned");
            // The next small request goes to the NEW block, never back.
            let p = cg_heap_alloc(heap, 8);
            let newest = (*heap).current;
            assert_eq!(p, (*newest).base.add(32));
            cg_heap_destroy(heap);
        }
        teardown();
    }

    #[test]
    fn destroy_releases_payload_then_header_newest_first_then_the_head() {
        let _g = setup();
        unsafe {
            let heap = cg_heap_create(16);
            cg_heap_alloc(heap, 16);
            cg_heap_alloc(heap, 16); // block 2
            cg_heap_alloc(heap, 16); // block 3
            let b3 = (*heap).current;
            let b2 = (*b3).next;
            let b1 = (*b2).next;
            assert!((*b1).next.is_null());
            let expected = std::vec![
                (*b3).base as usize,
                b3 as usize,
                (*b2).base as usize,
                b2 as usize,
                (*b1).base as usize,
                b1 as usize,
                heap as usize,
            ];
            cg_heap_destroy(heap);
            assert_eq!(*core::ptr::addr_of!(FREED), expected);
        }
        teardown();
    }
}
