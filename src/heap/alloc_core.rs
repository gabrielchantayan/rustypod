//! The retailOS heap allocation engine:
//!
//! - `heap_freelist_alloc` — original: `FUN_0819ce28` @ 0x0819ce28 (316
//!   bytes, up to the `heap_panic` call at 0x0819cf64). First-fit walk of
//!   the size-sorted free list. Register contract: r0 = heap descriptor,
//!   r1 = pre-rounded block size (header included, 8-aligned, >= 16),
//!   r2 = caller tag (forwarded untouched to the stats hook). Returns the
//!   user pointer (block + 8) in r0, or NULL when no block fits. A found
//!   block is unlinked (+4 = next, +8 = prev), its physical successor's
//!   PREV_FREE bit is validated and cleared, and when the block is bigger
//!   than `(size + 19) & SIZE_MASK` it is split: the *tail* (exactly
//!   `size` bytes) becomes the allocated block while the shrunken head
//!   keeps its address and goes back into the free list via the insert
//!   hook (which is what sets the tail's PREV_FREE bit). Finally the stats
//!   hook runs and `allocated_bytes` grows by the block size.
//! - `heap_alloc_core` — original: `FUN_0819d048` @ 0x0819d048 (668 bytes,
//!   up to the `heap_panic` call at 0x0819d2e0). Combined alloc + realloc
//!   engine. Register contract: r0 = descriptor, r1 = raw requested user
//!   size, r2 = zero-fill flag (== 1 clears the whole user area), r3 =
//!   caller tag (only the low byte is used), stack[0] = `old_ptr` (NULL =
//!   plain alloc, otherwise realloc source), stack[1] = copy flag (!= 0
//!   copies `min(old_size - 8, size)` bytes when the block moves, via the
//!   ROM/ADS `__rt_memcpy` @ 0x08037db0 — the same function as
//!   `crate::libc::rt_memcpy::__rt_memcpy`), stack[2] = low-memory-trace
//!   gate (byte). Size rounding: `((size + 3) & SIZE_MASK) + 8`, clamped
//!   up to 16, then 8-aligned. Realloc: same size retags and returns
//!   early; grow tries to absorb a free physical successor in place
//!   (merged span must reach `size + 8`), shrink/merged blocks split the
//!   tail back into the free list when it exceeds
//!   `(alloc_size + 19) & SIZE_MASK`; otherwise a fresh first-fit block is
//!   taken and the old block is freed through the free hook.
//!
//! Locking: the originals bracket the operation with `heap_lock` @
//! 0x0819d6cc / `heap_unlock` @ 0x0819cde4 (RTXC semaphore wrappers,
//! another agent's module). They are exposed through `HEAP_LOCK_HOOKS`,
//! a fn-pointer pair defaulting to no-ops — correct for the early OS
//! (mutex_state == 0 takes the `bx lr` path in the originals too) and for
//! host tests; on target the heap-init code points them at the real
//! RTXC-backed ports once those land.
//!
//! Other sibling machinery the originals call is likewise routed through
//! `ALLOC_ENGINE_HOOKS` (all another agent's files, per the porting
//! contract this module may only import `crate::heap::types` and
//! `crate::libc::rt_memcpy`):
//! - `freelist_insert` — original @ 0x0819d314. Default stub: no-op
//!   (split remainders leak until the real port is wired in).
//! - `stats_tag` — original @ 0x0819d714; `stats_retag` — original @
//!   0x0819cd5c (subtract old tag/class bytes, tail-calls 0x0819d714).
//!   Pure telemetry; default no-ops.
//! - `auto_init` — original @ 0x0819cf68 (lazy heap init). Default no-op.
//! - `free_core` — original @ 0x0819d4dc. Default no-op (realloc moves
//!   leak the old block until wired up).
//! - `heap_panic` — original @ 0x08030f44: `__rt_raise(1, 0)` then a tail
//!   branch to the OS terminate path @ 0x082b20a0; it never returns. The
//!   default stub is the documented `loop {}`. The original takes no
//!   argument; the hook receives a `HEAP_PANIC_*` reason code (a port
//!   addition for diagnostics) and must not return. Note the originals do
//!   NOT unlock on the panic paths — neither does this port.
//!
//! Deviations / simplifications (documented, none observable on target):
//! - The low-memory diagnostic trace (three `FUN_082bc4fc` calls gated by
//!   the global byte @ 0x089caf6e and the stack[2] flag) is omitted — it
//!   only emits debug output when an alloc fails; the flag argument is
//!   accepted and ignored.
//! - Two redundant null checks in the originals are unreachable
//!   (`cmp r2, #0` right after a successful match in the walk, and
//!   `cmp r5, #0` on the realloc in-place path where r5 = block + 8) and
//!   are not reproduced.
//! - The free-list link words are 32-bit *absolute* pointers on the ARM
//!   target. 64-bit host test builds can't store real pointers in a u32,
//!   so `cfg(test)` builds store links as u32 offsets from a per-test
//!   arena base (`TEST_LINK_BASE`); 0 stays the NULL list end in both
//!   worlds. Only the link-word→pointer cast changes — offsets, masks and
//!   walk order are identical, so the ARM build is the original algorithm.
//! - The zero-fill loop uses volatile word stores so LLVM's loop-idiom
//!   recognition cannot rewrite it into a `memset` call (no libc on
//!   target; see PORTING.md).

use crate::heap::types::{BlockHeader, HeapDescriptor, BLOCK_FREE, PREV_FREE, SIZE_MASK};
use crate::libc::rt_memcpy::__rt_memcpy;

/// heap_panic reason: block size argument failed the `(size - 8) & 3 == 0`
/// alignment gate in `heap_freelist_alloc`.
pub const HEAP_PANIC_BAD_SIZE: u32 = 1;
/// heap_panic reason: a block header or result pointer is not 8-aligned.
pub const HEAP_PANIC_BAD_ALIGN: u32 = 2;
/// heap_panic reason: the physical successor's header flags disagree with
/// this block's state (PREV_FREE/FREE inconsistency).
pub const HEAP_PANIC_BAD_FLAGS: u32 = 3;
/// heap_panic reason: a split remainder failed the alignment checks.
pub const HEAP_PANIC_BAD_SPLIT: u32 = 4;
/// heap_panic reason: realloc source header is zero or already free.
pub const HEAP_PANIC_BAD_BLOCK: u32 = 5;

/// Lock/unlock pair standing in for `heap_lock` @ 0x0819d6cc and
/// `heap_unlock` @ 0x0819cde4 (see the module header). Defaults to no-ops.
#[derive(Clone, Copy)]
pub struct HeapLockHooks {
    pub lock: unsafe extern "C" fn(desc: *mut HeapDescriptor),
    pub unlock: unsafe extern "C" fn(desc: *mut HeapDescriptor),
}

/// Default stub: the no-mutex path of the originals is a plain `bx lr`.
unsafe extern "C" fn lock_noop(_desc: *mut HeapDescriptor) {}

/// The active lock pair. Written once at heap-init time on target; host
/// tests swap in counting mocks (serialized by their own mutex).
pub static mut HEAP_LOCK_HOOKS: HeapLockHooks = HeapLockHooks {
    lock: lock_noop,
    unlock: lock_noop,
};

/// Indirect dispatch for the not-yet-importable sibling machinery (see the
/// module header for the default-stub behavior of each slot).
#[derive(Clone, Copy)]
pub struct AllocEngineHooks {
    /// freelist_insert @ 0x0819d314: (desc, block) — coalesce, set FREE /
    /// successor's PREV_FREE, size-sorted insert, free_bytes += size.
    pub freelist_insert: unsafe extern "C" fn(desc: *mut HeapDescriptor, block: *mut u8),
    /// stats_tag @ 0x0819d714: (desc, block, tag) — telemetry on a freshly
    /// allocated block.
    pub stats_tag: unsafe extern "C" fn(desc: *mut HeapDescriptor, block: *mut u8, tag: u32),
    /// stats_retag @ 0x0819cd5c: (desc, block, old_size, tag) — telemetry
    /// when a realloc keeps its block (subtracts old_size, retags).
    pub stats_retag: unsafe extern "C" fn(
        desc: *mut HeapDescriptor,
        block: *mut u8,
        old_size: u32,
        tag: u32,
    ),
    /// auto_init @ 0x0819cf68: (desc, 0, 0) — lazy heap initialization.
    pub auto_init: unsafe extern "C" fn(desc: *mut HeapDescriptor, a2: u32, a3: u32),
    /// free_core @ 0x0819d4dc: (desc, user_ptr, tag) — frees the old block
    /// after a realloc moved it.
    pub free_core: unsafe extern "C" fn(desc: *mut HeapDescriptor, user_ptr: *mut u8, tag: u32),
    /// heap_panic @ 0x08030f44: never returns (raises, then terminates the
    /// OS). Default stub spins. Receives a HEAP_PANIC_* reason code.
    pub heap_panic: unsafe extern "C" fn(reason: u32) -> !,
}

unsafe extern "C" fn insert_stub(_desc: *mut HeapDescriptor, _block: *mut u8) {}
unsafe extern "C" fn stats_tag_stub(_desc: *mut HeapDescriptor, _block: *mut u8, _tag: u32) {}
unsafe extern "C" fn stats_retag_stub(
    _desc: *mut HeapDescriptor,
    _block: *mut u8,
    _old_size: u32,
    _tag: u32,
) {
}
unsafe extern "C" fn auto_init_stub(_desc: *mut HeapDescriptor, _a2: u32, _a3: u32) {}
unsafe extern "C" fn free_core_stub(_desc: *mut HeapDescriptor, _user_ptr: *mut u8, _tag: u32) {}

/// Default heap_panic stub: the original terminates the OS; with nothing
/// ported to raise into, the closest safe stub is a spin.
unsafe extern "C" fn heap_panic_stub(_reason: u32) -> ! {
    loop {}
}

/// The active engine hooks. Same install-once / test-swap contract as
/// `HEAP_LOCK_HOOKS`.
pub static mut ALLOC_ENGINE_HOOKS: AllocEngineHooks = AllocEngineHooks {
    freelist_insert: insert_stub,
    stats_tag: stats_tag_stub,
    stats_retag: stats_retag_stub,
    auto_init: auto_init_stub,
    free_core: free_core_stub,
    heap_panic: heap_panic_stub,
};

/// Volatile reads so LLVM cannot constant-fold the defaults and inline the
/// stubs (observed in malloc_rt.rs: a folded `loop {}` collapsed an
/// exported function to a branch-to-self in the ARM release build).
#[inline(always)]
fn lock_hooks() -> HeapLockHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HEAP_LOCK_HOOKS)) }
}

#[inline(always)]
fn engine_hooks() -> AllocEngineHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ALLOC_ENGINE_HOOKS)) }
}

#[inline(never)]
unsafe fn heap_panic(reason: u32) -> ! {
    (engine_hooks().heap_panic)(reason)
}

/// Free-list link words are raw little-endian u32s at fixed offsets from
/// the block header: +4 = next, +8 = prev (the prev slot overlaps the user
/// area of an allocated block — only free blocks carry it).
#[inline(always)]
unsafe fn read_link(slot: *mut u8) -> u32 {
    (slot as *const u32).read()
}

#[inline(always)]
unsafe fn write_link(slot: *mut u8, link: u32) {
    (slot as *mut u32).write(link);
}

/// Link word -> pointer. On the ARM target a link word *is* the absolute
/// 32-bit pointer the original stored. In 64-bit host test builds links
/// are u32 offsets from `TEST_LINK_BASE` (see the module header); 0 is the
/// NULL list end in both worlds.
#[cfg(not(test))]
#[inline(always)]
fn link_to_ptr(link: u32) -> *mut u8 {
    link as *mut u8
}

#[cfg(test)]
static mut TEST_LINK_BASE: *mut u8 = core::ptr::null_mut();

#[cfg(test)]
#[inline(always)]
fn link_to_ptr(link: u32) -> *mut u8 {
    unsafe {
        if link == 0 {
            core::ptr::null_mut()
        } else {
            TEST_LINK_BASE.add(link as usize)
        }
    }
}

/// heap_freelist_alloc — original: `FUN_0819ce28` @ 0x0819ce28 (316 bytes).
///
/// r0 = `desc`, r1 = `size` (pre-rounded, header included, 8-aligned),
/// r2 = `tag` (forwarded to the stats hook). Returns block + 8, or NULL.
///
/// # Safety
/// `desc` must point at an initialized heap descriptor whose free list is
/// intact; the caller must hold the heap lock (the original is only ever
/// called under `heap_lock`).
#[no_mangle]
pub unsafe extern "C" fn heap_freelist_alloc(
    desc: *mut HeapDescriptor,
    size: u32,
    tag: u32,
) -> *mut u8 {
    if size.wrapping_sub(8) & 3 != 0 {
        heap_panic(HEAP_PANIC_BAD_SIZE);
    }
    let hooks = engine_hooks();
    let sentinel = core::ptr::addr_of_mut!((*desc).sentinel) as *mut u8;
    let mut node = sentinel;
    let mut result: *mut u8 = core::ptr::null_mut();
    while !node.is_null() {
        let header = node as *mut BlockHeader;
        let size_flags = (*header).size_flags;
        if size_flags & SIZE_MASK >= size {
            // First fit. The user pointer must be 8-aligned.
            let user = node.add(8);
            if user as usize & 7 != 0 {
                heap_panic(HEAP_PANIC_BAD_ALIGN);
            }
            // The physical successor must know this block is free
            // (PREV_FREE set) and must itself be allocated.
            let next_block = node.add((size_flags & SIZE_MASK) as usize) as *mut BlockHeader;
            let next_flags = (*next_block).size_flags;
            if next_flags & PREV_FREE == 0 || next_flags & BLOCK_FREE != 0 {
                heap_panic(HEAP_PANIC_BAD_FLAGS);
            }
            (*next_block).size_flags = next_flags & !PREV_FREE;
            // Unlink from the size-sorted free list (+4 = next, +8 = prev).
            let prev_link = read_link(node.add(8));
            if prev_link != 0 {
                write_link(link_to_ptr(prev_link).add(4), read_link(node.add(4)));
            }
            let next_link = read_link(node.add(4));
            if next_link != 0 {
                write_link(link_to_ptr(next_link).add(8), read_link(node.add(8)));
            }
            // Mark allocated and account the whole block.
            let new_flags = size_flags & !BLOCK_FREE;
            (*header).size_flags = new_flags;
            let block_size = new_flags & SIZE_MASK;
            (*desc).free_bytes = (*desc).free_bytes.wrapping_sub(block_size);
            let mut allocated = node;
            if block_size > size.wrapping_add(19) & SIZE_MASK {
                // Split: the head shrinks and is reinserted, the tail
                // (exactly `size`) becomes the allocated block.
                let remainder = new_flags.wrapping_sub(size);
                (*header).size_flags = remainder;
                if remainder & 7 != 0 || remainder.wrapping_sub(4) & 3 != 0 {
                    heap_panic(HEAP_PANIC_BAD_SPLIT);
                }
                allocated = node.add((remainder & SIZE_MASK) as usize);
                if allocated.add(8) as usize & 7 != 0 {
                    heap_panic(HEAP_PANIC_BAD_ALIGN);
                }
                (*(allocated as *mut BlockHeader)).size_flags = size;
                (hooks.freelist_insert)(desc, node);
            }
            (hooks.stats_tag)(desc, allocated, tag);
            let allocated_size = (*(allocated as *mut BlockHeader)).size_flags & SIZE_MASK;
            (*desc).allocated_bytes = (*desc).allocated_bytes.wrapping_add(allocated_size);
            result = allocated.add(8);
            break;
        }
        node = link_to_ptr(read_link(node.add(4)));
    }
    if result as usize & 7 != 0 {
        heap_panic(HEAP_PANIC_BAD_ALIGN);
    }
    result
}

/// heap_alloc_core — original: `FUN_0819d048` @ 0x0819d048 (668 bytes).
///
/// r0 = `desc`, r1 = `size` (raw user request), r2 = `zero_fill`
/// (== 1 clears the user area), r3 = `tag` (low byte used), stack[0] =
/// `old_ptr` (NULL = plain alloc), stack[1] = `copy_flag` (!= 0 copies
/// `min(old_size - 8, size)` bytes when the block moves), stack[2] =
/// `oom_trace_disable` (accepted; the trace it gates is omitted — see the
/// module header). Returns the user pointer in r0, NULL on failure.
///
/// # Safety
/// `desc` must be a valid heap descriptor; `old_ptr`, when non-NULL, must
/// be a live allocation from this heap. Not reentrant beyond what the
/// installed lock hooks provide.
#[no_mangle]
pub unsafe extern "C" fn heap_alloc_core(
    desc: *mut HeapDescriptor,
    size: u32,
    zero_fill: u32,
    tag: u32,
    old_ptr: *mut u8,
    copy_flag: u32,
    oom_trace_disable: u32,
) -> *mut u8 {
    let _ = oom_trace_disable;
    // Lazy auto-init, gated on the low bytes of `initialized` (0xc0) and
    // `auto_init` (0xcc) exactly like the original's ldrb/strb.
    let initialized = core::ptr::addr_of!((*desc).initialized) as *const u8;
    let auto_init = core::ptr::addr_of!((*desc).auto_init) as *const u8;
    if initialized.read() == 0 && auto_init.read() != 0 {
        (core::ptr::addr_of_mut!((*desc).initialized) as *mut u8).write(1);
        (engine_hooks().auto_init)(desc, 0, 0);
    }
    let mut raw_size = (size.wrapping_add(3) & SIZE_MASK).wrapping_add(8);
    if raw_size < 16 {
        raw_size = 16;
    }
    let alloc_size = raw_size.wrapping_add(7) & !7;
    let tag = tag & 0xff; // the original reloads the tag with ldrb
    let hooks = engine_hooks();
    let locks = lock_hooks();
    (locks.lock)(desc);

    let mut result: *mut u8 = core::ptr::null_mut();
    let mut old_size: u32 = 0;
    if !old_ptr.is_null() {
        let block = old_ptr.sub(8) as *mut BlockHeader;
        let header = (*block).size_flags;
        old_size = header & SIZE_MASK;
        if header == 0 || header & BLOCK_FREE != 0 {
            heap_panic(HEAP_PANIC_BAD_BLOCK); // original: no unlock here
        }
        if old_size == alloc_size {
            // Same size: retag and return the block untouched.
            (hooks.stats_retag)(desc, block as *mut u8, old_size, tag);
            (locks.unlock)(desc);
            return old_ptr;
        }
        let mut keep_block = old_size > alloc_size; // shrink keeps the block
        if old_size < alloc_size {
            // Grow: try to absorb the physical successor in place. Its
            // PREV_FREE bit refers to *this* block — set means corruption.
            let next_block = (block as *mut u8).add(old_size as usize) as *mut BlockHeader;
            let next_flags = (*next_block).size_flags;
            if next_flags & PREV_FREE != 0 {
                heap_panic(HEAP_PANIC_BAD_FLAGS); // original: no unlock here
            }
            if next_flags & BLOCK_FREE != 0 {
                let next_size = next_flags & SIZE_MASK;
                if old_size.wrapping_add(next_size) >= size.wrapping_add(8) {
                    // Merge: swallow the successor, unlink it from the free
                    // list, and clear PREV_FREE on the block that follows.
                    (*desc).free_bytes = (*desc).free_bytes.wrapping_sub(next_size);
                    let merged = (*block).size_flags;
                    (*block).size_flags =
                        merged.wrapping_add(next_size) & SIZE_MASK | merged & !SIZE_MASK;
                    let absorbed = next_block as *mut u8;
                    let prev_link = read_link(absorbed.add(8));
                    if prev_link != 0 {
                        write_link(link_to_ptr(prev_link).add(4), read_link(absorbed.add(4)));
                    }
                    let next_link = read_link(absorbed.add(4));
                    if next_link != 0 {
                        write_link(link_to_ptr(next_link).add(8), read_link(absorbed.add(8)));
                    }
                    let following = (block as *mut u8)
                        .add(((*block).size_flags & SIZE_MASK) as usize)
                        as *mut BlockHeader;
                    (*following).size_flags &= !PREV_FREE;
                    keep_block = true;
                }
            }
        }
        if keep_block {
            // Shrink (or merged-grow): give the tail back when it is big
            // enough to live on the free list.
            let current_size = (*block).size_flags & SIZE_MASK;
            if current_size > alloc_size.wrapping_add(19) & SIZE_MASK {
                (*block).size_flags =
                    alloc_size & SIZE_MASK | (*block).size_flags & !SIZE_MASK;
                let remainder = (block as *mut u8).add(alloc_size as usize) as *mut BlockHeader;
                (*remainder).size_flags = current_size.wrapping_sub(alloc_size);
                (hooks.freelist_insert)(desc, remainder as *mut u8);
            }
            (hooks.stats_retag)(desc, block as *mut u8, old_size, tag);
            result = old_ptr;
        }
    }
    if result.is_null() {
        result = heap_freelist_alloc(desc, alloc_size, tag);
    }
    if !result.is_null() {
        if zero_fill == 1 {
            let block_size = (*(result.sub(8) as *const BlockHeader)).size_flags & SIZE_MASK;
            let mut left = block_size.wrapping_sub(8);
            let mut word = result as *mut u32;
            while left != 0 {
                left = left.wrapping_sub(4);
                word.write_volatile(0);
                word = word.add(1);
            }
        }
        (*desc).alloc_counter = (*desc).alloc_counter.wrapping_add(1);
    }
    (locks.unlock)(desc);
    // Omitted: the low-memory diagnostic trace (three FUN_082bc4fc calls
    // gated by the byte @ 0x089caf6e and `oom_trace_disable`).
    if !old_ptr.is_null() && !result.is_null() && old_ptr != result {
        if copy_flag != 0 {
            let mut copy_len = old_size.wrapping_sub(8);
            if size < copy_len {
                copy_len = size;
            }
            __rt_memcpy(result, old_ptr, copy_len as usize);
        }
        (hooks.free_core)(desc, old_ptr, tag);
    }
    if result as usize & 7 != 0 {
        heap_panic(HEAP_PANIC_BAD_ALIGN);
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests: they all share the global hooks, link base and
    /// the longjmp buffer.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    // Hook call log.
    static mut LOCK_CALLS: u32 = 0;
    static mut UNLOCK_CALLS: u32 = 0;
    static mut INSERT_CALLS: u32 = 0;
    static mut STATS_TAG_CALLS: u32 = 0;
    static mut STATS_RETAG_CALLS: u32 = 0;
    static mut LAST_RETAG_OLD_SIZE: u32 = 0;
    static mut AUTO_INIT_CALLS: u32 = 0;
    static mut FREE_CALLS: u32 = 0;
    static mut LAST_FREE_PTR: *mut u8 = core::ptr::null_mut();
    static mut PANIC_REASON: u32 = 0;

    extern "C" {
        fn sigsetjmp(env: *mut i32, savesigs: i32) -> i32;
        fn siglongjmp(env: *mut i32, val: i32) -> !;
    }
    /// Oversized on purpose (Darwin arm64 needs far less); heap_panic
    /// longjmps back here so corruption tests can observe the noreturn hook.
    static mut JMP_BUF: [i32; 128] = [0; 128];

    unsafe extern "C" fn mock_lock(_desc: *mut HeapDescriptor) {
        LOCK_CALLS += 1;
    }
    unsafe extern "C" fn mock_unlock(_desc: *mut HeapDescriptor) {
        UNLOCK_CALLS += 1;
    }
    unsafe extern "C" fn mock_stats_tag(_desc: *mut HeapDescriptor, _block: *mut u8, _tag: u32) {
        STATS_TAG_CALLS += 1;
    }
    unsafe extern "C" fn mock_stats_retag(
        _desc: *mut HeapDescriptor,
        _block: *mut u8,
        old_size: u32,
        _tag: u32,
    ) {
        STATS_RETAG_CALLS += 1;
        LAST_RETAG_OLD_SIZE = old_size;
    }
    unsafe extern "C" fn mock_auto_init(_desc: *mut HeapDescriptor, _a2: u32, _a3: u32) {
        AUTO_INIT_CALLS += 1;
    }
    unsafe extern "C" fn mock_free_core(_desc: *mut HeapDescriptor, ptr: *mut u8, _tag: u32) {
        FREE_CALLS += 1;
        LAST_FREE_PTR = ptr;
    }
    unsafe extern "C" fn mock_heap_panic(reason: u32) -> ! {
        PANIC_REASON = reason;
        siglongjmp(JMP_BUF.as_mut_ptr(), 1);
    }

    unsafe fn l2p(link: u32) -> *mut u8 {
        if link == 0 {
            core::ptr::null_mut()
        } else {
            TEST_LINK_BASE.add(link as usize)
        }
    }

    unsafe fn p2l(ptr: *mut u8) -> u32 {
        if ptr.is_null() {
            0
        } else {
            ptr.offset_from(TEST_LINK_BASE) as u32
        }
    }

    /// Test double for freelist_insert @ 0x0819d314: sets FREE, sets the
    /// physical successor's PREV_FREE and backlink, inserts size-sorted
    /// (before the first node >= our size, like the original) and accounts
    /// free_bytes. Deliberately no coalescing — the test heaps never place
    /// a remainder next to another free block.
    unsafe extern "C" fn mock_insert(desc: *mut HeapDescriptor, block: *mut u8) {
        INSERT_CALLS += 1;
        let header = block as *mut u32;
        let size = header.read() & SIZE_MASK;
        header.write(header.read() | BLOCK_FREE);
        let next_phys = block.add(size as usize);
        (next_phys as *mut u32).write((next_phys as *mut u32).read() | PREV_FREE);
        (next_phys.sub(4) as *mut u32).write(size);
        let sentinel = core::ptr::addr_of_mut!((*desc).sentinel) as *mut u8;
        let mut prev = sentinel;
        loop {
            let next_link = (prev.add(4) as *const u32).read();
            if next_link == 0 {
                write_link(block.add(4), 0);
                write_link(block.add(8), p2l(prev));
                write_link(prev.add(4), p2l(block));
                break;
            }
            let next = l2p(next_link);
            let next_size = (next as *const u32).read() & SIZE_MASK;
            if next_size >= size {
                write_link(block.add(4), next_link);
                write_link(block.add(8), p2l(prev));
                write_link(prev.add(4), p2l(block));
                write_link(next.add(8), p2l(block));
                break;
            }
            prev = next;
        }
        (*desc).free_bytes = (*desc).free_bytes.wrapping_add(size);
    }

    /// Buffer-backed heap: the descriptor sits at offset 0 (so its
    /// embedded sentinel is reachable through u32 link offsets) and blocks
    /// live from 0x400 up. Backing is u64 so the base is 8-aligned.
    struct TestHeap {
        arena: Vec<u64>,
    }

    const BLOCKS: usize = 0x400;
    const SENTINEL: usize = 0xd0;

    impl TestHeap {
        fn new(words: usize) -> TestHeap {
            TestHeap {
                arena: vec![0u64; words],
            }
        }
        fn base(&self) -> *mut u8 {
            self.arena.as_ptr() as *mut u8
        }
        unsafe fn desc(&self) -> *mut HeapDescriptor {
            self.base() as *mut HeapDescriptor
        }
        unsafe fn w32(&self, off: usize, val: u32) {
            (self.base().add(off) as *mut u32).write(val);
        }
        unsafe fn r32(&self, off: usize) -> u32 {
            (self.base().add(off) as *const u32).read()
        }
        fn fill(&self, byte: u8) {
            // In-bounds by construction (arena length).
            unsafe { core::ptr::write_bytes(self.base(), byte, self.arena.len() * 8) };
        }
        /// Writes a block header (raw size_flags word).
        unsafe fn header(&self, off: usize, size_flags: u32) {
            self.w32(off, size_flags);
        }
        /// Chains the given free blocks (offsets) into the sentinel list.
        unsafe fn set_free_list(&self, blocks: &[usize]) {
            self.w32(SENTINEL, 0);
            self.w32(
                SENTINEL + 4,
                blocks.first().map_or(0, |&b| b as u32),
            );
            for (i, &b) in blocks.iter().enumerate() {
                let next = blocks.get(i + 1).map_or(0, |&n| n as u32);
                let prev = if i == 0 {
                    SENTINEL as u32
                } else {
                    blocks[i - 1] as u32
                };
                self.w32(b + 4, next);
                self.w32(b + 8, prev);
            }
        }
        /// Walks the free list from the sentinel; returns (size, offset).
        unsafe fn free_list_sizes(&self) -> Vec<(u32, usize)> {
            let mut out = Vec::new();
            let mut link = self.r32(SENTINEL + 4);
            while link != 0 {
                let off = link as usize;
                out.push((self.r32(off) & SIZE_MASK, off));
                link = self.r32(off + 4);
            }
            out
        }
    }

    /// Points the engine's link translation at `heap`, resets the call log
    /// and initializes the descriptor counters (but NOT free_bytes — the
    /// heap builders own that). Caller must hold the OPS_LOCK guard.
    unsafe fn rebind(heap: &TestHeap) {
        LOCK_CALLS = 0;
        UNLOCK_CALLS = 0;
        INSERT_CALLS = 0;
        STATS_TAG_CALLS = 0;
        STATS_RETAG_CALLS = 0;
        LAST_RETAG_OLD_SIZE = 0;
        AUTO_INIT_CALLS = 0;
        FREE_CALLS = 0;
        LAST_FREE_PTR = core::ptr::null_mut();
        PANIC_REASON = 0;
        TEST_LINK_BASE = heap.base();
        let desc = heap.desc();
        (*desc).allocated_bytes = 0;
        (*desc).alloc_counter = 0;
        (*desc).initialized = 1;
        (*desc).auto_init = 0;
    }

    /// Installs the mock hooks, rebinds to `heap`, returns the lock guard.
    fn setup(heap: &TestHeap) -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        unsafe {
            *core::ptr::addr_of_mut!(HEAP_LOCK_HOOKS) = HeapLockHooks {
                lock: mock_lock,
                unlock: mock_unlock,
            };
            *core::ptr::addr_of_mut!(ALLOC_ENGINE_HOOKS) = AllocEngineHooks {
                freelist_insert: mock_insert,
                stats_tag: mock_stats_tag,
                stats_retag: mock_stats_retag,
                auto_init: mock_auto_init,
                free_core: mock_free_core,
                heap_panic: mock_heap_panic,
            };
            rebind(heap);
        }
        guard
    }

    /// Standard arena: free blocks A(0x20) @0x420, B(0x40) @0x460,
    /// C(0x100) @0x4c0, separated by allocated fences so no two free
    /// blocks are physically adjacent (the real heap coalesces those).
    unsafe fn standard_heap() -> TestHeap {
        let heap = TestHeap::new(0x100);
        unsafe {
            heap.fill(0xAA);
            // fence0: allocated 0x20, first block (prev not free).
            heap.header(BLOCKS, 0x20);
            // A: free 0x20.
            heap.header(0x420, 0x20 | BLOCK_FREE);
            // f1: allocated 0x20, prev free; backlink at f1 - 4.
            heap.header(0x440, 0x20 | PREV_FREE);
            heap.w32(0x43c, 0x20);
            // B: free 0x40.
            heap.header(0x460, 0x40 | BLOCK_FREE);
            // f2: allocated 0x20, prev free.
            heap.header(0x4a0, 0x20 | PREV_FREE);
            heap.w32(0x49c, 0x40);
            // C: free 0x100.
            heap.header(0x4c0, 0x100 | BLOCK_FREE);
            // f3: allocated 0x40, prev free.
            heap.header(0x5c0, 0x40 | PREV_FREE);
            heap.w32(0x5bc, 0x100);
            heap.set_free_list(&[0x420, 0x460, 0x4c0]);
            (*heap.desc()).free_bytes = 0x20 + 0x40 + 0x100;
        }
        heap
    }

    #[test]
    fn first_fit_selects_first_large_enough_block() {
        let heap = unsafe { standard_heap() };
        let _lock = setup(&heap);
        unsafe {
            // Request 0x38 user bytes -> block 0x40. A(0x20) is too small,
            // B(0x40) is the first fit; 0x40 <= (0x40+19)&MASK = 0x50, so
            // no split (exact fit).
            let result = heap_alloc_core(heap.desc(), 0x38, 0, 7, core::ptr::null_mut(), 0, 0);
            assert_eq!(result, heap.base().add(0x468), "block B user pointer");
            assert_eq!(result as usize & 7, 0, "8-aligned");
            assert_eq!(heap.r32(0x460), 0x40, "B allocated, FREE cleared");
            assert_eq!(INSERT_CALLS, 0, "exact fit must not split/reinsert");
            // B unlinked: A.next = C, C.prev = A.
            assert_eq!(heap.free_list_sizes(), vec![(0x20, 0x420), (0x100, 0x4c0)]);
            assert_eq!(heap.r32(0x4c0 + 8), 0x420, "C.prev = A");
            // f2's PREV_FREE cleared (its predecessor is no longer free).
            assert_eq!(heap.r32(0x4a0), 0x20);
            assert_eq!((*heap.desc()).free_bytes, 0x160 - 0x40);
            assert_eq!((*heap.desc()).allocated_bytes, 0x40);
            assert_eq!((*heap.desc()).alloc_counter, 1);
            assert_eq!(STATS_TAG_CALLS, 1);
            assert_eq!(STATS_RETAG_CALLS, 0);
            assert_eq!(LOCK_CALLS, 1);
            assert_eq!(UNLOCK_CALLS, 1);
        }
    }

    /// Single free block B(0x40) @0x420 between allocated fences.
    unsafe fn single_block_heap() -> TestHeap {
        let heap = TestHeap::new(0x100);
        unsafe {
            heap.fill(0xAA);
            heap.header(BLOCKS, 0x20); // fence
            heap.header(0x420, 0x40 | BLOCK_FREE);
            heap.header(0x460, 0x20 | PREV_FREE); // trailing fence
            heap.w32(0x45c, 0x40);
            heap.set_free_list(&[0x420]);
            (*heap.desc()).free_bytes = 0x40;
        }
        heap
    }

    #[test]
    fn size_rounding_and_minimum_block() {
        // Request 1 byte -> raw (1+3)&~3 + 8 = 12 -> clamped to 16.
        // 0x40 > (0x10+19)&MASK = 0x20, so the block splits.
        let heap = unsafe { single_block_heap() };
        let _lock = setup(&heap);
        unsafe {
            let result = heap_alloc_core(heap.desc(), 1, 0, 0, core::ptr::null_mut(), 0, 0);
            assert_eq!(result, heap.base().add(0x420 + 0x30 + 8));
            assert_eq!(result as usize & 7, 0);
            assert_eq!(
                heap.r32(0x420 + 0x30) & SIZE_MASK,
                0x10,
                "minimum block is 16 bytes"
            );
            assert_eq!(
                heap.r32(0x420 + 0x30) & PREV_FREE,
                PREV_FREE,
                "insert marks the carved tail prev-free"
            );
            // Remainder 0x30 stays at B and returns to the list.
            assert_eq!(heap.r32(0x420), 0x30 | BLOCK_FREE);
            assert_eq!(heap.free_list_sizes(), vec![(0x30, 0x420)]);
            assert_eq!((*heap.desc()).free_bytes, 0x30);
            assert_eq!((*heap.desc()).allocated_bytes, 0x10);
            assert_eq!(LOCK_CALLS, 1);
            assert_eq!(UNLOCK_CALLS, 1);

            // Request 9 -> (9+3)&~3 + 8 = 20 -> 8-aligned 24.
            let heap2 = single_block_heap();
            rebind(&heap2);
            let result = heap_alloc_core(heap2.desc(), 9, 0, 0, core::ptr::null_mut(), 0, 0);
            assert_eq!(result, heap2.base().add(0x420 + 0x28 + 8));
            assert_eq!(heap2.r32(0x420 + 0x28) & SIZE_MASK, 0x18);
            assert_eq!(heap2.free_list_sizes(), vec![(0x28, 0x420)]);

            // Request 0 rounds up to the minimum block too.
            let heap3 = single_block_heap();
            rebind(&heap3);
            let result = heap_alloc_core(heap3.desc(), 0, 0, 0, core::ptr::null_mut(), 0, 0);
            assert_eq!(result, heap3.base().add(0x420 + 0x30 + 8));
            assert_eq!(heap3.r32(0x420 + 0x30) & SIZE_MASK, 0x10);
            assert_eq!(LOCK_CALLS, 1);
            assert_eq!(UNLOCK_CALLS, 1);
        }
    }

    #[test]
    fn split_keeps_free_list_size_sorted() {
        let heap = unsafe { standard_heap() };
        let _lock = setup(&heap);
        unsafe {
            // Request 0x80 -> block 0x88. Only C(0x100) fits; split leaves
            // 0x78 at C, which keeps its sorted place after A and B.
            let result = heap_alloc_core(heap.desc(), 0x80, 0, 0, core::ptr::null_mut(), 0, 0);
            assert_eq!(result, heap.base().add(0x4c0 + 0x78 + 8));
            assert_eq!(heap.r32(0x4c0), 0x78 | BLOCK_FREE);
            assert_eq!(
                heap.free_list_sizes(),
                vec![(0x20, 0x420), (0x40, 0x460), (0x78, 0x4c0)]
            );
            // Link integrity both ways.
            assert_eq!(heap.r32(0x420 + 4), 0x460);
            assert_eq!(heap.r32(0x460 + 8), 0x420);
            assert_eq!(heap.r32(0x460 + 4), 0x4c0);
            assert_eq!(heap.r32(0x4c0 + 8), 0x460);
            assert_eq!(heap.r32(0x4c0 + 4), 0);
            assert_eq!((*heap.desc()).free_bytes, 0x160 - 0x100 + 0x78);

            // Now allocate 0x30 -> block 0x38; B(0x40) is first fit and
            // (0x38+19)&MASK = 0x48 >= 0x40, so B goes whole (no split).
            let result = heap_alloc_core(heap.desc(), 0x30, 0, 0, core::ptr::null_mut(), 0, 0);
            assert_eq!(result, heap.base().add(0x460 + 8));
            assert_eq!(heap.r32(0x460), 0x40);
            assert_eq!(
                heap.free_list_sizes(),
                vec![(0x20, 0x420), (0x78, 0x4c0)]
            );
            assert_eq!(INSERT_CALLS, 1, "only the first alloc split");
        }
    }

    #[test]
    fn exact_fit_and_too_small_remainder_do_not_split() {
        let heap = TestHeap::new(0x100);
        heap.fill(0xAA);
        let _lock = setup(&heap);
        unsafe {
            heap.header(BLOCKS, 0x20); // fence
            heap.header(0x420, 0x48 | BLOCK_FREE);
            heap.header(0x468, 0x20 | PREV_FREE);
            heap.w32(0x464, 0x48);
            heap.set_free_list(&[0x420]);
            (*heap.desc()).free_bytes = 0x48;

            // Block 0x48 vs request 0x40: remainder 8 can never be a free
            // block, (0x40+19)&MASK = 0x50 >= 0x48 -> take the whole block.
            let result = heap_alloc_core(heap.desc(), 0x38, 0, 0, core::ptr::null_mut(), 0, 0);
            assert_eq!(result, heap.base().add(0x428));
            assert_eq!(heap.r32(0x420), 0x48, "whole 0x48 block allocated");
            assert_eq!(INSERT_CALLS, 0);
            assert_eq!(heap.free_list_sizes(), vec![]);
            assert_eq!((*heap.desc()).free_bytes, 0);
            assert_eq!((*heap.desc()).allocated_bytes, 0x48);
            assert_eq!(heap.r32(0x468), 0x20, "successor PREV_FREE cleared");
        }
    }

    #[test]
    fn zero_fill_clears_exactly_the_user_area() {
        let heap = TestHeap::new(0x100);
        heap.fill(0xAA);
        let _lock = setup(&heap);
        unsafe {
            heap.header(BLOCKS, 0x20);
            heap.header(0x420, 0x100 | BLOCK_FREE);
            heap.header(0x520, 0x20 | PREV_FREE);
            heap.w32(0x51c, 0x100);
            heap.set_free_list(&[0x420]);
            (*heap.desc()).free_bytes = 0x100;

            // Request 0x20 -> block 0x28; split carve puts it at the tail.
            let result = heap_alloc_core(heap.desc(), 0x20, 1, 0, core::ptr::null_mut(), 0, 0);
            let block = result.sub(8);
            assert_eq!((block as *const u32).read() & SIZE_MASK, 0x28);
            for i in 0..0x20 {
                assert_eq!(result.add(i).read(), 0, "zeroed user byte {i}");
            }
            // The remainder's user area keeps the 0xAA fill (its +4/+8
            // words hold free-list links, so check past them).
            assert_eq!(heap.r32(0x420 + 0xc), 0xAAAA_AAAA);
            assert_eq!(heap.r32(0x420), 0xD8 | BLOCK_FREE);

            // zero_fill != 1 leaves the pattern alone — except the last
            // user word (0x4f4), which still holds the stale backlink the
            // insert hook wrote when this memory was the free remainder's
            // tail (the original never scrubs backlinks either).
            let result2 = heap_alloc_core(heap.desc(), 0x20, 0, 0, core::ptr::null_mut(), 0, 0);
            for i in (0..0x1c).step_by(4) {
                assert_eq!((result2.add(i) as *const u32).read(), 0xAAAA_AAAA);
            }
            assert_eq!((result2.add(0x1c) as *const u32).read(), 0xD8, "stale backlink");
        }
    }

    #[test]
    fn realloc_same_size_returns_early() {
        let heap = unsafe { standard_heap() };
        let _lock = setup(&heap);
        unsafe {
            let fence = heap.base().add(BLOCKS + 8);
            // fence0 is 0x20; request 0x18 -> block 0x20 == old size.
            let result = heap_alloc_core(heap.desc(), 0x18, 0, 3, fence, 1, 0);
            assert_eq!(result, fence);
            assert_eq!(STATS_RETAG_CALLS, 1);
            assert_eq!(LAST_RETAG_OLD_SIZE, 0x20);
            assert_eq!(STATS_TAG_CALLS, 0, "no fresh allocation");
            assert_eq!(INSERT_CALLS, 0);
            assert_eq!(FREE_CALLS, 0);
            assert_eq!((*heap.desc()).alloc_counter, 0, "early return skips the counter");
            assert_eq!(LOCK_CALLS, 1);
            assert_eq!(UNLOCK_CALLS, 1);
        }
    }

    /// Realloc arena: P(0x20) allocated @0x400 with a byte pattern in its
    /// user area, Q(q_size) free @0x420, R allocated fence, S(0x60) free,
    /// T allocated fence. Offsets after Q follow q_size. Returns the heap
    /// plus the offsets of Q's fence and S.
    unsafe fn realloc_heap(q_size: u32) -> (TestHeap, usize, usize) {
        let heap = TestHeap::new(0x100);
        unsafe {
            heap.fill(0);
            heap.header(BLOCKS, 0x20);
            let user = heap.base().add(BLOCKS + 8);
            for i in 0..0x18 {
                user.add(i).write((i as u32 * 7 + 1) as u8);
            }
            let q = 0x420;
            let r = q + q_size as usize;
            let s = r + 0x20;
            let t = s + 0x60;
            heap.header(q, q_size | BLOCK_FREE);
            heap.header(r, 0x20 | PREV_FREE);
            heap.w32(r - 4, q_size);
            heap.header(s, 0x60 | BLOCK_FREE);
            heap.header(t, 0x20 | PREV_FREE);
            heap.w32(t - 4, 0x60);
            heap.set_free_list(&[q, s]);
            (*heap.desc()).free_bytes = q_size + 0x60;
            (heap, r, s)
        }
    }

    #[test]
    fn realloc_grows_by_merging_next_free_block_in_place() {
        let (heap, r, s) = unsafe { realloc_heap(0x30) };
        let _lock = setup(&heap);
        unsafe {
            let p_user = heap.base().add(BLOCKS + 8);
            // Grow 0x20 -> request 0x40 (block 0x48). Q is free and
            // 0x20+0x30 = 0x50 >= 0x40+8, so the merge happens in place;
            // 0x50 <= (0x48+19)&MASK = 0x58, so no split.
            let result = heap_alloc_core(heap.desc(), 0x40, 0, 5, p_user, 1, 0);
            assert_eq!(result, p_user, "merged in place, same pointer");
            assert_eq!(heap.r32(BLOCKS), 0x50, "P absorbed Q");
            assert_eq!(heap.r32(r), 0x20, "R PREV_FREE cleared");
            assert_eq!(heap.free_list_sizes(), vec![(0x60, s)]);
            assert_eq!((*heap.desc()).free_bytes, 0x90 - 0x30);
            assert_eq!(INSERT_CALLS, 0);
            assert_eq!(FREE_CALLS, 0, "no move, no free");
            assert_eq!(STATS_RETAG_CALLS, 1);
            assert_eq!(LAST_RETAG_OLD_SIZE, 0x20);
            assert_eq!((*heap.desc()).alloc_counter, 1);
            // Original contents untouched.
            for i in 0..0x18 {
                assert_eq!(p_user.add(i).read(), (i as u32 * 7 + 1) as u8);
            }
            assert_eq!(LOCK_CALLS, 1);
            assert_eq!(UNLOCK_CALLS, 1);
        }
    }

    #[test]
    fn realloc_merge_then_splits_the_tail_back() {
        let (heap, r, s) = unsafe { realloc_heap(0x60) };
        let _lock = setup(&heap);
        unsafe {
            let p_user = heap.base().add(BLOCKS + 8);
            // Merged span 0x20+0x60 = 0x80 vs block 0x48: tail 0x38 splits.
            let result = heap_alloc_core(heap.desc(), 0x40, 0, 5, p_user, 1, 0);
            assert_eq!(result, p_user);
            assert_eq!(heap.r32(BLOCKS), 0x48, "P shrunk to the request");
            // P is 0x20 at 0x400, merged to 0x80, split at 0x48 -> 0x448.
            assert_eq!(heap.r32(0x448) & SIZE_MASK, 0x38);
            assert_eq!(heap.r32(0x448) & BLOCK_FREE, BLOCK_FREE);
            // Sorted: 0x38 < 0x60, so the remainder heads the list.
            assert_eq!(heap.free_list_sizes(), vec![(0x38, 0x448), (0x60, s)]);
            // The block after the merged span (R) got PREV_FREE from the
            // insert's successor marking.
            assert_eq!(heap.r32(r) & PREV_FREE, PREV_FREE);
            assert_eq!((*heap.desc()).free_bytes, 0x60 + 0x60 - 0x60 + 0x38);
            assert_eq!(INSERT_CALLS, 1);
            assert_eq!(FREE_CALLS, 0);
        }
    }

    #[test]
    fn realloc_shrink_splits_remainder() {
        let heap = TestHeap::new(0x100);
        heap.fill(0);
        let _lock = setup(&heap);
        unsafe {
            // P allocated 0x60 @0x400, then an allocated fence, then a free
            // block (kept non-adjacent to the coming remainder).
            heap.header(BLOCKS, 0x60);
            let p_user = heap.base().add(BLOCKS + 8);
            for i in 0..0x58 {
                p_user.add(i).write((i as u32 * 3 + 2) as u8);
            }
            heap.header(0x460, 0x20);
            heap.header(0x480, 0x40 | BLOCK_FREE);
            heap.header(0x4c0, 0x20 | PREV_FREE);
            heap.w32(0x4bc, 0x40);
            heap.set_free_list(&[0x480]);
            (*heap.desc()).free_bytes = 0x40;

            // Shrink to request 0x10 -> block 0x18; tail 0x48 goes back.
            let result = heap_alloc_core(heap.desc(), 0x10, 0, 5, p_user, 1, 0);
            assert_eq!(result, p_user, "shrink keeps the block");
            assert_eq!(heap.r32(BLOCKS), 0x18);
            assert_eq!(heap.r32(0x418) & SIZE_MASK, 0x48);
            assert_eq!(heap.r32(0x418) & BLOCK_FREE, BLOCK_FREE);
            assert_eq!(
                heap.free_list_sizes(),
                vec![(0x40, 0x480), (0x48, 0x418)],
                "remainder sorts after the existing 0x40 block"
            );
            assert_eq!((*heap.desc()).free_bytes, 0x40 + 0x48);
            assert_eq!(FREE_CALLS, 0);
            assert_eq!(LAST_RETAG_OLD_SIZE, 0x60);
            for i in 0..0x10 {
                assert_eq!(p_user.add(i).read(), (i as u32 * 3 + 2) as u8);
            }
        }
    }

    /// P(0x20) allocated with a pattern, Q allocated right after (cannot
    /// merge), S(0x60) free, T fence.
    unsafe fn no_merge_heap() -> TestHeap {
        let heap = TestHeap::new(0x100);
        unsafe {
            heap.fill(0);
            heap.header(BLOCKS, 0x20);
            let p_user = heap.base().add(BLOCKS + 8);
            for i in 0..0x18 {
                p_user.add(i).write((i as u32 * 7 + 1) as u8);
            }
            heap.header(0x420, 0x30);
            heap.header(0x450, 0x60 | BLOCK_FREE);
            heap.header(0x4b0, 0x20 | PREV_FREE);
            heap.w32(0x4ac, 0x60);
            heap.set_free_list(&[0x450]);
            (*heap.desc()).free_bytes = 0x60;
        }
        heap
    }

    #[test]
    fn realloc_grow_without_merge_allocates_copies_and_frees() {
        let heap = unsafe { no_merge_heap() };
        let _lock = setup(&heap);
        unsafe {
            let p_user = heap.base().add(BLOCKS + 8);
            // Grow to request 0x40 (block 0x48); 0x60 > 0x58 so S splits
            // and the copy keeps min(0x20-8, 0x40) = 0x18 bytes.
            let result = heap_alloc_core(heap.desc(), 0x40, 0, 5, p_user, 1, 0);
            assert_eq!(result, heap.base().add(0x450 + 0x18 + 8));
            assert_eq!(heap.r32(0x450 + 0x18) & SIZE_MASK, 0x48);
            assert_eq!(heap.free_list_sizes(), vec![(0x18, 0x450)]);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_PTR, p_user);
            for i in 0..0x18 {
                assert_eq!(
                    result.add(i).read(),
                    (i as u32 * 7 + 1) as u8,
                    "copied byte {i}"
                );
            }
            // P's header is untouched (freeing is the free hook's job).
            assert_eq!(heap.r32(BLOCKS), 0x20);
            assert_eq!(LOCK_CALLS, 1);
            assert_eq!(UNLOCK_CALLS, 1);

            // copy_flag == 0 moves without copying (fresh heap).
            let heap2 = no_merge_heap();
            rebind(&heap2);
            let p_user2 = heap2.base().add(BLOCKS + 8);
            let result2 = heap_alloc_core(heap2.desc(), 0x40, 0, 5, p_user2, 0, 0);
            assert_eq!(result2, heap2.base().add(0x450 + 0x18 + 8));
            assert_eq!((result2 as *const u32).read(), 0, "no copy happened");
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_PTR, p_user2);
        }
    }

    #[test]
    fn out_of_memory_returns_null_and_keeps_heap() {
        let heap = unsafe { standard_heap() };
        let _lock = setup(&heap);
        unsafe {
            let result = heap_alloc_core(heap.desc(), 0x1000, 0, 0, core::ptr::null_mut(), 0, 0);
            assert!(result.is_null());
            assert_eq!((*heap.desc()).alloc_counter, 0, "failed alloc skips the counter");
            assert_eq!(LOCK_CALLS, 1);
            assert_eq!(UNLOCK_CALLS, 1, "unlock still runs on failure");

            // Realloc failure: old block intact, not freed.
            let fence = heap.base().add(BLOCKS + 8);
            let result = heap_alloc_core(heap.desc(), 0x1000, 0, 0, fence, 1, 0);
            assert!(result.is_null());
            assert_eq!(heap.r32(BLOCKS), 0x20, "old block still allocated");
            assert_eq!(FREE_CALLS, 0);
        }
    }

    #[test]
    fn auto_init_runs_once_when_uninitialized() {
        let heap = unsafe { standard_heap() };
        let _lock = setup(&heap);
        unsafe {
            (*heap.desc()).initialized = 0;
            (*heap.desc()).auto_init = 1;
            let result = heap_alloc_core(heap.desc(), 0x10, 0, 0, core::ptr::null_mut(), 0, 0);
            assert!(!result.is_null());
            assert_eq!(AUTO_INIT_CALLS, 1);
            assert_eq!((*heap.desc()).initialized & 0xff, 1, "low byte set");

            let result = heap_alloc_core(heap.desc(), 0x10, 0, 0, core::ptr::null_mut(), 0, 0);
            assert!(!result.is_null());
            assert_eq!(AUTO_INIT_CALLS, 1, "no second auto-init");
        }
    }

    /// Runs `body`; expects the heap_panic hook to fire with `reason`.
    /// The mock hook longjmps back to the sigsetjmp inside this helper.
    unsafe fn expect_panic(reason: u32, body: impl FnOnce()) {
        if sigsetjmp(JMP_BUF.as_mut_ptr(), 0) == 0 {
            body();
            panic!("expected heap_panic reason {reason}, call returned");
        }
        assert_eq!(PANIC_REASON, reason);
    }

    #[test]
    fn corruption_misaligned_size_panics() {
        let heap = unsafe { standard_heap() };
        let _lock = setup(&heap);
        unsafe {
            expect_panic(HEAP_PANIC_BAD_SIZE, || {
                heap_freelist_alloc(heap.desc(), 0x12, 0);
            });
        }
    }

    #[test]
    fn corruption_successor_flags_panics() {
        let heap = TestHeap::new(0x100);
        heap.fill(0xAA);
        let _lock = setup(&heap);
        unsafe {
            heap.header(BLOCKS, 0x20);
            heap.header(0x420, 0x20 | BLOCK_FREE);
            // Successor claims its predecessor is allocated: corruption.
            heap.header(0x440, 0x20);
            heap.set_free_list(&[0x420]);
            (*heap.desc()).free_bytes = 0x20;
            expect_panic(HEAP_PANIC_BAD_FLAGS, || {
                heap_freelist_alloc(heap.desc(), 0x10, 0);
            });
        }
    }

    #[test]
    fn corruption_realloc_header_panics() {
        let heap = unsafe { standard_heap() };
        let _lock = setup(&heap);
        unsafe {
            // Zero header.
            let bogus = heap.base().add(BLOCKS + 8);
            heap.header(BLOCKS, 0);
            expect_panic(HEAP_PANIC_BAD_BLOCK, || {
                heap_alloc_core(heap.desc(), 0x40, 0, 0, bogus, 1, 0);
            });
            // Header with the FREE bit set.
            heap.header(BLOCKS, 0x20 | BLOCK_FREE);
            expect_panic(HEAP_PANIC_BAD_BLOCK, || {
                heap_alloc_core(heap.desc(), 0x40, 0, 0, bogus, 1, 0);
            });
        }
    }

    #[test]
    fn realloc_grow_into_free_predecessor_flag_panics() {
        let (heap, _r, _s) = unsafe { realloc_heap(0x30) };
        let _lock = setup(&heap);
        unsafe {
            let p_user = heap.base().add(BLOCKS + 8);
            // Lie: Q's PREV_FREE says P is free while P is allocated.
            heap.header(0x420, 0x30 | BLOCK_FREE | PREV_FREE);
            expect_panic(HEAP_PANIC_BAD_FLAGS, || {
                heap_alloc_core(heap.desc(), 0x40, 0, 0, p_user, 1, 0);
            });
        }
    }
}
