//! Port of the retailOS heap free path (boundary-tag coalescing +
//! size-sorted free-list insertion) from the heap core cluster
//! 0x0819cd5c..0x0819d9d8:
//!
//! - `heap_free_insert` — original: `FUN_0819d314` @ 0x0819d314 (456
//!   bytes). Frees an allocated block given its header: coalesces forward
//!   with the next physical block when that block's header says free
//!   (bit 0), and backward with the previous physical block when the freed
//!   header's prev-free bit (bit 1) is set — the previous block is located
//!   through the size footer copy it left at `block_end - 4` when it was
//!   freed. The merged block is marked free, the following block's
//!   prev-free bit is set, the footer copy is refreshed, and the block is
//!   inserted into the ascending size-sorted doubly-linked free list
//!   anchored at the descriptor's sentinel (+0xd0). Corruption is fatal
//!   via `heap_panic`: misaligned header, bit 2 of the header word set
//!   (sizes are 8-aligned), the next block already believing we are free
//!   (double free), a zero/misaligned footer, a footer that disagrees with
//!   the previous header's size, or a previous block that is not actually
//!   free. Returns the (possibly merged) block header.
//! - `heap_free` — original: `FUN_0819d4dc` @ 0x0819d4dc (200 bytes).
//!   User-pointer free. NULL is a no-op; a zero header word or an
//!   already-free header (bit 0 set) is a fatal double free. Otherwise it
//!   takes the heap mutex, debits the telemetry counters (per-tag and
//!   per-class byte counters and totals, the size-bin histogram and
//!   total, and the allocated byte count), runs `heap_free_insert` and
//!   drops the mutex.
//! - `msb_index` — original: `FUN_080e837c` @ 0x080e837c (56 bytes; a
//!   shared helper outside the heap cluster). floor(log2(size)) via a
//!   5-step binary search over a mask/shift table (0xffff0000/16,
//!   0xff00ff00/8, 0xf0f0f0f0/4, 0xcccccccc/2, 0xaaaaaaaa/1 — the table
//!   itself lives at 0x083e9b60, outside the osos image; the values are
//!   the canonical set implied by the loop structure). Used to pick the
//!   histogram bin debited on free.
//!
//! Free-list layout recovered from the machine code: a free block keeps
//! its list links at header+4 (`next`, toward larger blocks, NULL at the
//! tail — this overlays `BlockHeader::link_or_tag`) and at header+8
//! (`prev`, toward smaller blocks, pointing at the sentinel for the head
//! element — this overlays the first user word). The sentinel at
//! descriptor+0xd0 is only a head anchor: its +4 field is the list head
//! (NULL when empty) and its size word is 0, so the sorted walk always
//! steps past it.
//!
//! Hooks (OS-facing machinery reached through swappable fn pointers so
//! host tests can observe/replace it):
//! - `heap_panic` @ 0x08030f44 is exported by src/heap/veneers.rs (raise
//!   -> exit -> terminate through its ops table). To avoid a duplicate
//!   `#[no_mangle]` symbol, this file routes corruption through a private
//!   fn of the same name which dispatches to the `HEAP_PANIC_HOOK` fn
//!   pointer; the default is a `C-unwind` shim over the veneers.rs port.
//!   Host tests install an unwinding hook and observe panics with
//!   `catch_unwind`.
//! - The heap mutex (`heap_lock` @ 0x0819d6cc / `heap_unlock` @
//!   0x0819cde4 — RTXC semaphore via the descriptor bytes at +0xb4/+0xb5
//!   and handle at +0xb8) is routed through `HEAP_MUTEX_HOOKS`, which
//!   defaults to the real wrappers.rs ports (no-ops until the kernel
//!   reports running, exactly like the originals); host tests install
//!   counting hooks.
//!
//! Simplifications / deviations:
//! - The caller tag and size class halfwords are read straight from the
//!   header and used as unchecked array indexes exactly like the original
//!   (a corrupt tag scribbles outside the descriptor in both versions).
//! - The original's `adds r2, r0, #0xd0; beq` guard (skips insertion when
//!   descriptor+0xd0 wraps to 0 — impossible for a real descriptor) is
//!   omitted.
//! - `heap_free` receives the veneer caller tag in r2 but never uses it
//!   (only saved/restored on the stack); kept as an unused parameter to
//!   preserve the 3-argument contract. The original also leaves the
//!   descriptor in r0 on exit purely as a side effect of the unlock call
//!   setup — the port returns `()`.
//! - Free-list links are modeled with the private `FreeNode` overlay:
//!   the original 0/+4/+8 (size_flags/next/prev) layout on the 32-bit
//!   target; on 64-bit hosts the pointer fields widen (same convention as
//!   `FreeSentinel` in types.rs) so tests can store real host pointers.
//!   All access goes through named fields.
//! - `heap_free_insert`, `msb_index` and the panic stub are
//!   `#[inline(never)]` so the ARM build keeps the original's call
//!   boundaries (`bl`) for tools/match.py review.
//! - The two exported functions use the `C-unwind` ABI so host tests can
//!   observe `heap_panic` through the unwinding recording hook with
//!   `catch_unwind`; on the ARM target (panic=abort, no unwinding) this is
//!   the same AAPCS contract as the original.

use crate::heap::types::{BlockHeader, HeapDescriptor, BLOCK_FREE, PREV_FREE, SIZE_MASK};

/// Free-list node overlay for block headers and the sentinel (see the
/// module header for the layout and the 64-bit host widening convention).
#[repr(C)]
struct FreeNode {
    size_flags: u32,
    next: *mut FreeNode,
    prev: *mut FreeNode,
}

/// Panic hook contract: like the original `heap_panic`, the hook must not
/// return. Declared `C-unwind` so host tests can install a hook that
/// records the panic and unwinds into `catch_unwind`; the default stub
/// spins forever.
pub type HeapPanicHook = unsafe extern "C-unwind" fn() -> !;

/// Default heap_panic: the real veneers.rs port (raise -> exit ->
/// terminate), behind a `C-unwind` shim so the hook type stays
/// test-catchable. Never returns, like the original.
unsafe extern "C-unwind" fn heap_panic_ported() -> ! {
    crate::heap::veneers::heap_panic()
}

/// Wired default (see the module header). Host tests swap in a recording
/// hook and restore this afterwards.
pub(crate) const DEFAULT_HEAP_PANIC_HOOK: HeapPanicHook = heap_panic_ported;

/// The active heap_panic implementation. Defaults to the real veneers.rs
/// port; swapped by host tests.
pub static mut HEAP_PANIC_HOOK: HeapPanicHook = DEFAULT_HEAP_PANIC_HOOK;

/// Reads the hook. Volatile so LLVM cannot constant-fold the load and
/// inline the default stub's `loop {}` (same rationale as malloc_rt.rs).
#[inline(always)]
fn panic_hook() -> HeapPanicHook {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HEAP_PANIC_HOOK)) }
}

/// heap_panic — original: `FUN_08030f44` @ 0x08030f44 (32 bytes, fatal,
/// does not return). Private stub; the canonical export lives in
/// src/heap/veneers.rs (see the module header).
#[inline(never)]
unsafe fn heap_panic() -> ! {
    panic_hook()()
}

/// Indirect dispatch for the heap mutex (see the module header; defaults
/// are the real wrappers.rs ports).
#[derive(Clone, Copy)]
pub struct HeapMutexHooks {
    /// `heap_lock` @ 0x0819d6cc: takes the descriptor's RTXC semaphore.
    pub lock: unsafe extern "C" fn(desc: *mut HeapDescriptor),
    /// `heap_unlock` @ 0x0819cde4: releases it.
    pub unlock: unsafe extern "C" fn(desc: *mut HeapDescriptor),
}

/// Wired default (see the module header). Host tests swap in counting
/// hooks and restore this afterwards.
pub(crate) const DEFAULT_HEAP_MUTEX_HOOKS: HeapMutexHooks = HeapMutexHooks {
    lock: crate::heap::wrappers::heap_lock,
    unlock: crate::heap::wrappers::heap_unlock,
};

/// The active heap mutex implementation. Defaults to the real ports;
/// swapped by host tests.
pub static mut HEAP_MUTEX_HOOKS: HeapMutexHooks = DEFAULT_HEAP_MUTEX_HOOKS;

/// Reads the hooks (volatile; same rationale as `panic_hook`).
#[inline(always)]
fn mutex_hooks() -> HeapMutexHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HEAP_MUTEX_HOOKS)) }
}

/// msb_index — original: `FUN_080e837c` @ 0x080e837c (56 bytes).
///
/// Index of the highest set bit of `value` (0 for 0), via the original's
/// 5-step binary search: coarsest mask first (the original counts r1 down
/// from 4 through its mask/shift table, so the table stores the fine masks
/// first; the arrays here are in test order instead).
#[inline(never)]
fn msb_index(mut value: u32) -> u32 {
    const MASKS: [u32; 5] = [0xffff_0000, 0xff00_ff00, 0xf0f0_f0f0, 0xcccc_cccc, 0xaaaa_aaaa];
    const SHIFTS: [u32; 5] = [16, 8, 4, 2, 1];
    let mut index = 0;
    for step in 0..5 {
        if value & MASKS[step] != 0 {
            value >>= SHIFTS[step];
            index |= SHIFTS[step];
        }
    }
    index
}

/// Removes `node` from the free list. The original inlines this twice in
/// `heap_free_insert`; both links are NULL-tolerant.
#[inline(always)]
unsafe fn free_list_unlink(node: *mut FreeNode) {
    let next = (*node).next;
    if !next.is_null() {
        (*next).prev = (*node).prev;
    }
    let prev = (*node).prev;
    if !prev.is_null() {
        (*prev).next = next;
    }
}

/// heap_free_insert — original: `FUN_0819d314` @ 0x0819d314 (456 bytes).
///
/// Coalesces the allocated block at `header` with free physical neighbors
/// and inserts it into `desc`'s size-sorted free list. Returns the
/// (possibly merged) block header. Fatal via `heap_panic` on any
/// corruption described in the module header.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C-unwind" fn heap_free_insert(
    desc: *mut HeapDescriptor,
    header: *mut BlockHeader,
) -> *mut BlockHeader {
    // Prologue sanity checks (the original gates these behind a
    // conditional-execution chain; every failure path is heap_panic).
    if (header as usize).wrapping_add(8) & 7 != 0 {
        heap_panic();
    }
    let mut node = header as *mut FreeNode;
    if (*node).size_flags & 4 != 0 {
        // Block sizes are 8-aligned; bit 2 can only be corruption.
        heap_panic();
    }

    // Forward coalescing: absorb the next physical block if it is free.
    let next_block = (node as usize + ((*node).size_flags & SIZE_MASK) as usize) as *mut FreeNode;
    let next_flags = (*next_block).size_flags;
    if next_flags & PREV_FREE != 0 {
        // The next block already believes we are free: double free.
        heap_panic();
    }
    if next_flags & BLOCK_FREE != 0 {
        let next_size = next_flags & SIZE_MASK;
        (*desc).free_bytes = (*desc).free_bytes.wrapping_sub(next_size);
        (*node).size_flags = (*node).size_flags.wrapping_add(next_size);
        free_list_unlink(next_block);
    }

    // Backward coalescing: if the previous physical block is free it is
    // located through the size footer copy it left at our header - 4.
    if (*node).size_flags & PREV_FREE != 0 {
        let footer = (node as *mut u32).sub(1).read();
        if footer == 0 || footer & 3 != 0 {
            heap_panic();
        }
        let prev_block = (node as usize - footer as usize) as *mut FreeNode;
        let prev_flags = (*prev_block).size_flags;
        if prev_flags & SIZE_MASK != footer {
            // Footer disagrees with the previous header's size.
            heap_panic();
        }
        if prev_flags & BLOCK_FREE == 0 {
            // prev-free bit set but the previous block is allocated.
            heap_panic();
        }
        (*desc).free_bytes = (*desc).free_bytes.wrapping_sub(footer);
        (*prev_block).size_flags =
            (*prev_block).size_flags.wrapping_add((*node).size_flags & SIZE_MASK);
        free_list_unlink(prev_block);
        node = prev_block;
    }

    // Mark free, propagate prev-free to the following block, refresh the
    // footer copy (pure size, no flag bits).
    (*node).size_flags |= BLOCK_FREE;
    let size = (*node).size_flags & SIZE_MASK;
    let following = (node as usize + size as usize) as *mut FreeNode;
    (*following).size_flags |= PREV_FREE;
    ((node as usize + size as usize - 4) as *mut u32).write(size);

    // Ascending size-sorted insertion: insert before the first node whose
    // size is >= ours; a NULL next makes us the new tail.
    let sentinel = core::ptr::addr_of_mut!((*desc).sentinel) as *mut FreeNode;
    let mut candidate = sentinel;
    loop {
        if (*candidate).size_flags & SIZE_MASK >= size {
            if candidate == sentinel {
                // New head (the original special-cases the sentinel anchor).
                let old_head = (*sentinel).next;
                (*node).next = old_head;
                (*node).prev = sentinel;
                if !old_head.is_null() {
                    (*old_head).prev = node;
                }
                (*sentinel).next = node;
            } else {
                let prev = (*candidate).prev;
                (*node).next = candidate;
                (*node).prev = prev;
                if !prev.is_null() {
                    (*prev).next = node;
                }
                (*candidate).prev = node;
            }
            break;
        }
        let next = (*candidate).next;
        if next.is_null() {
            // New tail.
            (*node).next = core::ptr::null_mut();
            (*candidate).next = node;
            (*node).prev = candidate;
            break;
        }
        candidate = next;
    }

    (*desc).free_bytes = (*desc).free_bytes.wrapping_add(size);
    node as *mut BlockHeader
}

/// heap_free — original: `FUN_0819d4dc` @ 0x0819d4dc (200 bytes).
///
/// Frees the user pointer `ptr` into `heap`. NULL is a no-op; a zero
/// header word or an already-free block is a fatal double free. `_tag` is
/// the veneer caller tag the original receives in r2 but never uses.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C-unwind" fn heap_free(heap: *mut HeapDescriptor, ptr: *mut u8, _tag: usize) {
    if ptr.is_null() {
        return;
    }
    let header = ptr.sub(8) as *mut BlockHeader;
    let size_flags = (*header).size_flags;
    if size_flags == 0 || size_flags & BLOCK_FREE != 0 {
        // Zero header word or already-free block: corrupt / double free.
        heap_panic();
    }
    let hooks = mutex_hooks();
    (hooks.lock)(heap);

    let size = (*header).size_flags & SIZE_MASK;
    let link_or_tag = (*header).link_or_tag;
    // Unchecked indexing, exactly like the original (see module header).
    let tag = (link_or_tag & 0xffff) as usize;
    let bytes_per_tag = (*heap).bytes_per_tag.as_mut_ptr().add(tag);
    *bytes_per_tag = bytes_per_tag.read().wrapping_sub(size);
    (*heap).tag_total = (*heap).tag_total.wrapping_sub(size);
    let class = (link_or_tag >> 16) as usize;
    let bytes_per_class = (*heap).bytes_per_class.as_mut_ptr().add(class);
    *bytes_per_class = bytes_per_class.read().wrapping_sub(size);
    (*heap).class_total = (*heap).class_total.wrapping_sub(size);
    let bin = msb_index(size) as usize;
    let blocks_per_bin = (*heap).blocks_per_bin.as_mut_ptr().add(bin);
    *blocks_per_bin = blocks_per_bin.read().wrapping_sub(1);
    (*heap).bin_total = (*heap).bin_total.wrapping_sub(1);
    (*heap).allocated_bytes = (*heap).allocated_bytes.wrapping_sub(size);

    heap_free_insert(heap, header);
    (hooks.unlock)(heap);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests that swap the global hooks.
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    static mut PANIC_CALLS: usize = 0;
    /// Mutex event log ('L' = lock, 'U' = unlock).
    static mut EVENTS: [u8; 16] = [0; 16];
    static mut EVENT_COUNT: usize = 0;

    struct PanicMarker;

    unsafe extern "C-unwind" fn recording_panic() -> ! {
        PANIC_CALLS += 1;
        std::panic::resume_unwind(Box::new(PanicMarker));
    }

    unsafe extern "C" fn counting_lock(_desc: *mut HeapDescriptor) {
        EVENTS[EVENT_COUNT] = b'L';
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn counting_unlock(_desc: *mut HeapDescriptor) {
        EVENTS[EVENT_COUNT] = b'U';
        EVENT_COUNT += 1;
    }

    const TEST_MUTEX_HOOKS: HeapMutexHooks = HeapMutexHooks {
        lock: counting_lock,
        unlock: counting_unlock,
    };

    /// Serializes hook state, installs the recording panic hook + counting
    /// mutex hooks, and silences panic output for the catch_unwind tests.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = HOOK_LOCK.lock().unwrap();
        unsafe {
            PANIC_CALLS = 0;
            EVENTS = [0; 16];
            EVENT_COUNT = 0;
            core::ptr::addr_of_mut!(HEAP_PANIC_HOOK).write(recording_panic);
            core::ptr::addr_of_mut!(HEAP_MUTEX_HOOKS).write(TEST_MUTEX_HOOKS);
        }
        std::panic::set_hook(Box::new(|_| {}));
        guard
    }

    /// 8-aligned block arena (u64-backed).
    struct Arena(Vec<u64>);

    impl Arena {
        fn new(bytes: usize) -> Arena {
            Arena(vec![0u64; bytes / 8])
        }
        fn base(&mut self) -> *mut u8 {
            self.0.as_mut_ptr() as *mut u8
        }
        unsafe fn header(&mut self, off: usize) -> *mut BlockHeader {
            self.base().add(off) as *mut BlockHeader
        }
        unsafe fn word(&mut self, off: usize) -> u32 {
            (self.base().add(off) as *const u32).read()
        }
    }

    fn new_desc() -> *mut HeapDescriptor {
        Box::leak(Box::new(unsafe { core::mem::zeroed() }))
    }

    fn sentinel(desc: *mut HeapDescriptor) -> *mut FreeNode {
        unsafe { core::ptr::addr_of_mut!((*desc).sentinel) as *mut FreeNode }
    }

    /// Allocated block header; `size` includes the 8-byte header.
    unsafe fn alloc_block(arena: &mut Arena, off: usize, size: u32, prev_free: bool) {
        let h = arena.header(off);
        (*h).size_flags = size | if prev_free { PREV_FREE } else { 0 };
        (*h).link_or_tag = 0;
    }

    /// Free block header + footer copy, not linked into any list.
    unsafe fn free_block(
        arena: &mut Arena,
        off: usize,
        size: u32,
        prev_free: bool,
    ) -> *mut BlockHeader {
        let h = arena.header(off);
        (*h).size_flags = size | BLOCK_FREE | if prev_free { PREV_FREE } else { 0 };
        (arena.base().add(off + size as usize - 4) as *mut u32).write(size);
        h
    }

    /// Wires `block` into `desc`'s free list as the only element.
    unsafe fn list_of_one(desc: *mut HeapDescriptor, block: *mut BlockHeader) {
        let s = sentinel(desc);
        let n = block as *mut FreeNode;
        (*s).next = n;
        (*n).next = core::ptr::null_mut();
        (*n).prev = s;
    }

    /// size_flags of every list element, head to tail.
    unsafe fn list_sizes(desc: *mut HeapDescriptor) -> Vec<u32> {
        let mut out = Vec::new();
        let mut cur = (*sentinel(desc)).next;
        while !cur.is_null() {
            out.push((*cur).size_flags);
            cur = (*cur).next;
        }
        out
    }

    /// Runs `f` expecting exactly one heap_panic (observed via the hook).
    unsafe fn expect_panic(f: impl FnOnce()) {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        assert!(r.is_err(), "expected heap_panic");
        assert_eq!(PANIC_CALLS, 1);
    }

    #[test]
    fn insert_between_two_allocated_blocks_coalesces_neither_way() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            alloc_block(&mut arena, 0x00, 0x40, false); // A
            alloc_block(&mut arena, 0x40, 0x40, false); // B (freed)
            alloc_block(&mut arena, 0x80, 0x40, false); // C
            (*desc).free_bytes = 0;

            let b = arena.header(0x40);
            let ret = heap_free_insert(desc, b);
            assert_eq!(ret, b);
            assert_eq!(PANIC_CALLS, 0);
            // B marked free, size unchanged.
            assert_eq!((*b).size_flags, 0x40 | BLOCK_FREE);
            // C now sees its predecessor as free; A untouched.
            assert_eq!((*arena.header(0x80)).size_flags, 0x40 | PREV_FREE);
            assert_eq!((*arena.header(0x00)).size_flags, 0x40);
            // Footer copy: pure size, no flag bits (header word is 0x41).
            assert_eq!(arena.word(0x80 - 4), 0x40);
            // List: sentinel -> B -> NULL; B.prev = sentinel.
            let s = sentinel(desc);
            assert_eq!((*s).next, b as *mut FreeNode);
            assert_eq!((*(b as *mut FreeNode)).prev, s);
            assert!((*(b as *mut FreeNode)).next.is_null());
            assert_eq!((*desc).free_bytes, 0x40);
        }
    }

    #[test]
    fn coalesce_forward_only() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            alloc_block(&mut arena, 0x00, 0x40, false); // A (freed)
            let b = free_block(&mut arena, 0x40, 0x80, false); // B free
            alloc_block(&mut arena, 0xC0, 0x40, true); // C: prev (B) free
            list_of_one(desc, b);
            (*desc).free_bytes = 0x80;

            let a = arena.header(0x00);
            let ret = heap_free_insert(desc, a);
            assert_eq!(ret, a);
            assert_eq!(PANIC_CALLS, 0);
            // A absorbed B: 0x40 + 0x80 = 0xC0.
            assert_eq!((*a).size_flags, 0xC0 | BLOCK_FREE);
            // B was unlinked; A is the only list element.
            let s = sentinel(desc);
            assert_eq!((*s).next, a as *mut FreeNode);
            assert_eq!((*(a as *mut FreeNode)).prev, s);
            assert!((*(a as *mut FreeNode)).next.is_null());
            // C keeps PREV_FREE (now referring to the merged A).
            assert_eq!((*arena.header(0xC0)).size_flags, 0x40 | PREV_FREE);
            // Footer at the new block end.
            assert_eq!(arena.word(0xC0 - 4), 0xC0);
            // free_bytes: -0x80 (B absorbed) + 0xC0 (merged inserted).
            assert_eq!((*desc).free_bytes, 0xC0);
        }
    }

    #[test]
    fn coalesce_backward_only() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            let a = free_block(&mut arena, 0x00, 0x80, false); // A free
            alloc_block(&mut arena, 0x80, 0x40, true); // B (freed), prev free
            alloc_block(&mut arena, 0xC0, 0x40, false); // C
            list_of_one(desc, a);
            (*desc).free_bytes = 0x80;

            let b = arena.header(0x80);
            let ret = heap_free_insert(desc, b);
            assert_eq!(ret, a, "merged block starts at the previous header");
            assert_eq!(PANIC_CALLS, 0);
            assert_eq!((*a).size_flags, 0xC0 | BLOCK_FREE);
            // C gains PREV_FREE.
            assert_eq!((*arena.header(0xC0)).size_flags, 0x40 | PREV_FREE);
            assert_eq!(arena.word(0xC0 - 4), 0xC0);
            assert_eq!((*desc).free_bytes, 0xC0);
            // A was unlinked and re-inserted as the only element.
            assert_eq!(list_sizes(desc), vec![0xC0 | BLOCK_FREE]);
        }
    }

    #[test]
    fn coalesce_both_ways() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            let a = free_block(&mut arena, 0x00, 0x40, false); // A free
            alloc_block(&mut arena, 0x40, 0x40, true); // B (freed), prev free
            let c = free_block(&mut arena, 0x80, 0x80, false); // C free
            alloc_block(&mut arena, 0x100, 0x40, true); // D: prev (C) free
            // Free list: A (0x40) before C (0x80), ascending.
            let s = sentinel(desc);
            (*s).next = a as *mut FreeNode;
            (*(a as *mut FreeNode)).prev = s;
            (*(a as *mut FreeNode)).next = c as *mut FreeNode;
            (*(c as *mut FreeNode)).prev = a as *mut FreeNode;
            (*(c as *mut FreeNode)).next = core::ptr::null_mut();
            (*desc).free_bytes = 0xC0;

            let b = arena.header(0x40);
            let ret = heap_free_insert(desc, b);
            assert_eq!(ret, a);
            assert_eq!(PANIC_CALLS, 0);
            // 0x40 (A) + 0x40 (B) + 0x80 (C) = 0x100.
            assert_eq!((*a).size_flags, 0x100 | BLOCK_FREE);
            assert_eq!((*arena.header(0x100)).size_flags, 0x40 | PREV_FREE);
            assert_eq!(arena.word(0x100 - 4), 0x100);
            assert_eq!((*desc).free_bytes, 0x100);
            // Both neighbors unlinked; merged A re-inserted alone.
            assert_eq!(list_sizes(desc), vec![0x100 | BLOCK_FREE]);
        }
    }

    #[test]
    fn free_list_stays_size_sorted() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            // Free blocks interleaved with allocated spacers (adjacent
            // frees would coalesce by design).
            alloc_block(&mut arena, 0x00, 0x100, false); // F1 (freed, 0x100)
            alloc_block(&mut arena, 0x100, 0x40, false); // spacer
            alloc_block(&mut arena, 0x140, 0x40, false); // F2 (freed, 0x40)
            alloc_block(&mut arena, 0x180, 0x40, false); // spacer
            alloc_block(&mut arena, 0x1C0, 0x80, false); // F3 (freed, 0x80)
            alloc_block(&mut arena, 0x240, 0x40, false); // spacer
            alloc_block(&mut arena, 0x280, 0x40, false); // F4 (freed, 0x40)
            alloc_block(&mut arena, 0x2C0, 0x40, false); // end spacer
            let f1 = arena.header(0x00);
            let f2 = arena.header(0x140);
            let f3 = arena.header(0x1C0);
            let f4 = arena.header(0x280);
            heap_free_insert(desc, f1);
            heap_free_insert(desc, f2);
            heap_free_insert(desc, f3);
            heap_free_insert(desc, f4);
            assert_eq!(PANIC_CALLS, 0);

            let s = sentinel(desc);
            // Ascending: F4 (0x40, newest equal size goes first), F2 (0x40),
            // F3 (0x80), F1 (0x100).
            assert_eq!((*s).next, f4 as *mut FreeNode);
            assert_eq!((*(f4 as *mut FreeNode)).next, f2 as *mut FreeNode);
            assert_eq!((*(f2 as *mut FreeNode)).next, f3 as *mut FreeNode);
            assert_eq!((*(f3 as *mut FreeNode)).next, f1 as *mut FreeNode);
            assert!((*(f1 as *mut FreeNode)).next.is_null());
            // prev chain runs back to the sentinel.
            assert_eq!((*(f1 as *mut FreeNode)).prev, f3 as *mut FreeNode);
            assert_eq!((*(f3 as *mut FreeNode)).prev, f2 as *mut FreeNode);
            assert_eq!((*(f2 as *mut FreeNode)).prev, f4 as *mut FreeNode);
            assert_eq!((*(f4 as *mut FreeNode)).prev, s);
            assert_eq!((*desc).free_bytes, 0x100 + 0x40 + 0x80 + 0x40);
        }
    }

    #[test]
    fn misaligned_header_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            let bad = arena.header(0x44); // header+8 not 8-aligned
            expect_panic(|| {
                heap_free_insert(desc, bad);
            });
        }
    }

    #[test]
    fn header_bit2_set_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            let h = arena.header(0x00);
            (*h).size_flags = 0x44; // bit 2: impossible in an 8-aligned size
            expect_panic(|| {
                heap_free_insert(desc, h);
            });
        }
    }

    #[test]
    fn double_free_next_block_prev_free_bit_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            alloc_block(&mut arena, 0x00, 0x40, false); // A "freed" again
            // B already believes A is free -> A is a double free.
            alloc_block(&mut arena, 0x40, 0x40, true);
            let a = arena.header(0x00);
            expect_panic(|| {
                heap_free_insert(desc, a);
            });
        }
    }

    #[test]
    fn backward_zero_footer_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            // B claims its predecessor is free, but there is no footer.
            alloc_block(&mut arena, 0x80, 0x40, true);
            alloc_block(&mut arena, 0xC0, 0x40, false);
            let b = arena.header(0x80);
            expect_panic(|| {
                heap_free_insert(desc, b);
            });
        }
    }

    #[test]
    fn backward_misaligned_footer_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            alloc_block(&mut arena, 0x80, 0x40, true);
            alloc_block(&mut arena, 0xC0, 0x40, false);
            (arena.base().add(0x80 - 4) as *mut u32).write(0x43);
            let b = arena.header(0x80);
            expect_panic(|| {
                heap_free_insert(desc, b);
            });
        }
    }

    #[test]
    fn backward_footer_size_mismatch_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            // Footer says 0x40 but the header there describes 0x80.
            free_block(&mut arena, 0x40, 0x80, false);
            alloc_block(&mut arena, 0x80, 0x40, true);
            alloc_block(&mut arena, 0xC0, 0x40, false);
            (arena.base().add(0x80 - 4) as *mut u32).write(0x40);
            let b = arena.header(0x80);
            expect_panic(|| {
                heap_free_insert(desc, b);
            });
        }
    }

    #[test]
    fn backward_prev_not_free_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            // Footer matches A's size, but A is allocated.
            alloc_block(&mut arena, 0x40, 0x40, false);
            alloc_block(&mut arena, 0x80, 0x40, true);
            alloc_block(&mut arena, 0xC0, 0x40, false);
            (arena.base().add(0x80 - 4) as *mut u32).write(0x40);
            let b = arena.header(0x80);
            expect_panic(|| {
                heap_free_insert(desc, b);
            });
        }
    }

    #[test]
    fn heap_free_null_is_noop() {
        let _lock = setup();
        let desc = new_desc();
        unsafe {
            heap_free(desc, core::ptr::null_mut(), 2);
            assert_eq!(PANIC_CALLS, 0);
            assert_eq!(EVENT_COUNT, 0, "no mutex activity for NULL");
        }
    }

    #[test]
    fn heap_free_zero_header_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            let h = arena.header(0x40); // zeroed arena: size_flags == 0
            expect_panic(|| {
                heap_free(desc, (h as *mut u8).add(8), 2);
            });
            assert_eq!(EVENT_COUNT, 0, "validation happens before the mutex");
        }
    }

    #[test]
    fn heap_free_already_free_header_panics() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            let h = free_block(&mut arena, 0x40, 0x40, false); // bit 0 set
            expect_panic(|| {
                heap_free(desc, (h as *mut u8).add(8), 2);
            });
            assert_eq!(EVENT_COUNT, 0);
        }
    }

    #[test]
    fn heap_free_debits_stats_locks_and_inserts() {
        let _lock = setup();
        let desc = new_desc();
        let mut arena = Arena::new(0x400);
        unsafe {
            alloc_block(&mut arena, 0x00, 0x80, false); // A
            alloc_block(&mut arena, 0x80, 0x40, false); // B (freed)
            alloc_block(&mut arena, 0xC0, 0x40, false); // C
            let b = arena.header(0x80);
            (*b).link_or_tag = (9 << 16) | 5; // class 9, tag 5
            (*desc).bytes_per_tag[5] = 0x1000;
            (*desc).tag_total = 0x5000;
            (*desc).bytes_per_class[9] = 0x2000;
            (*desc).class_total = 0x6000;
            (*desc).blocks_per_bin[6] = 3; // msb_index(0x40) == 6
            (*desc).bin_total = 7;
            (*desc).allocated_bytes = 0x4000;
            (*desc).free_bytes = 0x80;

            heap_free(desc, (b as *mut u8).add(8), 2);
            assert_eq!(PANIC_CALLS, 0);
            assert_eq!(&EVENTS[..EVENT_COUNT], b"LU", "lock ... unlock");
            assert_eq!((*desc).bytes_per_tag[5], 0x1000 - 0x40);
            assert_eq!((*desc).tag_total, 0x5000 - 0x40);
            assert_eq!((*desc).bytes_per_class[9], 0x2000 - 0x40);
            assert_eq!((*desc).class_total, 0x6000 - 0x40);
            assert_eq!((*desc).blocks_per_bin[6], 2);
            assert_eq!((*desc).bin_total, 6);
            assert_eq!((*desc).allocated_bytes, 0x4000 - 0x40);
            assert_eq!((*desc).free_bytes, 0x80 + 0x40);
            // Block inserted: free bit, C's prev-free bit, footer, list.
            assert_eq!((*b).size_flags, 0x40 | BLOCK_FREE);
            assert_eq!((*arena.header(0xC0)).size_flags, 0x40 | PREV_FREE);
            assert_eq!(arena.word(0xC0 - 4), 0x40);
            assert_eq!((*sentinel(desc)).next, b as *mut FreeNode);
        }
    }

    #[test]
    fn msb_index_matches_floor_log2() {
        for (value, want) in [
            (0u32, 0),
            (1, 0),
            (2, 1),
            (3, 1),
            (4, 2),
            (0x40, 6),
            (0x7f, 6),
            (0x80, 7),
            (0x100, 8),
            (0xffff, 15),
            (0x0001_0000, 16),
            (0x7fff_ffff, 30),
            (0x8000_0000, 31),
            (0xffff_ffff, 31),
        ] {
            assert_eq!(msb_index(value), want, "msb_index({value:#x})");
        }
    }
}
