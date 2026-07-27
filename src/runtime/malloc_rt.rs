//! Ports of the ARM ADS 1.0.1 heap veneers that sit between the C library
//! and the retailOS heap:
//!
//! - `malloc` — original: `FUN_0802edac` @ 0x0802edac (40 bytes). Loads the
//!   heap descriptor from libspace+8 into r0 and the size into r1, then
//!   tail-branches through veneer 0x082ab188, which *drops* the descriptor
//!   and tail-calls the retailOS allocator @ 0x080eb67c with
//!   (r0 = size, r1 = 1).
//! - `free` — original: `FUN_0802edc8` @ 0x0802edc8 (52 bytes). NULL guard
//!   (`cmp r0, #0; moveq pc, lr`), then descriptor/size setup as above and
//!   tail veneer 0x082ab19c, which re-checks for NULL and tail-calls the
//!   retailOS free @ 0x080e7970 with (r0 = ptr, r1 = 1).
//! - `realloc` — original: `FUN_0802edec` @ 0x0802edec (92 bytes).
//!   `size == 0` -> `free(ptr)`, return NULL. `ptr == NULL` -> `malloc(size)`.
//!   Otherwise descriptor setup and tail veneer 0x082ab1b4 -> retailOS
//!   realloc @ 0x080edbf0 with (r0 = ptr, r1 = size, r2 = 1, r3 = 1).
//! - `__rt_heap_init` — original: `FUN_0802ed14` @ 0x0802ed14 (152 bytes;
//!   the "__rt_heap_extend-ish" init that installs the heap descriptor).
//!   Asks veneer 0x082ab194 for the heap guard size (stub: always 1). If
//!   `limit < base + guard` the initial range is empty, so it tries to grow
//!   the alloc arena via 0x080336c0 (a `push/pop` wrapper around the
//!   sbrk-like arena extension @ 0x0803571c, which bumps libspace+0x14 and
//!   writes the old arena low bound to its out-parameter); on failure it
//!   calls `__rt_raise` @ 0x080320a8 with (9 = SIGRTMEM "Out of heap", 0).
//!   It then stores the (possibly updated) base into libspace+8 as the heap
//!   descriptor, runs the descriptor-init hook veneer 0x082ab1ac (a `bx lr`
//!   stub in osos), and — when `limit != base + align8(guard)` — passes the
//!   region [base + align8(guard), limit) to the heap-extend hook veneer
//!   0x082ab1b0 (also a `bx lr` stub in osos). Returns the descriptor.
//!
//! Also ported here (batch 10):
//! - `os_heap_grow_arena` — original: `FUN_0803571c` @ 0x0803571c
//!   (108 bytes): the sbrk-like arena extension itself (see its doc
//!   comment for the growth policy), plus its 12-byte call veneer
//!   `heap_grow_arena_wrapper` @ 0x080336c0.
//!
//! Heap-dispatch design (deviation, by necessity): instead of the
//! originals' tail branches, the three heap ops plus the arena-grow and
//! raise entry points dispatch indirectly through the `HEAP_OPS`
//! function-pointer table so host tests can swap in a mock heap (pattern
//! shared with heap/veneers.rs and heap/wrappers.rs). Every default is
//! the real port of the original call chain (`DEFAULT_MALLOC_RT_OPS`):
//! - `alloc`/`free`/`realloc` reach the retailOS wrappers
//!   `malloc_wrapper` @ 0x080eb67c / `free_wrapper` @ 0x080e7970 /
//!   `realloc_wrapper` @ 0x080edbf0 (heap/veneers.rs — each runs
//!   `lazy_init_default_heap` @ 0x08077250 and dispatches into the heap
//!   core @ 0x0819d048) through thin shims folding the constants of the
//!   ADS tail veneers, each of which has exactly one caller (the ADS
//!   front-end above it) and therefore lives here as a `*_ported` shim
//!   rather than an exported symbol (binary-verified):
//!   - 0x082ab188 (12 bytes; from `malloc`): `mov r0, r1; mov r1, #1;
//!     b 0x080eb67c` — drops the heap descriptor, tag 1;
//!   - 0x082ab19c (16 bytes; from `free`): `movs r0, r1; movne r1, #1;
//!     bne 0x080e7970; bx lr` — drops the descriptor, re-guards NULL,
//!     tag 1;
//!   - 0x082ab1b4 (20 bytes; from `realloc`): `mov r0, r1; mov r1, r2;
//!     mov r2, #1; mov r3, #1; b 0x080edbf0` — drops the descriptor,
//!     tag 1, copy-on-move 1.
//! - `grow` is `heap_grow_arena_wrapper` @ 0x080336c0 — the exact `bl`
//!   target of `__rt_heap_init` @ 0x0802ed40. The extension derives its
//!   limit from the live stack pointer and the libspace arena fields;
//!   the original reads the same state unconditionally and relies on
//!   startup having seeded libspace before the heap is touched, so the
//!   wired default is behavior-faithful.
//! - `raise` is `__rt_raise` @ 0x080320a8 (runtime/raise.rs), the
//!   original's `bleq 0x080320a8` SIGRTMEM path.
//!
//! Simplifications (all in dead or stubbed code paths of the original):
//! - The guard size is a compile-time `1` (veneer 0x082ab194 is a
//!   `mov r0, #1; bx lr` stub), so `align8(guard)` folds to 8.
//! - The descriptor-init and heap-extend hook veneers (0x082ab1ac /
//!   0x082ab1b0) are `bx lr` stubs in osos — the ADS descriptor machinery
//!   is bypassed in favor of the retailOS heap — so they are not called.
//! - The constant tag/copy `1` arguments the tail veneers feed the
//!   retailOS heap are fixed inside the default shims (`ADS_HEAP_TAG`,
//!   `ADS_REALLOC_COPY`) instead of being forwarded.
//! - `__rt_heap_init` keeps the original's 4-argument register contract;
//!   r2 is unused by the original and r3 only seeds the stack slot the
//!   arena extension overwrites, so both are inert here.
//! - Symbol exports (`#[no_mangle]`) are gated to the firmware target (`target_os = "none"`):
//!   on macOS, dyld interposes the test executable's exported
//!   `malloc`/`free`/`realloc` over libSystem's, and std's startup
//!   allocations would dispatch into the spin-forever default stubs.

use crate::errno::libspace;

/// ADS signal raised when the heap cannot be initialized: 9 = SIGRTMEM
/// ("Out of heap"; see raise.rs for the signal table).
const SIGRTMEM: i32 = 9;

/// Heap guard size — veneer 0x082ab194 in osos is a stub returning 1
/// (`mov r0, #1; bx lr`), regardless of its argument.
const HEAP_GUARD_SIZE: usize = 1;

/// Indirect dispatch table for the not-yet-ported retailOS heap (see the
/// module header for the design and the default-stub behavior).
#[derive(Clone, Copy)]
pub struct HeapOps {
    /// retailOS allocator @ 0x080eb67c (called by the malloc veneer with
    /// r0 = size, r1 = 1; the flag is folded into this contract).
    pub alloc: unsafe extern "C" fn(size: usize) -> *mut u8,
    /// retailOS free @ 0x080e7970 (r0 = ptr, r1 = 1).
    pub free: unsafe extern "C" fn(ptr: *mut u8),
    /// retailOS realloc @ 0x080edbf0 (r0 = ptr, r1 = size, r2 = 1, r3 = 1).
    pub realloc: unsafe extern "C" fn(ptr: *mut u8, size: usize) -> *mut u8,
    /// sbrk-like alloc-arena extension @ 0x0803571c (reached from the init
    /// through the wrapper @ 0x080336c0). Grows the arena by at least
    /// `min_size`, writes the old arena low bound to `old_base` and returns
    /// the grown size, or 0 on failure.
    pub grow: unsafe extern "C" fn(min_size: usize, old_base: *mut usize) -> usize,
    /// `__rt_raise` @ 0x080320a8 (ported in raise.rs; routed through the
    /// table because that module is not importable from here).
    pub raise: unsafe extern "C" fn(sig: i32, code: i32) -> i32,
}

/// Caller tag the ADS tail veneers pass to the retailOS heap (`mov r1,
/// #1` in 0x082ab188/0x082ab19c, `mov r2, #1` in 0x082ab1b4).
const ADS_HEAP_TAG: usize = 1;

/// Copy-on-move flag the ADS realloc tail veneer 0x082ab1b4 passes
/// (`mov r3, #1`): a relocated block keeps its contents.
const ADS_REALLOC_COPY: usize = 1;

/// `alloc` slot default — the ADS tail veneer @ 0x082ab188 (12 bytes,
/// sole caller: `malloc`): drops the heap descriptor and tail-calls the
/// retailOS allocator `malloc_wrapper` @ 0x080eb67c with tag 1. The
/// descriptor drop lives in the `HeapOps` contract (the slot never
/// receives it).
unsafe extern "C" fn alloc_ported(size: usize) -> *mut u8 {
    crate::heap::veneers::malloc_wrapper(size, ADS_HEAP_TAG)
}

/// `free` slot default — the ADS tail veneer @ 0x082ab19c (16 bytes,
/// sole caller: `free`): drops the descriptor, re-guards NULL (`movs r0,
/// r1; bne ...`) and tail-calls the retailOS `free_wrapper` @ 0x080e7970
/// with tag 1.
unsafe extern "C" fn free_ported(ptr: *mut u8) {
    if ptr.is_null() {
        return; // second NULL guard, faithful to the veneer
    }
    crate::heap::veneers::free_wrapper(ptr, ADS_HEAP_TAG)
}

/// `realloc` slot default — the ADS tail veneer @ 0x082ab1b4 (20 bytes,
/// sole caller: `realloc`): drops the descriptor and tail-calls the
/// retailOS `realloc_wrapper` @ 0x080edbf0 with tag 1, copy-on-move 1.
unsafe extern "C" fn realloc_ported(ptr: *mut u8, size: usize) -> *mut u8 {
    crate::heap::veneers::realloc_wrapper(ptr, size, ADS_HEAP_TAG, ADS_REALLOC_COPY)
}

/// Wired defaults (see the module header): every slot is the real port
/// of the original call chain. Host tests swap in a mock heap under
/// `OPS_LOCK` and never dispatch through these.
pub(crate) const DEFAULT_MALLOC_RT_OPS: HeapOps = HeapOps {
    alloc: alloc_ported,
    free: free_ported,
    realloc: realloc_ported,
    grow: heap_grow_arena_wrapper,
    raise: crate::runtime::raise::__rt_raise,
};

/// The active heap implementation. Defaults to the wired table above;
/// host tests swap in a mock heap. Written once at init on target; tests
/// serialize access.
pub static mut HEAP_OPS: HeapOps = DEFAULT_MALLOC_RT_OPS;

/// Reads the ops table. The read is volatile: the table is meant to be
/// swapped at runtime (host tests, target hooks), and in a build where
/// nothing writes it, LLVM would otherwise constant-fold the loads to the
/// defaults and inline them (observed with the old spin-stub defaults:
/// `malloc` collapsed to a branch-to-self in the ARM release build).
#[inline(always)]
fn heap_ops() -> HeapOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS)) }
}

/// malloc — original: `FUN_0802edac` @ 0x0802edac (40 bytes).
///
/// The original loads the heap descriptor from libspace+8 purely so the
/// tail veneer can discard it (the retailOS allocator takes only
/// size + flag 1), so the port dispatches straight to the heap op.
// NOTE: `#[no_mangle]` is gated to the firmware target. On macOS the dynamic
// linker interposes the main executable's exported `malloc`/`free`/`realloc`
// over libSystem's, so the host test binary would route std's startup
// allocations into the spin-forever default stubs and hang before main.
// ARM/release builds export the symbols normally for match.py and linking.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    (heap_ops().alloc)(size)
}

/// free — original: `FUN_0802edc8` @ 0x0802edc8 (52 bytes).
///
/// NULL is a no-op (guarded twice in the original: here, and again in the
/// tail veneer 0x082ab19c).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    (heap_ops().free)(ptr)
}

/// realloc — original: `FUN_0802edec` @ 0x0802edec (92 bytes).
///
/// `size == 0` frees and returns NULL; `ptr == NULL` is plain malloc;
/// anything else dispatches to the retailOS realloc.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    if size == 0 {
        free(ptr);
        return core::ptr::null_mut();
    }
    if ptr.is_null() {
        return malloc(size);
    }
    (heap_ops().realloc)(ptr, size)
}

/// __rt_heap_extend-ish heap init — original: `FUN_0802ed14` @ 0x0802ed14
/// (152 bytes).
///
/// Installs `heap_base` as the heap descriptor at libspace+8. If the
/// [base, limit) range is too small to hold even the guard, the alloc
/// arena is extended first (SIGRTMEM on failure) and base/limit are
/// recomputed from the extension result. `reserved` mirrors the original's
/// unused r2; `arena_seed` mirrors r3, the initial value of the stack slot
/// the arena extension overwrites with the old arena low bound.
///
/// Returns the installed descriptor (the original returns it in both
/// exit paths).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_heap_init(
    heap_base: usize,
    heap_limit: usize,
    _reserved: usize,
    arena_seed: usize,
) -> usize {
    let guard = HEAP_GUARD_SIZE;
    let mut base = heap_base;
    let mut limit = heap_limit;
    if heap_limit < heap_base.wrapping_add(guard) {
        let mut old_arena_base = arena_seed;
        let ops = heap_ops();
        let grown = (ops.grow)(guard, &mut old_arena_base);
        if grown == 0 {
            (ops.raise)(SIGRTMEM, 0);
        }
        if old_arena_base != heap_limit {
            base = old_arena_base;
        }
        limit = old_arena_base.wrapping_add(grown);
    }
    (*libspace()).heap_desc = base as u32;
    // Original: descriptor-init hook veneer 0x082ab1ac (bx lr stub), then,
    // when `limit != base + align8(guard)`, heap-extend hook veneer
    // 0x082ab1b0(desc, base + align8(guard), limit - that) — also a stub.
    // Neither has observable behavior in osos, so nothing to do here.
    let _ = limit;
    base
}

/// Reads the live stack pointer. The original arena extension compares the
/// prospective arena top against `sp` directly (the ADS one-region memory
/// model: heap grows up toward the stack).
#[inline(always)]
fn current_sp() -> usize {
    let sp: usize;
    unsafe {
        #[cfg(target_arch = "arm")]
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    sp
}

/// os_heap_grow_arena — original: `FUN_0803571c` @ 0x0803571c (108 bytes);
/// the sbrk-like ADS alloc-arena extension (the `HEAP_OPS.grow` contract).
///
/// Grows the arena break at libspace+0x14 toward the live stack pointer,
/// bounded by `sp - reserve` where `reserve` is the stack-guard distance at
/// libspace+0x1c. Writes the pre-grow break (= the new region's low bound)
/// to `*old_top_out` in BOTH exit paths, exactly like the original's
/// unconditional `str`. On success the new break is
/// `min((required + 0x1007) & !7, midpoint(limit, required) & !7)` — i.e.
/// roughly 4 KiB beyond the request, but never past halfway to the stack —
/// and the byte growth is returned. Returns 0 when even `required =
/// break + min_size` would cross the limit (the caller then raises
/// SIGRTMEM).
///
/// Deviations: the original computes the midpoint with a 33-bit
/// `adds`+`rrx` average; here it is the overflow-free equivalent
/// `limit/2 + required/2 + (limit & required & 1)`. Arena fields live in
/// the u32 libspace slots (see errno.rs); host tests use small values so
/// the u32 truncation there is invisible.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn os_heap_grow_arena(min_size: usize, old_top_out: *mut usize) -> usize {
    let ls = libspace();
    let top = (*ls).alloc_arena_lo as usize;
    let reserve = (*ls).alloc_arena_hi as usize;
    let required = top.wrapping_add(min_size);
    let limit = current_sp().wrapping_sub(reserve);
    *old_top_out = top;
    match grow_policy(required, limit) {
        None => 0,
        Some(new_top) => {
            (*ls).alloc_arena_lo = new_top as u32;
            new_top.wrapping_sub(top)
        }
    }
}

/// The growth policy of `os_heap_grow_arena`, extracted pure so the
/// stack-limit clamp is host-testable (on a 64-bit host the u32 libspace
/// reserve field cannot place `limit` near a real 64-bit sp). Returns the
/// new arena break, or None when even `required` crosses `limit`.
fn grow_policy(required: usize, limit: usize) -> Option<usize> {
    if required > limit {
        return None;
    }
    let midpoint = (limit / 2)
        .wrapping_add(required / 2)
        .wrapping_add(limit & required & 1)
        & !7;
    let generous = required.wrapping_add(0x1007) & !7;
    Some(if generous > midpoint { midpoint } else { generous })
}

/// heap_grow_arena_wrapper — original: `FUN_080336c0` @ 0x080336c0
/// (12 bytes): a plain `push {r4, lr}; bl 0x0803571c; pop {r4, pc}` call
/// veneer (how `__rt_heap_init` reaches the arena extension in osos).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn heap_grow_arena_wrapper(
    min_size: usize,
    old_top_out: *mut usize,
) -> usize {
    os_heap_grow_arena(min_size, old_top_out)
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that swap the global ops table / mock state.
    /// Shared with runtime/lib_init.rs, whose init walk installs the
    /// heap descriptor.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Locks the ops table / libspace heap fields for a test outside
    /// this module (lib_init.rs's full-init test).
    pub(crate) fn lock_ops() -> std::sync::MutexGuard<'static, ()> {
        OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    // Mock heap call log.
    static mut ALLOC_CALLS: usize = 0;
    static mut LAST_ALLOC_SIZE: usize = 0;
    static mut FREE_CALLS: usize = 0;
    static mut LAST_FREE_PTR: *mut u8 = core::ptr::null_mut();
    static mut REALLOC_CALLS: usize = 0;
    static mut LAST_REALLOC_PTR: *mut u8 = core::ptr::null_mut();
    static mut LAST_REALLOC_SIZE: usize = 0;
    static mut GROW_CALLS: usize = 0;
    static mut GROW_RET: usize = 0;
    static mut GROW_WRITES_BASE: usize = 0;
    static mut RAISE_CALLS: usize = 0;
    static mut LAST_RAISE_SIG: i32 = 0;
    static mut LAST_RAISE_CODE: i32 = 0;

    const BLOCK_A: usize = 0xA110_0000;
    const BLOCK_B: usize = 0xB220_0000;

    unsafe extern "C" fn mock_alloc(size: usize) -> *mut u8 {
        ALLOC_CALLS += 1;
        LAST_ALLOC_SIZE = size;
        BLOCK_A as *mut u8
    }

    unsafe extern "C" fn mock_free(ptr: *mut u8) {
        FREE_CALLS += 1;
        LAST_FREE_PTR = ptr;
    }

    unsafe extern "C" fn mock_realloc(ptr: *mut u8, size: usize) -> *mut u8 {
        REALLOC_CALLS += 1;
        LAST_REALLOC_PTR = ptr;
        LAST_REALLOC_SIZE = size;
        BLOCK_B as *mut u8
    }

    unsafe extern "C" fn mock_grow(_min: usize, old_base: *mut usize) -> usize {
        GROW_CALLS += 1;
        *old_base = GROW_WRITES_BASE;
        GROW_RET
    }

    unsafe extern "C" fn mock_raise(sig: i32, code: i32) -> i32 {
        RAISE_CALLS += 1;
        LAST_RAISE_SIG = sig;
        LAST_RAISE_CODE = code;
        0
    }

    const MOCK_OPS: HeapOps = HeapOps {
        alloc: mock_alloc,
        free: mock_free,
        realloc: mock_realloc,
        grow: mock_grow,
        raise: mock_raise,
    };

    /// Resets the mock log, installs the mock table, returns the lock guard.
    fn mock_heap() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        unsafe {
            ALLOC_CALLS = 0;
            LAST_ALLOC_SIZE = 0;
            FREE_CALLS = 0;
            LAST_FREE_PTR = core::ptr::null_mut();
            REALLOC_CALLS = 0;
            LAST_REALLOC_PTR = core::ptr::null_mut();
            LAST_REALLOC_SIZE = 0;
            GROW_CALLS = 0;
            GROW_RET = 0;
            GROW_WRITES_BASE = 0;
            RAISE_CALLS = 0;
            LAST_RAISE_SIG = 0;
            LAST_RAISE_CODE = 0;
            *core::ptr::addr_of_mut!(HEAP_OPS) = MOCK_OPS;
        }
        guard
    }

    #[test]
    fn malloc_forwards_size_and_returns_block() {
        let _lock = mock_heap();
        unsafe {
            let p = malloc(0x1234);
            assert_eq!(p, BLOCK_A as *mut u8);
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(LAST_ALLOC_SIZE, 0x1234);
        }
    }

    #[test]
    fn free_null_is_noop() {
        let _lock = mock_heap();
        unsafe {
            free(core::ptr::null_mut());
            assert_eq!(FREE_CALLS, 0, "free(NULL) must not reach the heap");
        }
    }

    #[test]
    fn free_forwards_pointer() {
        let _lock = mock_heap();
        unsafe {
            free(BLOCK_A as *mut u8);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_PTR, BLOCK_A as *mut u8);
        }
    }

    #[test]
    fn realloc_zero_size_frees_and_returns_null() {
        let _lock = mock_heap();
        unsafe {
            let p = realloc(BLOCK_A as *mut u8, 0);
            assert!(p.is_null());
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_PTR, BLOCK_A as *mut u8);
            assert_eq!(REALLOC_CALLS, 0, "size 0 must not reach heap realloc");
        }
    }

    #[test]
    fn realloc_null_ptr_is_malloc() {
        let _lock = mock_heap();
        unsafe {
            let p = realloc(core::ptr::null_mut(), 64);
            assert_eq!(p, BLOCK_A as *mut u8);
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(LAST_ALLOC_SIZE, 64);
            assert_eq!(REALLOC_CALLS, 0, "NULL ptr must not reach heap realloc");
        }
    }

    #[test]
    fn realloc_dispatches_to_heap() {
        let _lock = mock_heap();
        unsafe {
            let p = realloc(BLOCK_A as *mut u8, 96);
            assert_eq!(p, BLOCK_B as *mut u8);
            assert_eq!(REALLOC_CALLS, 1);
            assert_eq!(LAST_REALLOC_PTR, BLOCK_A as *mut u8);
            assert_eq!(LAST_REALLOC_SIZE, 96);
        }
    }

    #[test]
    fn init_stores_descriptor_without_grow_when_range_fits() {
        let _lock = mock_heap();
        unsafe {
            let desc = __rt_heap_init(0x1000, 0x2000, 0, 0);
            assert_eq!(desc, 0x1000);
            assert_eq!((*libspace()).heap_desc, 0x1000);
            assert_eq!(GROW_CALLS, 0, "non-empty range must not grow");
            assert_eq!(RAISE_CALLS, 0);
        }
    }

    #[test]
    fn init_grows_arena_when_range_is_empty() {
        let _lock = mock_heap();
        unsafe {
            GROW_WRITES_BASE = 0x3000;
            GROW_RET = 0x1000;
            // limit (0x2000) < base (0x2000) + guard (1) -> extension path.
            let desc = __rt_heap_init(0x2000, 0x2000, 0, 0xdead);
            assert_eq!(GROW_CALLS, 1);
            assert_eq!(RAISE_CALLS, 0, "successful grow must not raise");
            // Old arena base replaces the descriptor base, grown size the
            // limit (the stubbed extend hook makes the limit unobservable).
            assert_eq!(desc, 0x3000);
            assert_eq!((*libspace()).heap_desc, 0x3000);
        }
    }

    #[test]
    fn init_raises_sigrtmem_when_grow_fails() {
        let _lock = mock_heap();
        unsafe {
            GROW_WRITES_BASE = 0x4000;
            GROW_RET = 0; // grow fails
            let desc = __rt_heap_init(0x2000, 0x2000, 0, 0xdead);
            assert_eq!(GROW_CALLS, 1);
            assert_eq!(RAISE_CALLS, 1);
            assert_eq!(LAST_RAISE_SIG, 9, "must raise SIGRTMEM");
            assert_eq!(LAST_RAISE_CODE, 0);
            // With grown == 0: base/limit come from the grow out-param
            // (0x4000 != old limit 0x2000, so base follows it).
            assert_eq!(desc, 0x4000);
            assert_eq!((*libspace()).heap_desc, 0x4000);
        }
    }

    #[test]
    fn init_keeps_base_when_grow_returns_old_limit() {
        let _lock = mock_heap();
        unsafe {
            // If the out-param still equals the passed limit, the original
            // keeps the caller's base (`movne r5, r0` guard).
            GROW_WRITES_BASE = 0x2000;
            GROW_RET = 0x800;
            let desc = __rt_heap_init(0x2000, 0x2000, 0, 0xdead);
            assert_eq!(GROW_CALLS, 1);
            assert_eq!(desc, 0x2000);
            assert_eq!((*libspace()).heap_desc, 0x2000);
        }
    }

    /// Seeds the libspace arena fields, runs the grow, restores them.
    /// Returns (grow return, out-param value, post-grow arena break).
    unsafe fn grow_with_arena(top: u32, reserve: u32, min_size: usize) -> (usize, usize, u32) {
        let ls = libspace();
        let (saved_top, saved_reserve) = ((*ls).alloc_arena_lo, (*ls).alloc_arena_hi);
        (*ls).alloc_arena_lo = top;
        (*ls).alloc_arena_hi = reserve;
        let mut old_top = 0xdeadusize;
        let grown = os_heap_grow_arena(min_size, &mut old_top);
        let new_top = (*ls).alloc_arena_lo;
        (*ls).alloc_arena_lo = saved_top;
        (*ls).alloc_arena_hi = saved_reserve;
        (grown, old_top, new_top)
    }

    #[test]
    fn grow_grants_about_4k_beyond_the_request() {
        let _lock = OPS_LOCK.lock().unwrap();
        unsafe {
            // Host sp is astronomically above the tiny arena values, so
            // the midpoint clamp never binds: exact arithmetic holds.
            let (grown, old_top, new_top) = grow_with_arena(0x1000, 0, 0x100);
            // new break = (0x1000 + 0x100 + 0x1007) & !7 = 0x2100.
            assert_eq!(new_top, 0x2100);
            assert_eq!(grown, 0x1100);
            assert_eq!(old_top, 0x1000, "out-param gets the pre-grow break");
        }
    }

    #[test]
    fn grow_rounds_the_new_break_down_to_8() {
        let _lock = OPS_LOCK.lock().unwrap();
        unsafe {
            let (grown, old_top, new_top) = grow_with_arena(0x1001, 0, 1);
            // required = 0x1002; break = (0x1002 + 0x1007) & !7 = 0x2008.
            assert_eq!(new_top, 0x2008);
            assert_eq!(grown, 0x1007);
            assert_eq!(old_top, 0x1001);
        }
    }

    #[test]
    fn grow_fails_when_the_request_crosses_the_stack_limit() {
        let _lock = OPS_LOCK.lock().unwrap();
        unsafe {
            // required = top + huge overshoots any host sp.
            let (grown, old_top, new_top) = grow_with_arena(0x1000, 0, usize::MAX / 2);
            assert_eq!(grown, 0, "failure returns 0");
            assert_eq!(old_top, 0x1000, "out-param written on failure too");
            assert_eq!(new_top, 0x1000, "break unchanged on failure");
        }
    }

    #[test]
    fn grow_policy_clamps_to_the_midpoint_when_the_limit_is_near() {
        // limit only 0x800 above the request: the generous 4 KiB grant
        // would overshoot, so the midpoint (aligned down to 8) wins.
        assert_eq!(grow_policy(0x1100, 0x1900), Some(0x1500));
        // Odd sum exercises the 33-bit rrx-average carry handling.
        assert_eq!(grow_policy(0x1101, 0x1902), Some((0x1101 + 0x400) & !7));
        // Right at the limit: grant shrinks to the (aligned) request.
        assert_eq!(grow_policy(0x1100, 0x1100), Some(0x1100));
        // One byte short: refuse.
        assert_eq!(grow_policy(0x1101, 0x1100), None);
    }

    /// Every shipped default is the real port of the original chain
    /// (house precedent: kernel/task.rs `default_wired_slots`). Compares
    /// the const table, so no lock and no restore are needed.
    #[test]
    fn default_wired_slots() {
        assert_eq!(DEFAULT_MALLOC_RT_OPS.alloc as usize, alloc_ported as usize);
        assert_eq!(DEFAULT_MALLOC_RT_OPS.free as usize, free_ported as usize);
        assert_eq!(
            DEFAULT_MALLOC_RT_OPS.realloc as usize,
            realloc_ported as usize
        );
        assert_eq!(
            DEFAULT_MALLOC_RT_OPS.grow as usize,
            heap_grow_arena_wrapper as usize
        );
        assert_eq!(
            DEFAULT_MALLOC_RT_OPS.raise as usize,
            crate::runtime::raise::__rt_raise as usize
        );
    }

    // The three default shims, driven end-to-end into the retailOS layer
    // (heap/veneers.rs) with ITS mock heap installed — verifying the ADS
    // tail-veneer constants (tag 1, copy-on-move 1) reach the wrappers.
    // These take veneers' ops lock, not this module's; each test holds
    // exactly one lock, so no ordering hazard.

    #[test]
    fn default_alloc_shim_reaches_retailos_with_tag_1() {
        let _lock = crate::heap::veneers::tests::mock_heap();
        unsafe {
            let p = alloc_ported(0x40);
            assert_eq!(p, crate::heap::veneers::tests::mock_block());
            assert_eq!(
                crate::heap::veneers::tests::alloc_log(),
                (1, 0x40, 1),
                "0x082ab188: one alloc, size through, tag 1"
            );
        }
    }

    #[test]
    fn default_free_shim_guards_null_and_uses_tag_1() {
        let _lock = crate::heap::veneers::tests::mock_heap();
        unsafe {
            free_ported(core::ptr::null_mut());
            assert_eq!(
                crate::heap::veneers::tests::free_log().0,
                0,
                "0x082ab19c re-guards NULL before the retailOS free"
            );
            let block = crate::heap::veneers::tests::mock_block();
            free_ported(block);
            assert_eq!(
                crate::heap::veneers::tests::free_log(),
                (1, block, 1),
                "0x082ab19c: ptr through, tag 1"
            );
        }
    }

    #[test]
    fn default_realloc_shim_uses_tag_1_and_copy_1() {
        let _lock = crate::heap::veneers::tests::mock_heap();
        unsafe {
            let block = crate::heap::veneers::tests::mock_block();
            let p = realloc_ported(block, 0x80);
            assert_eq!(p, block);
            assert_eq!(
                crate::heap::veneers::tests::realloc_log(),
                (1, block, 0x80, 1, 1),
                "0x082ab1b4: ptr/size through, tag 1, copy-on-move 1"
            );
        }
    }

    #[test]
    fn grow_wrapper_is_a_passthrough() {
        let _lock = OPS_LOCK.lock().unwrap();
        unsafe {
            let ls = libspace();
            let (saved_top, saved_reserve) = ((*ls).alloc_arena_lo, (*ls).alloc_arena_hi);
            (*ls).alloc_arena_lo = 0x1000;
            (*ls).alloc_arena_hi = 0;
            let mut old_top = 0usize;
            let grown = heap_grow_arena_wrapper(0x100, &mut old_top);
            (*ls).alloc_arena_lo = saved_top;
            (*ls).alloc_arena_hi = saved_reserve;
            assert_eq!(grown, 0x1100);
            assert_eq!(old_top, 0x1000);
        }
    }
}
