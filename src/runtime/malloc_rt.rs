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
//! Heap-dispatch design (deviation, by necessity): the retailOS heap itself
//! (0x080eb67c / 0x080e7970 / 0x080edbf0, the arena extension 0x0803571c
//! and `__rt_raise` 0x080320a8) is not yet ported, so these veneers cannot
//! tail-branch to real code. Instead of undefined `extern "C"` symbols —
//! which would break the freestanding ARM link — the three heap ops plus
//! the arena-grow and raise entry points dispatch indirectly through the
//! `HEAP_OPS` function-pointer table. The table defaults to documented
//! stubs: `alloc`/`realloc`/`raise` spin forever (they cannot produce
//! memory or a signal handler out of thin air; on real hardware the table
//! must be installed before the heap is touched), `free` silently leaks
//! (harmless), and `grow` reports failure (returns 0). Host tests swap in a
//! mock heap; once the retailOS heap is ported, `HEAP_OPS` can be pointed
//! at the real `extern "C"` targets below.
//!
//! The eventual link contract (not referenced yet — declaring without
//! referencing emits no undefined symbols):
//!
//! ```text
//! extern "C" {
//!     fn os_heap_alloc(size: usize, flag: usize) -> *mut u8;   // 0x080eb67c, flag always 1
//!     fn os_heap_free(ptr: *mut u8, flag: usize);              // 0x080e7970, flag always 1
//!     fn os_heap_realloc(ptr: *mut u8, size: usize,            // 0x080edbf0, a3/a4 always 1
//!                        a3: usize, a4: usize) -> *mut u8;
//!     fn os_heap_grow_arena(min: usize, old_base: *mut usize) -> usize; // 0x0803571c
//!     fn __rt_raise(sig: i32, code: i32) -> i32;               // 0x080320a8 (raise.rs)
//! }
//! ```
//!
//! Simplifications (all in dead or stubbed code paths of the original):
//! - The guard size is a compile-time `1` (veneer 0x082ab194 is a
//!   `mov r0, #1; bx lr` stub), so `align8(guard)` folds to 8.
//! - The descriptor-init and heap-extend hook veneers (0x082ab1ac /
//!   0x082ab1b0) are `bx lr` stubs in osos — the ADS descriptor machinery
//!   is bypassed in favor of the retailOS heap — so they are not called.
//! - The constant `flag = 1` arguments the veneers feed the retailOS heap
//!   are fixed inside the ops-table contract instead of being forwarded.
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

/// Default stub: allocation is impossible without a heap — spin. On real
/// hardware `HEAP_OPS` must be installed before the heap is first used.
unsafe extern "C" fn missing_alloc(_size: usize) -> *mut u8 {
    loop {}
}

/// Default stub: freeing into a nonexistent heap leaks the block — a
/// harmless no-op.
unsafe extern "C" fn missing_free(_ptr: *mut u8) {}

/// Default stub: like `missing_alloc`, cannot produce memory — spin.
unsafe extern "C" fn missing_realloc(_ptr: *mut u8, _size: usize) -> *mut u8 {
    loop {}
}

/// Default stub: report "cannot grow" (0), matching the original's
/// failure path which falls through to the SIGRTMEM raise.
unsafe extern "C" fn missing_grow(_min_size: usize, _old_base: *mut usize) -> usize {
    0
}

/// Default stub: an unhandled SIGRTMEM in the original terminates the OS
/// (0x082b20a0); with no signal runtime the closest safe stub is a spin.
unsafe extern "C" fn missing_raise(_sig: i32, _code: i32) -> i32 {
    loop {}
}

/// The active heap implementation. Defaults to the documented stubs above;
/// replaced by host tests (mock heap) and eventually by the ported
/// retailOS heap. Written once at init on target; tests serialize access.
pub static mut HEAP_OPS: HeapOps = HeapOps {
    alloc: missing_alloc,
    free: missing_free,
    realloc: missing_realloc,
    grow: missing_grow,
    raise: missing_raise,
};

/// Reads the ops table. The read is volatile: the table is meant to be
/// swapped at runtime (heap installer, host tests), and in a build where
/// nothing writes it yet, LLVM would otherwise constant-fold the loads to
/// the default stubs and inline their `loop {}` bodies (observed: `malloc`
/// collapsed to a branch-to-self in the ARM release build).
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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that swap the global ops table / mock state.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

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
}
