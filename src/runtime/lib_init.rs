//! Ports of the ARM ADS 1.0.1 library-initialization cluster — the
//! callees of `__rt_lib_init` (ported below as `rt_lib_init_for_abort`,
//! its established names.yaml name: abort @ 0x0803206c is its sole
//! caller in osos, binary-verified) plus the init routine itself.
//!
//! - `_fp_init` — original: `FUN_083ecb90` @ 0x083ecb90 (20 bytes).
//!   `bl __rt_fp_status_addr; mov r1, #0; str r1, [r0]` — zeroes the
//!   soft-float status word at libspace+4. Sole caller: the init below.
//! - `heap_guard_size` — original: `FUN_082ab194` @ 0x082ab194 (8 bytes).
//!   `mov r0, #1; bx lr` — the heap guard-size veneer, a stub returning 1
//!   regardless of its argument. Two callers (binary-verified):
//!   `__rt_heap_init` @ 0x0802ed14 (whose port folds the constant as
//!   `HEAP_GUARD_SIZE`, see malloc_rt.rs) and the init below (which
//!   stores the result into the bounds block).
//! - `stackheap_bounds_fetch` — original: `thunk_FUN_082ab11c`
//!   @ 0x0800af04 (12 bytes): `ldr r3, [pc]; add r3, pc, r3; mov pc, r3`
//!   — a position-independent thunk whose literal (0x2a020c) resolves to
//!   0x082ab11c, a bare `bx lr`. The stock-ADS stack/heap-bounds fetch
//!   (`__user_initial_stackheap` family: r0 = 3-word block
//!   {heap_base, heap_limit, guard}, bounds returned in r0/r1) is LINKED
//!   OUT on this build — the call returns immediately with r0 (the block
//!   pointer) and r1 unchanged. Sole caller: the init below.
//! - `rt_lib_init_post_heap_hook` — original: `FUN_0802ecc4` @ 0x0802ecc4
//!   (4 bytes). `mov pc, lr` — a linked-out weak hook between the heap
//!   init and the rand seeding (twin of the exit-path no-op @ 0x0802ecc0).
//!   Sole caller: the init below.
//! - `rt_lib_init_for_abort` — original: `FUN_08035788` @ 0x08035788
//!   (240 bytes). The ADS library (re)initialization; see its docs.
//!
//! ## The C++ static-constructor hook
//!
//! The original ends with `__cpp_initialise` @ 0x080316cc, which walks a
//! linker-generated region of SELF-RELATIVE offsets bounded by the
//! literals at 0x08031704/0x08031708 — in osos that region is
//! 0x089d4f8c..0x089d51d8 (147 entries), all unported firmware C++
//! initializers. The ported `__cpp_initialise` (atexit.rs) takes a plain
//! function-pointer table instead, so this module dispatches through the
//! [`CPP_STATIC_INIT`] hook (house `HEAP_OPS`/`STREAM_GETC` pattern); the
//! default is a documented no-op. On device a walker over the original
//! self-relative region can be installed.
//!
//! ## Deviations
//!
//! - The five LC category words (libspace+0x20..+0x34) are seeded through
//!   locale.rs's `LC_SLOTS` model, not the u32 words in errno.rs's
//!   `Libspace` (the documented locale.rs deviation: host pointers do not
//!   fit u32). On the 32-bit target the two views are the same words in
//!   spirit.
//! - The original passes its callers r2/r3 through to `__rt_heap_init`,
//!   where both are dead (r2 unused, r3 an overwritten stack-slot seed);
//!   the port passes 0/0 and takes only (heap_base, heap_limit) — abort
//!   @ 0x0803206c calls with (-1, -3) via the loader @ 0x08035894.
//! - The original returns the `stackheap_bounds_fetch` result in r0/r1 —
//!   with the fetch linked out that is (dangling pointer to the on-stack
//!   bounds block, leftover 0). The sole caller discards it; the port
//!   returns nothing.
//! - exit.rs's `abort` still reaches the init through its own documented
//!   no-op `abort_report` stub; pointing it here is an init-time
//!   unification concern (same policy as its exit_stdio_cleanup note).

use crate::errno::__rt_fp_status_addr;

/// _fp_init — original: `FUN_083ecb90` @ 0x083ecb90 (20 bytes).
///
/// Zeroes the ADS soft-float status word at libspace+4 (the word
/// `__rt_fp_status_addr` @ 0x08036d60 returns the address of).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _fp_init() {
    *__rt_fp_status_addr() = 0;
}

/// heap_guard_size — original: `FUN_082ab194` @ 0x082ab194 (8 bytes).
///
/// `mov r0, #1; bx lr` — the heap guard-size veneer is a stub returning 1
/// for any `request` (malloc_rt.rs folds the same constant as
/// `HEAP_GUARD_SIZE` inside its `__rt_heap_init` port).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn heap_guard_size(_request: usize) -> usize {
    1
}

/// stackheap_bounds_fetch — original: `thunk_FUN_082ab11c` @ 0x0800af04
/// (12 bytes), a pc-relative thunk to 0x082ab11c (`bx lr`).
///
/// The stock-ADS stack/heap-bounds fetch is linked out on this build (see
/// module docs): the call is a no-op that leaves the bounds block
/// untouched and returns its argument (r0 passes through the `bx lr`).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stackheap_bounds_fetch(bounds_block: *mut usize) -> *mut usize {
    bounds_block
}

/// rt_lib_init_post_heap_hook — original: `FUN_0802ecc4` @ 0x0802ecc4
/// (4 bytes). `mov pc, lr` — a linked-out weak init hook (see module
/// docs); nothing to do.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rt_lib_init_post_heap_hook() {}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn fp_init_zeroes_the_status_word() {
        unsafe {
            // No pre-poisoning: errno.rs's tests assert this word reads 0
            // and run concurrently (no shared lock exists for libspace).
            _fp_init();
            assert_eq!(*__rt_fp_status_addr(), 0);
        }
    }

    #[test]
    fn heap_guard_size_is_always_one() {
        unsafe {
            for request in [0usize, 1, 0x44, usize::MAX] {
                assert_eq!(heap_guard_size(request), 1);
            }
        }
    }

    #[test]
    fn stackheap_bounds_fetch_is_linked_out() {
        unsafe {
            let mut block = [0x11usize, 0x22, 0x33];
            let ret = stackheap_bounds_fetch(block.as_mut_ptr());
            assert_eq!(ret, block.as_mut_ptr(), "bx lr: r0 passes through");
            assert_eq!(block, [0x11, 0x22, 0x33], "block untouched");
        }
    }

}
