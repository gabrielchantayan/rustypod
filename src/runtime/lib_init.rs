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

use crate::errno::{libspace, __rt_fp_status_addr};
use crate::locale::{get_lc_ctype, get_lc_monetary, get_lc_numeric, lc_slot_write};
use crate::malloc_rt::__rt_heap_init;
use crate::random::srandom1_thunk;
use crate::stdio_init::stdio_init;

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

/// C++ static-constructor runner slot for the init's final
/// `__cpp_initialise` call (original 0x080316cc walking the self-relative
/// offset region 0x089d4f8c..0x089d51d8 — see module docs).
pub type CppStaticInitFn = unsafe extern "C" fn();

/// Default [`CPP_STATIC_INIT`]: no constructors registered, nothing to
/// run (the original's 147-entry table is unported firmware code).
unsafe extern "C" fn cpp_static_init_stub() {}

/// The active C++ static-constructor runner (see module docs).
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut CPP_STATIC_INIT: CppStaticInitFn = cpp_static_init_stub;

/// Volatile hook read (keeps the swap-at-runtime dispatch alive; house
/// pattern, see e.g. semihost.rs).
#[inline(always)]
fn cpp_static_init() -> CppStaticInitFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CPP_STATIC_INIT)) }
}

/// rt_lib_init_for_abort — original: `FUN_08035788` @ 0x08035788
/// (240 bytes); the ADS `__rt_lib_init`. Sole caller (binary-verified bl
/// scan): abort @ 0x0803206c, so the termination report runs on a sane
/// runtime.
///
/// Sequence (disasm-verified, in order):
/// 1. `_fp_init` — zero the fp status word.
/// 2. Build the 3-word bounds block {heap_base, heap_limit,
///    heap_guard_size(0)} on the stack and offer it to
///    `stackheap_bounds_fetch` (linked out — the block comes back
///    untouched).
/// 3. `__rt_heap_init(block[0], block[1], ..)` — install the heap
///    descriptor at libspace+8.
/// 4. `rt_lib_init_post_heap_hook` (linked-out no-op), then
///    `srandom1_thunk` — seed the rand state with 1.
/// 5. Seed the five LC category slots: LC_COLLATE (slot 0) and LC_TIME
///    (slot 4) get ZERO — their getter calls are linked out to
///    `mov r0, r0` nops with r0 = 0, NOT the locale directory pointer
///    setlocale would install; LC_CTYPE (slot 1) = `get_lc_ctype(0,0)+1`
///    (biased like setlocale), LC_MONETARY (slot 2) =
///    `get_lc_monetary(0,0)`, LC_NUMERIC (slot 3) = `get_lc_numeric(0,0)`.
/// 6. `stdio_init` — reset and reopen the three static ":tt" streams
///    (more linked-out hooks surround the call: five nops before, two
///    after).
/// 7. The C++ static-constructor walk ([`CPP_STATIC_INIT`] hook).
///
/// r2/r3 pass-through and the r0/r1 return are dropped — see the module
/// deviations.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rt_lib_init_for_abort(heap_base: usize, heap_limit: usize) {
    _fp_init();
    let mut bounds_block = [heap_base, heap_limit, heap_guard_size(0)];
    stackheap_bounds_fetch(bounds_block.as_mut_ptr());
    __rt_heap_init(bounds_block[0], bounds_block[1], 0, 0);
    rt_lib_init_post_heap_hook();
    srandom1_thunk();
    let null = core::ptr::null();
    lc_slot_write(0, 0); // LC_COLLATE getter linked out: seeded zero
    lc_slot_write(1, get_lc_ctype(null, null) as usize + 1);
    lc_slot_write(2, get_lc_monetary(null, null) as usize);
    lc_slot_write(3, get_lc_numeric(null, null) as usize);
    lc_slot_write(4, 0); // LC_TIME getter linked out: seeded zero
    stdio_init();
    cpp_static_init()();
}

/// Read-back of the installed heap descriptor for tests (libspace+8).
#[cfg(test)]
unsafe fn heap_desc() -> u32 {
    (*libspace()).heap_desc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::locale::lc_slot_read;
    use crate::random::random;
    use crate::semihost::tests as swi;
    use crate::semihost::SYS_OPEN;
    use crate::stream_file::{stderr_file, stdin_file, stdout_file};

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

    /// The full init against mocks: fp status cleared, heap descriptor
    /// installed, rand seeded with 1, LC slots 1..3 seeded (0 and 4
    /// zero), the three ":tt" streams opened. Takes every shared-state
    /// test lock the walk touches (fixed order, no other test holds more
    /// than one of these at a time).
    #[test]
    fn rt_lib_init_seeds_the_whole_runtime() {
        let _swi_guard = swi::mock_swi(&[3, 4, 5]);
        let _locale_guard = crate::locale::tests::locale_state();
        let _random_guard = crate::random::tests::lock_state();
        let _heap_guard = crate::malloc_rt::tests::lock_ops();
        unsafe {
            *stdin_file() = crate::stream_file::ADS_FILE_ZERO;
            *stdout_file() = crate::stream_file::ADS_FILE_ZERO;
            *stderr_file() = crate::stream_file::ADS_FILE_ZERO;
            for i in 0..5 {
                lc_slot_write(i, 0xdead_0000 + i);
            }

            rt_lib_init_for_abort(0x1000, 0x2000);

            assert_eq!(*__rt_fp_status_addr(), 0, "fp status cleared");
            assert_eq!(heap_desc(), 0x1000, "heap descriptor = heap_base");
            // rand state seeded with 1: the next draw equals the first
            // draw after an explicit srandom(1).
            let first = random();
            crate::random::srandom(1);
            assert_eq!(random(), first, "rand seeded via srandom1_thunk");
            // LC slots: 0 and 4 zero (linked-out getters), 1..3 seeded.
            let null = core::ptr::null();
            assert_eq!(lc_slot_read(0), 0);
            assert_eq!(lc_slot_read(1), get_lc_ctype(null, null) as usize + 1);
            assert_eq!(lc_slot_read(2), get_lc_monetary(null, null) as usize);
            assert_eq!(lc_slot_read(3), get_lc_numeric(null, null) as usize);
            assert_eq!(lc_slot_read(4), 0);
            // stdio: three ":tt" opens (modes r/w/w), handles installed.
            let opens: std::vec::Vec<_> = (*core::ptr::addr_of!(swi::SWI_LOG))
                .iter()
                .filter(|(op, _)| *op == SYS_OPEN)
                .collect();
            assert_eq!(opens.len(), 3);
            assert_eq!((*stdin_file()).stream.handle, 3);
            assert_eq!((*stdout_file()).stream.handle, 4);
            assert_eq!((*stderr_file()).stream.handle, 5);
            assert_eq!((*stdin_file()).link, stdout_file());
            assert_eq!((*stdout_file()).link, stderr_file());
            swi::restore_swi();
        }
    }
}
