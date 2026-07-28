//! FreeType `ftutil.c` — the memory layer every other FreeType module
//! allocates through. Three functions live here; between them they carry
//! 326 `bl` + 12 tail `b` call sites (binary-scanned), which makes this
//! the second-busiest FreeType translation unit in the image after the
//! trace sink.
//!
//! The translation unit is pinned three ways. Its `FT_ASSERT` calls pass
//! the `__FILE__` pointer 0x08901290, whose text is
//! `...\freetype\src\base\ftutil.c`; its neighbour at 0x082cfa90 is
//! upstream's `ft_highpow2` verbatim (clear the lowest set bit until the
//! value goes to zero, return the previous one); and the
//! `ft_mem_qrealloc` at 0x082cfb34 calls both [`ft_mem_alloc`] and
//! [`ft_mem_free`] exactly where upstream's source does — the `block =
//! ft_mem_alloc( memory, new_count*item_size, &error )` of its
//! `cur_count == 0` arm and the `ft_mem_free( memory, block )` of its
//! `new_count == 0` arm.
//!
//! The layout of `FT_MemoryRec` falls straight out of the code:
//! `ft_mem_qalloc` calls through `[memory, #4]`, `ft_mem_free` through
//! `[memory, #8]` and `ft_mem_qrealloc` through `[memory, #12]`, i.e.
//! upstream's `user`, `alloc`, `free`, `realloc` in that order.
//!
//! # Addresses in this file
//!
//! Load addresses are the ones Ghidra and `functions.csv` use, i.e. file
//! offsets into `osos.dec` at base 0x08000000. Absolute pointers baked
//! into the literal pools are *runtime* addresses, which sit 0xaed8 below
//! their file position — 0x08901290 above is the runtime address of the
//! `ftutil.c` path string stored at 0x0890c168. Relative branches are
//! unaffected, so every `bl` target quoted here is a file address like
//! the rest of the project's.

use crate::ft::error::{FT_ERR_INVALID_ARGUMENT, FT_ERR_OK, FT_ERR_OUT_OF_MEMORY};

/// `FT_Alloc_Func` — `memory->alloc`, called through `[memory, #4]`.
/// Returns null when it cannot satisfy the request.
pub type FtAllocFunc = unsafe extern "C" fn(memory: *mut FtMemory, size: i32) -> *mut u8;

/// `FT_Free_Func` — `memory->free`, called through `[memory, #8]`.
pub type FtFreeFunc = unsafe extern "C" fn(memory: *mut FtMemory, block: *mut u8);

/// `FT_Realloc_Func` — `memory->realloc`, called through `[memory, #12]`
/// by the (unported) `ft_mem_qrealloc` @ 0x082cfb34.
pub type FtReallocFunc = unsafe extern "C" fn(
    memory: *mut FtMemory,
    cur_size: i32,
    new_size: i32,
    block: *mut u8,
) -> *mut u8;

/// `FT_MemoryRec` — the allocator FreeType is handed at library-init
/// time. 16 bytes on ARM: `user` @ +0, `alloc` @ +4, `free` @ +8,
/// `realloc` @ +12.
///
/// The three callbacks are non-optional exactly as upstream declares
/// them: the original loads and branches to them without a null test
/// (`ldr r2, [r0, #8]` / `bxne r2`), so a null callback is already
/// undefined behavior in the C.
#[repr(C)]
pub struct FtMemory {
    pub user: *mut core::ffi::c_void,
    pub alloc: FtAllocFunc,
    pub free: FtFreeFunc,
    pub realloc: FtReallocFunc,
}

/// ft_mem_qalloc (FreeType `ft_mem_qalloc`, ftutil.c) — original:
/// `FUN_082cfaf8` @ 0x082cfaf8 (60 bytes; 3 `bl` call sites, one of them
/// [`ft_stream_enter_frame`](crate::ft::stream::ft_stream_enter_frame)).
///
/// The "quick" allocation: hand `size` to `memory->alloc` and report the
/// outcome through `*p_error`, without zeroing anything. A `size` of 0
/// is not an error — it yields a null block and `FT_Err_Ok`, which is
/// how `FT_QALLOC( p, 0 )` legally produces a null pointer. A *negative*
/// size is rejected outright with `FT_Err_Invalid_Argument`; the
/// allocator is never asked.
///
/// # Safety
/// `memory` must be a valid `FtMemory` whose `alloc` callback is
/// callable; `p_error` must be a valid `i32` pointer.
// A real `bl` target in the original (three call sites, one of them
// `ft_mem_alloc`); keep it out of line so the hooked symbol exists.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_mem_qalloc(
    memory: *mut FtMemory,
    size: i32,
    p_error: *mut i32,
) -> *mut u8 {
    let mut error = FT_ERR_OK;
    let mut block = core::ptr::null_mut();

    if size > 0 {
        block = ((*memory).alloc)(memory, size);
        if block.is_null() {
            error = FT_ERR_OUT_OF_MEMORY;
        }
    } else if size < 0 {
        error = FT_ERR_INVALID_ARGUMENT;
    }

    *p_error = error;
    block
}

/// ft_mem_alloc (FreeType `ft_mem_alloc`, ftutil.c) — original:
/// `FUN_082cfaa4` @ 0x082cfaa4 (68 bytes; 68 `bl` call sites).
///
/// [`ft_mem_qalloc`] plus the zero fill: on success, and only when
/// `size > 0`, the block is cleared with `memzero` (the original's
/// `FT_MEM_ZERO` lowers to ARM ADS' two-argument `__rt_memclr`, reached
/// through the iRAM veneer at 0x08037dc8 -> 0x220002d4, which is
/// [`memzero`](crate::libc::memzero::memzero) copied into fast memory).
///
/// # Safety
/// As [`ft_mem_qalloc`]. The allocator must return a block of at least
/// `size` writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_mem_alloc(
    memory: *mut FtMemory,
    size: i32,
    p_error: *mut i32,
) -> *mut u8 {
    let mut error = FT_ERR_OK;
    let block = ft_mem_qalloc(memory, size, &mut error);

    if error == FT_ERR_OK && size > 0 {
        crate::libc::memzero::memzero(block, size as usize);
    }

    *p_error = error;
    block
}

/// ft_mem_free (FreeType `ft_mem_free`, ftutil.c) — original:
/// `FUN_082cfae8` @ 0x082cfae8 (16 bytes; 255 `bl` + 12 tail `b` call
/// sites, the busiest routine in the FreeType build after the trace
/// sink).
///
/// `if ( P ) memory->free( memory, P )` — four instructions, a
/// conditional tail branch through `[memory, #8]` with `memory` and `P`
/// already in place. Freeing a null pointer is a no-op and does *not*
/// touch `memory`, which is why callers may pass a garbage `memory` with
/// a null block.
///
/// Note this is only half of upstream's `FT_FREE( p )` macro: the macro
/// also nulls the caller's pointer afterwards, which is why the ported
/// callers in `ft/stream.rs` write the null themselves.
///
/// # Safety
/// When `block` is non-null, `memory` must be a valid `FtMemory` whose
/// `free` callback is callable and `block` must have come from the same
/// allocator.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_mem_free(memory: *mut FtMemory, block: *mut u8) {
    if !block.is_null() {
        ((*memory).free)(memory, block);
    }
}

#[cfg(test)]
extern crate std;

/// A bump-allocating `FT_MemoryRec` for the tests, plus the reference
/// implementations of the three routines transcribed from upstream
/// `ftutil.c`. Shared with `ft/stream.rs`'s tests.
#[cfg(test)]
pub(crate) mod test_memory {
    use super::*;
    use std::{vec, vec::Vec};

    /// Serializes the tests that share the arena below (see PORTING.md's
    /// test-harness rule: one guard per `#[test]`, never shadowed).
    pub(crate) static TEST_MEMORY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) const ARENA: usize = 4096;

    static mut ARENA_BYTES: [u8; ARENA] = [0; ARENA];
    static mut ARENA_USED: usize = 0;
    /// When set, `alloc` refuses every request (drives the
    /// `FT_Err_Out_Of_Memory` path).
    static mut ALLOC_FAILS: bool = false;
    static mut ALLOC_CALLS: usize = 0;
    static mut FREE_CALLS: usize = 0;
    static mut FREED: [*mut u8; 16] = [core::ptr::null_mut(); 16];

    unsafe extern "C" fn arena_alloc(_memory: *mut FtMemory, size: i32) -> *mut u8 {
        *core::ptr::addr_of_mut!(ALLOC_CALLS) += 1;
        if *core::ptr::addr_of!(ALLOC_FAILS) {
            return core::ptr::null_mut();
        }
        let used = *core::ptr::addr_of!(ARENA_USED);
        let want = (size as usize + 7) & !7;
        if used + want > ARENA {
            return core::ptr::null_mut();
        }
        *core::ptr::addr_of_mut!(ARENA_USED) = used + want;
        let base = core::ptr::addr_of_mut!(ARENA_BYTES).cast::<u8>();
        // Poison, so a missing FT_MEM_ZERO is visible.
        for i in 0..want {
            *base.add(used + i) = 0xa5;
        }
        base.add(used)
    }

    unsafe extern "C" fn arena_free(_memory: *mut FtMemory, block: *mut u8) {
        let n = *core::ptr::addr_of!(FREE_CALLS);
        if n < 16 {
            (*core::ptr::addr_of_mut!(FREED))[n] = block;
        }
        *core::ptr::addr_of_mut!(FREE_CALLS) = n + 1;
    }

    unsafe extern "C" fn arena_realloc(
        _memory: *mut FtMemory,
        _cur: i32,
        _new: i32,
        block: *mut u8,
    ) -> *mut u8 {
        block
    }

    /// A fresh allocator over a reset arena. Call under
    /// [`TEST_MEMORY_LOCK`].
    pub(crate) unsafe fn reset(alloc_fails: bool) -> FtMemory {
        *core::ptr::addr_of_mut!(ARENA_USED) = 0;
        *core::ptr::addr_of_mut!(ALLOC_FAILS) = alloc_fails;
        *core::ptr::addr_of_mut!(ALLOC_CALLS) = 0;
        *core::ptr::addr_of_mut!(FREE_CALLS) = 0;
        FtMemory {
            user: core::ptr::null_mut(),
            alloc: arena_alloc,
            free: arena_free,
            realloc: arena_realloc,
        }
    }

    pub(crate) unsafe fn alloc_calls() -> usize {
        *core::ptr::addr_of!(ALLOC_CALLS)
    }

    pub(crate) unsafe fn freed() -> Vec<*mut u8> {
        let n = (*core::ptr::addr_of!(FREE_CALLS)).min(16);
        (0..n).map(|i| (*core::ptr::addr_of!(FREED))[i]).collect()
    }

    pub(crate) unsafe fn free_calls() -> usize {
        *core::ptr::addr_of!(FREE_CALLS)
    }

    /// Upstream `ft_mem_qalloc`, transcribed.
    pub(crate) unsafe fn qalloc_ref(
        memory: *mut FtMemory,
        size: i32,
    ) -> (*mut u8, i32) {
        let mut error = 0;
        let mut block: *mut u8 = core::ptr::null_mut();
        if size > 0 {
            block = ((*memory).alloc)(memory, size);
            if block.is_null() {
                error = 0x40;
            }
        } else if size < 0 {
            error = 0x06;
        }
        (block, error)
    }

    /// Upstream `ft_mem_alloc`, transcribed: qalloc then `FT_MEM_ZERO`.
    pub(crate) unsafe fn alloc_ref(memory: *mut FtMemory, size: i32) -> (*mut u8, i32, Vec<u8>) {
        let (block, error) = qalloc_ref(memory, size);
        let mut bytes = vec![];
        if error == 0 && size > 0 {
            for i in 0..size as usize {
                *block.add(i) = 0;
            }
            bytes = core::slice::from_raw_parts(block, size as usize).to_vec();
        }
        (block, error, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::test_memory::*;
    use super::*;
    use std::vec;

    #[test]
    fn qalloc_returns_the_allocators_block_and_no_error() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = reset(false);
            let mut error = 0x1234;
            let block = ft_mem_qalloc(&mut memory, 32, &mut error);
            assert!(!block.is_null());
            assert_eq!(error, FT_ERR_OK);
            assert_eq!(alloc_calls(), 1);
            // "Quick" means unzeroed: the arena's poison survives.
            assert_eq!(*block, 0xa5);
        }
    }

    #[test]
    fn qalloc_matches_the_reference_across_the_size_domain() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            for &size in &[i32::MIN, -257, -1, 0, 1, 2, 7, 8, 63, 64, 255, 1024] {
                let mut memory = reset(false);
                let mut error = 0x1234;
                let block = ft_mem_qalloc(&mut memory, size, &mut error);
                let calls = alloc_calls();

                let mut reference = reset(false);
                let (want_block, want_error) = qalloc_ref(&mut reference, size);
                assert_eq!(error, want_error, "size {size}");
                assert_eq!(block.is_null(), want_block.is_null(), "size {size}");
                assert_eq!(calls, alloc_calls(), "size {size}");
            }
        }
    }

    #[test]
    fn qalloc_of_zero_is_a_null_block_with_no_error_and_no_call() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = reset(false);
            let mut error = 0x1234;
            assert!(ft_mem_qalloc(&mut memory, 0, &mut error).is_null());
            assert_eq!(error, FT_ERR_OK);
            assert_eq!(alloc_calls(), 0);
        }
    }

    #[test]
    fn qalloc_of_a_negative_size_never_reaches_the_allocator() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = reset(false);
            let mut error = 0;
            assert!(ft_mem_qalloc(&mut memory, -1, &mut error).is_null());
            assert_eq!(error, FT_ERR_INVALID_ARGUMENT);
            assert_eq!(alloc_calls(), 0);
        }
    }

    #[test]
    fn qalloc_reports_out_of_memory_when_the_allocator_refuses() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = reset(true);
            let mut error = 0;
            assert!(ft_mem_qalloc(&mut memory, 16, &mut error).is_null());
            assert_eq!(error, FT_ERR_OUT_OF_MEMORY);
            assert_eq!(alloc_calls(), 1);
        }
    }

    #[test]
    fn alloc_zero_fills_the_block_it_returns() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            for size in [1i32, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 100] {
                let mut memory = reset(false);
                let mut error = 0x1234;
                let block = ft_mem_alloc(&mut memory, size, &mut error);
                assert_eq!(error, FT_ERR_OK, "size {size}");
                let got = core::slice::from_raw_parts(block, size as usize).to_vec();

                let mut reference = reset(false);
                let (_, want_error, want) = alloc_ref(&mut reference, size);
                assert_eq!((error, got), (want_error, want), "size {size}");
            }
        }
    }

    #[test]
    fn alloc_does_not_zero_when_the_allocation_failed() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = reset(true);
            let mut error = 0;
            let block = ft_mem_alloc(&mut memory, 16, &mut error);
            assert!(block.is_null());
            assert_eq!(error, FT_ERR_OUT_OF_MEMORY);
        }
    }

    #[test]
    fn alloc_of_zero_or_negative_matches_qalloc_exactly() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            for &size in &[i32::MIN, -8, -1, 0] {
                let mut memory = reset(false);
                let mut error = 0x1234;
                let block = ft_mem_alloc(&mut memory, size, &mut error);
                let mut reference = reset(false);
                let (want_block, want_error) = qalloc_ref(&mut reference, size);
                assert_eq!(block.is_null(), want_block.is_null(), "size {size}");
                assert_eq!(error, want_error, "size {size}");
                assert_eq!(alloc_calls(), 0, "size {size}");
            }
        }
    }

    #[test]
    fn free_forwards_a_non_null_block_to_the_allocator() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = reset(false);
            let mut error = 0;
            let block = ft_mem_qalloc(&mut memory, 24, &mut error);
            ft_mem_free(&mut memory, block);
            assert_eq!(freed(), vec![block]);
        }
    }

    #[test]
    fn free_of_null_never_touches_the_allocator() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            let mut memory = reset(false);
            // The original tests `P` before it ever loads `memory->free`,
            // so a wild `memory` is harmless with a null block.
            ft_mem_free(core::ptr::null_mut(), core::ptr::null_mut());
            ft_mem_free(&mut memory, core::ptr::null_mut());
            assert_eq!(free_calls(), 0);
        }
    }

    #[test]
    fn alloc_then_free_round_trips_over_a_randomized_sweep() {
        let _guard = TEST_MEMORY_LOCK.lock().unwrap();
        unsafe {
            // Deterministic xorshift sweep over the size domain.
            let mut state = 0x1234_5678u32;
            let mut memory = reset(false);
            let mut live = vec![];
            for _ in 0..200 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let size = (state % 96) as i32 - 8;
                let mut error = 0x1234;
                let block = ft_mem_alloc(&mut memory, size, &mut error);

                let mut reference = reset(false);
                let (_, want_error) = qalloc_ref(&mut reference, size);
                memory = reset(false);
                // The arena resets under us, so only the classification is
                // compared; the zero fill is covered above.
                assert_eq!(error, want_error, "size {size}");
                assert_eq!(block.is_null(), size <= 0, "size {size}");
                if !block.is_null() {
                    live.push(block);
                }
            }
            for block in live {
                ft_mem_free(&mut memory, block);
            }
        }
    }
}
