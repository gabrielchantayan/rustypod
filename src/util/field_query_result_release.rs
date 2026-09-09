//! `field_query_result_release` — original: `FUN_081bfb50` @ `0x081bfb50`
//! (60 bytes; 16 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM extent is exactly 60 bytes (`0x081bfb50..0x081bfb8c`); the
//! distinct sibling `FUN_081bfb8c` begins immediately afterward
//! (`push {r0-r8, lr}`), confirming Ghidra's 60-byte size. The body:
//!
//! ```text
//! push {r4, r5, r6, lr}
//! add  r5, r0, #0x200
//! mov  r4, r0
//! ldrh r0, [r5, #8]        @ flags at result+0x208
//! tst  r0, #1
//! beq  done
//! ldr  r0, [r4, #0x210]    @ heap-owned text pointer
//! bl   0x08049398          @ retailOS heap free
//! ldrh r0, [r5, #8]
//! bic  r0, r0, #1
//! strh r0, [r5, #8]        @ clear the heap-text flag
//! mov  r0, #0
//! str  r0, [r4, #0x210]    @ null the text pointer
//! done:
//! mov  r0, r4              @ return the block
//! pop  {r4, r5, r6, pc}
//! ```
//!
//! This is the scope-exit cleanup for the 0x238-byte record field-query
//! result block (the same layout `object_install_field_text` @
//! `0x08056048` builds on its stack: flags halfword at `+0x208`, text
//! length at `+0x20a`, text pointer at `+0x210`). If bit 0 of the flags
//! halfword is set the block's text pointer is a heap allocation: it is
//! released through the retailOS heap free `0x08049398`, the flag bit is
//! cleared and the pointer nulled. The block pointer itself is returned
//! in r0. All 16 verified callers (`0x081be7f0..0x081bf7bc`, every one a
//! plain `bl`, none predicated) run it on a stack-local block right after
//! a query through `0x08051a48` and immediately overwrite r0, so the
//! return value is a destructor-style `this` passthrough the stock code
//! never consumes. The call count was verified by decoding every BL word
//! in `osos.dec`, not from Ghidra's listing.
//!
//! The heap free stays in retailOS behind the [`HEAP_FREE`] boundary;
//! host tests substitute a recording stub.

use core::ptr;

/// Block `+0x208` flags bit 0: the text pointer at `+0x210` is a heap
/// allocation owned by the block (matches `FIELD_RESULT_HEAP_TEXT` in
/// `ui/object_state.rs`).
const HEAP_TEXT_FLAG: u16 = 0x1;

/// Layout of the 0x238-byte field-query result block, as far as this
/// cleanup touches it. Matches the `FieldQueryResult` view in
/// `ui/object_state.rs`; the head fields are written by the unported
/// query helper and are opaque here.
#[repr(C)]
pub struct FieldQueryResult {
    _head: [u8; 0x208],
    /// Block `+0x208`: result flags; bit 0 = heap-owned text pointer.
    flags: u16,
    /// Block `+0x20a`: text length in bytes (not consulted here).
    _text_len: u16,
    _reserved: [u8; 4],
    /// Block `+0x210`: the text bytes — the helper's inline buffer at
    /// `+0x214`, or a heap allocation when [`HEAP_TEXT_FLAG`] is set.
    text: *mut u8,
}

type HeapFree = unsafe extern "C" fn(*mut u8);

/// Calls the stock heap free, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x08049398. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original is the retailOS allocator's free:
/// it returns immediately on a null pointer, validates the eight-byte
/// allocation header, decrements the pool accounting, and returns the
/// block to its pool.
unsafe extern "C" fn firmware_heap_free(pointer: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let heap_free: HeapFree = core::mem::transmute(0x0804_9398usize);
        heap_free(pointer)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = pointer;
    }
}

/// Narrow boundary for the unported 0x08049398 dependency.
static mut HEAP_FREE: HeapFree = firmware_heap_free;

#[inline(always)]
unsafe fn heap_free_fn() -> HeapFree {
    core::ptr::read_volatile(core::ptr::addr_of!(HEAP_FREE))
}

/// field_query_result_release — original: `FUN_081bfb50` @ `0x081bfb50`
/// (60 bytes; 16 verified direct `bl` call sites, all unconditional).
///
/// If bit 0 of the block's flags halfword (`+0x208`) is set, frees the
/// text pointer (`+0x210`) through the retailOS heap free, clears the
/// flag bit — preserving every other flag — and nulls the pointer.
/// Returns `result` unconditionally, matching the original's
/// destructor-style `mov r0, r4` passthrough.
///
/// # Safety
///
/// Like the original, there is no null guard on `result`: it must point
/// at a writable field-query result block of at least 0x214 bytes, as at
/// every stock call site. When [`HEAP_TEXT_FLAG`] is set the text pointer
/// must be a live allocation of the retailOS heap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn field_query_result_release(
    result: *mut FieldQueryResult,
) -> *mut FieldQueryResult {
    if unsafe { (*result).flags } & HEAP_TEXT_FLAG != 0 {
        unsafe { heap_free_fn()((*result).text) };
        unsafe { (*result).flags &= !HEAP_TEXT_FLAG };
        unsafe { (*result).text = ptr::null_mut() };
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{firmware_heap_free, field_query_result_release, FieldQueryResult, HEAP_FREE};
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    static RELEASE_LOCK: Mutex<()> = Mutex::new(());
    static mut FREE_CALLS: usize = 0;
    static mut FREED_POINTER: usize = 0;

    unsafe extern "C" fn record_heap_free(pointer: *mut u8) {
        unsafe {
            FREE_CALLS += 1;
            FREED_POINTER = pointer as usize;
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = RELEASE_LOCK.lock();
        unsafe {
            FREE_CALLS = 0;
            FREED_POINTER = 0;
            core::ptr::addr_of_mut!(HEAP_FREE).write(record_heap_free);
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(HEAP_FREE).write(firmware_heap_free) };
        }
    }

    fn fresh_block() -> FieldQueryResult {
        FieldQueryResult {
            _head: [0; 0x208],
            flags: 0,
            _text_len: 0,
            _reserved: [0; 4],
            text: ptr::null_mut(),
        }
    }

    #[test]
    fn clear_flag_skips_free_and_leaves_block_untouched() {
        let _bench = bench();
        let mut block = fresh_block();
        let mut text = [0xabu8; 8];
        block.flags = 0x4000;
        block.text = text.as_mut_ptr();
        let block_address = &mut block as *mut FieldQueryResult;

        let returned = unsafe { field_query_result_release(block_address) };

        assert_eq!(returned, block_address);
        assert_eq!(unsafe { FREE_CALLS }, 0);
        assert_eq!(block.flags, 0x4000);
        assert_eq!(block.text, text.as_mut_ptr());
    }

    #[test]
    fn set_flag_frees_text_clears_bit_and_nulls_pointer() {
        let _bench = bench();
        let mut block = fresh_block();
        let mut text = [0xabu8; 8];
        block.flags = 1;
        block.text = text.as_mut_ptr();
        let block_address = &mut block as *mut FieldQueryResult;

        let returned = unsafe { field_query_result_release(block_address) };

        assert_eq!(returned, block_address);
        assert_eq!(unsafe { FREE_CALLS }, 1);
        assert_eq!(unsafe { FREED_POINTER }, text.as_mut_ptr() as usize);
        assert_eq!(block.flags, 0);
        assert!(block.text.is_null());
    }

    #[test]
    fn free_preserves_every_other_flag_bit() {
        let _bench = bench();
        let mut block = fresh_block();
        let mut text = [0xabu8; 8];
        block.flags = 0xfffe | 1;
        block.text = text.as_mut_ptr();

        let returned = unsafe { field_query_result_release(&mut block) };

        assert_eq!(returned, &mut block as *mut FieldQueryResult);
        assert_eq!(unsafe { FREE_CALLS }, 1);
        assert_eq!(block.flags, 0xfffe);
        assert!(block.text.is_null());
    }
}
