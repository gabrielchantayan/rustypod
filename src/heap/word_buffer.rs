//! `word_buffer_reserve` — reserve capacity for a growable u32 buffer.
//!
//! Original: `FUN_082b8174` @ 0x082b8174 (76 bytes exactly,
//! 0x082b8174..0x082b81c0; the next independent body starts immediately at
//! 0x082b81c0). All 27 direct callers are unconditional `bl` instructions;
//! a full decode of every ARM B/BL word in `osos.dec` found no predicated
//! `blne`/`bleq` calls.
//!
//! The three target words are `{data, len, capacity}`. When `capacity` is
//! smaller than the requested word count, the function calls the unported
//! grow/copy helper `FUN_080a7f2c`, which allocates `requested + 1` words,
//! preserves the existing `len` words, and zeroes the remainder. On success
//! it releases the old data through `traced_free`, then publishes the new
//! data word and requested capacity in that order. A failed grow leaves every
//! field untouched and returns NULL. A request no larger than capacity makes
//! no calls and returns the original object.
//!
//! Deliberate deviation: `FUN_080a7f2c` is not in `names.yaml` as ported, so
//! its direct call is an indirect, volatile hook. Firmware builds default it
//! to the stock address; host builds default to an allocation failure. The
//! old-data release is direct because `traced_free` @ 0x08043994 is ported.

use crate::drivers::ata_cmd::traced_free;

/// Target-layout header for the u32 buffer. `data` remains a target pointer
/// word rather than a host pointer so `len` and `capacity` stay at +0x04 and
/// +0x08 respectively on every build.
#[repr(C)]
pub struct WordBuffer {
    pub data: u32,
    pub len: u32,
    pub capacity: u32,
}

/// The unported `FUN_080a7f2c` allocation/copy helper. It returns the new
/// data pointer as a target word pointer, or NULL without modifying `buffer`.
pub type WordBufferGrow = unsafe extern "C" fn(
    buffer: *mut WordBuffer,
    requested_capacity: u32,
) -> *mut u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn stock_word_buffer_grow(
    buffer: *mut WordBuffer,
    requested_capacity: u32,
) -> *mut u32 {
    let grow: WordBufferGrow = unsafe { core::mem::transmute(0x080a_7f2cusize) };
    unsafe { grow(buffer, requested_capacity) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_word_buffer_grow(
    _buffer: *mut WordBuffer,
    _requested_capacity: u32,
) -> *mut u32 {
    core::ptr::null_mut()
}

/// Hook for `FUN_080a7f2c`. It is volatile-read at the call site so LLVM
/// cannot fold the host failure stub into `word_buffer_reserve`.
#[cfg(target_os = "none")]
pub static mut WORD_BUFFER_GROW: WordBufferGrow = stock_word_buffer_grow;
#[cfg(not(target_os = "none"))]
pub static mut WORD_BUFFER_GROW: WordBufferGrow = missing_word_buffer_grow;

#[inline(always)]
unsafe fn word_buffer_grow() -> WordBufferGrow {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(WORD_BUFFER_GROW)) }
}

/// word_buffer_reserve — original: `FUN_082b8174` @ 0x082b8174 (76 bytes;
/// 27 unconditional `bl` call sites, no predicated direct calls).
///
/// Grows `buffer` to at least `requested_capacity` words. `buffer` must point
/// to the three aligned writable target words above; a nonzero `data` word
/// must be owned by the allocation family paired with `traced_free`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn word_buffer_reserve(
    buffer: *mut WordBuffer,
    requested_capacity: u32,
) -> *mut WordBuffer {
    let capacity = unsafe { core::ptr::addr_of!((*buffer).capacity).read_volatile() };
    if capacity < requested_capacity {
        let data = unsafe { word_buffer_grow()(buffer, requested_capacity) };
        if data.is_null() {
            return core::ptr::null_mut();
        }

        let old_data = unsafe { core::ptr::addr_of!((*buffer).data).read_volatile() };
        if old_data != 0 {
            unsafe { traced_free(old_data as usize as *mut u8) };
        }
        unsafe {
            core::ptr::addr_of_mut!((*buffer).data).write_volatile(data as usize as u32);
            core::ptr::addr_of_mut!((*buffer).capacity).write_volatile(requested_capacity);
        }
    }
    buffer
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut GROW_RESULT: *mut u32 = core::ptr::null_mut();
    static mut GROW_ARGS: (*mut WordBuffer, u32) = (core::ptr::null_mut(), 0);
    static mut FREED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn grow(buffer: *mut WordBuffer, requested_capacity: u32) -> *mut u32 {
        unsafe {
            GROW_ARGS = (buffer, requested_capacity);
            GROW_RESULT
        }
    }

    unsafe extern "C" fn record_free(block: *mut u8) {
        unsafe { FREED = block }
    }

    fn install() -> (MutexGuard<'static, ()>, WordBufferGrow, TracedFreeHooks) {
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old_grow = core::ptr::read_volatile(core::ptr::addr_of!(WORD_BUFFER_GROW));
            let old_free = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            WORD_BUFFER_GROW = grow;
            TRACED_FREE_HOOKS = TracedFreeHooks { free: record_free, trace: None };
            GROW_RESULT = core::ptr::null_mut();
            GROW_ARGS = (core::ptr::null_mut(), 0);
            FREED = core::ptr::null_mut();
            (guard, old_grow, old_free)
        }
    }

    unsafe fn restore(guard: MutexGuard<'static, ()>, old_grow: WordBufferGrow, old_free: TracedFreeHooks) {
        unsafe {
            WORD_BUFFER_GROW = old_grow;
            TRACED_FREE_HOOKS = old_free;
        }
        drop(guard);
    }

    #[test]
    fn reserve_skips_growth_at_capacity_and_preserves_every_word() {
        let (guard, old_grow, old_free) = install();
        let mut buffer = WordBuffer { data: 0x1111_0000, len: 3, capacity: 3 };

        let result = unsafe { word_buffer_reserve(&mut buffer, 3) };

        assert_eq!(result, &mut buffer as *mut WordBuffer);
        assert_eq!((buffer.data, buffer.len, buffer.capacity), (0x1111_0000, 3, 3));
        unsafe {
            assert_eq!(GROW_ARGS, (core::ptr::null_mut(), 0));
            assert!(FREED.is_null());
            restore(guard, old_grow, old_free);
        }
    }

    #[test]
    fn reserve_failed_growth_returns_null_without_releasing_or_mutating() {
        let (guard, old_grow, old_free) = install();
        let mut buffer = WordBuffer { data: 0x2222_0000, len: 4, capacity: 4 };

        let result = unsafe { word_buffer_reserve(&mut buffer, 7) };

        assert!(result.is_null());
        assert_eq!(unsafe { GROW_ARGS }, (&mut buffer as *mut WordBuffer, 7));
        assert_eq!((buffer.data, buffer.len, buffer.capacity), (0x2222_0000, 4, 4));
        unsafe {
            assert!(FREED.is_null());
            restore(guard, old_grow, old_free);
        }
    }

    #[test]
    fn reserve_releases_old_data_then_publishes_new_data_and_capacity() {
        let (guard, old_grow, old_free) = install();
        let mut replacement = [0u32; 8];
        let mut buffer = WordBuffer { data: 0x3333_0000, len: 2, capacity: 2 };
        unsafe { GROW_RESULT = replacement.as_mut_ptr() };

        let result = unsafe { word_buffer_reserve(&mut buffer, 8) };

        assert_eq!(result, &mut buffer as *mut WordBuffer);
        assert_eq!(unsafe { GROW_ARGS }, (&mut buffer as *mut WordBuffer, 8));
        assert_eq!(unsafe { FREED }, 0x3333_0000usize as *mut u8);
        assert_eq!(buffer.data, replacement.as_mut_ptr() as usize as u32);
        assert_eq!((buffer.len, buffer.capacity), (2, 8));
        unsafe { restore(guard, old_grow, old_free) };
    }
}
