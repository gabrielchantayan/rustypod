//! SQLite `StrAccum` finish and reset support.
//!
//! The recovered [`StrAccum`] layout and its initializer live in the adjacent
//! `vdbe_op` port at 0x08384e84. This module adds only the finish and reset
//! operations.

use crate::libc::rt_memcpy::__rt_memcpy;
use crate::sqlite::mem::db_malloc_op;
use crate::heap::tracked::tracked_free;
pub use super::vdbe_op::StrAccum;
/// sqlite3StrAccumFinish — original: `FUN_08384e14` @ 0x08384e14 (112
/// bytes).
///
/// Source: `ipod-decomp/decomp/c/033/08384e14_FUN_08384e14.c`, checked
/// against the corresponding retailOS disassembly. Terminate the current
/// text at `nChar` when it exists. If allocation is enabled and the text is
/// still the caller-owned base buffer, request `nChar + 1` bytes through
/// `sqlite3_malloc` @ 0x08390b14, install the returned pointer before copying
/// the terminated text, and set `mallocFailed` only if that request returned
/// NULL. The final `zText` value is returned unchanged in every other case.
///
/// # Safety
/// `accum` must point to a writable [`StrAccum`]. When `z_text` is non-NULL,
/// it must name writable storage through `n_char`; when transfer is taken,
/// `z_base` must name at least `n_char + 1` readable bytes and the active
/// SQLite allocator must return storage valid for that many output bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn str_accum_finish(accum: *mut StrAccum) -> *mut u8 {
    let text = (*accum).z_text;
    let byte_count = (*accum).n_char.wrapping_add(1);
    if !text.is_null() {
        text.add((*accum).n_char as u32 as usize).write(0);
        if (*accum).use_malloc != 0 && text == (*accum).z_base {
            let allocated = (db_malloc_op())(byte_count);
            (*accum).z_text = allocated;
            if allocated.is_null() {
                (*accum).malloc_failed = 1;
            } else {
                __rt_memcpy(allocated, (*accum).z_base, byte_count as u32 as usize);
            }
        }
    }
    (*accum).z_text
}


/// str_accum_reset — original: `FUN_08384eb0` @ 0x08384eb0 (40 bytes).
///
/// Source: `ipod-decomp/decomp/c/033/08384eb0_FUN_08384eb0.c`, checked
/// against `ipod-decomp/decomp/osos.asm`. This is SQLite's
/// `sqlite3StrAccumReset`: if `zText` is still the caller-owned `zBase`, it
/// returns without changing the accumulator. Otherwise it releases `zText`
/// through `sqlite3_free` @ 0x083906f4 ([`tracked_free`]) and writes NULL to
/// `zText`; all other accumulator fields remain untouched.
///
/// # Safety
/// `accum` must point to a writable [`StrAccum`]. When `z_text != z_base`,
/// `z_text` must be a live tracked-allocation payload accepted by
/// [`tracked_free`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn str_accum_reset(accum: *mut StrAccum) {
    if (*accum).z_text == (*accum).z_base {
        return;
    }
    tracked_free((*accum).z_text);
    (*accum).z_text = core::ptr::null_mut();
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};

    /// A hand-built tracked block: payload lives at raw+32 and records the
    /// `payload - (raw + BLOCK_HEADER_SIZE)` padding at payload-4.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new() -> Self {
            let mut block = Self([0; 64]);
            // A zero-size cookie keeps the global tracked-byte counter
            // unchanged while the mock heap observes the exact free call.
            block.0[0..4].copy_from_slice(&0i32.to_le_bytes());
            let padding = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&padding.to_le_bytes());
            block
        }

        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        fn payload(&mut self) -> *mut u8 {
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    fn accum(base: *mut u8, text: *mut u8) -> StrAccum {
        StrAccum {
            z_base: base,
            z_text: text,
            n_char: 17,
            n_alloc: 29,
            mx_alloc: 43,
            malloc_failed: 1,
            use_malloc: 0,
            too_big: 1,
        }
    }

    fn finish_accum(base: *mut u8, text: *mut u8, n_char: i32, use_malloc: u8) -> StrAccum {
        StrAccum {
            z_base: base,
            z_text: text,
            n_char,
            n_alloc: 29,
            mx_alloc: 43,
            malloc_failed: 0,
            use_malloc,
            too_big: 1,
        }
    }

    #[test]
    fn finish_terminates_existing_text_without_allocating() {
        let _allocator = install_recorder(core::ptr::null_mut());
        let mut base = [0xAAu8; 8];
        let mut text = [b'o', b'k', 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC];
        let mut state = finish_accum(base.as_mut_ptr(), text.as_mut_ptr(), 2, 1);

        let returned = unsafe { str_accum_finish(&mut state) };

        assert_eq!(returned, text.as_mut_ptr());
        assert_eq!(&text[..3], b"ok\0");
        assert!(realloc_log().is_empty(), "non-base text is never transferred");
        assert_eq!(state.malloc_failed, 0);
        assert_eq!((state.n_alloc, state.mx_alloc, state.too_big), (29, 43, 1));
    }

    #[test]
    fn finish_transfers_base_text_and_copies_terminator() {
        let mut base = [b'o', b'k', 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC];
        let mut allocated = [0xCCu8; 8];
        let _allocator = install_recorder(allocated.as_mut_ptr());
        let mut state = finish_accum(base.as_mut_ptr(), base.as_mut_ptr(), 2, 1);

        let returned = unsafe { str_accum_finish(&mut state) };

        assert_eq!(returned, allocated.as_mut_ptr());
        assert_eq!(state.z_text, allocated.as_mut_ptr(), "allocation replaces zText first");
        assert_eq!(&base[..3], b"ok\0", "base is terminated before the allocation");
        assert_eq!(&allocated[..3], b"ok\0", "copy includes the newly written terminator");
        assert_eq!(realloc_log(), std::vec![(0, 3)], "request is nChar + 1");
        assert_eq!(state.malloc_failed, 0);
    }

    #[test]
    fn finish_records_allocation_failure_after_terminating_base() {
        let _allocator = install_recorder(core::ptr::null_mut());
        let mut base = [b'o', b'k', 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC];
        let mut state = finish_accum(base.as_mut_ptr(), base.as_mut_ptr(), 2, 1);

        let returned = unsafe { str_accum_finish(&mut state) };

        assert!(returned.is_null());
        assert!(state.z_text.is_null(), "the failed allocation remains installed");
        assert_eq!(&base[..3], b"ok\0", "termination precedes the allocation attempt");
        assert_eq!(realloc_log(), std::vec![(0, 3)]);
        assert_eq!(state.malloc_failed, 1, "only the failed transfer sets the sticky flag");
    }

    #[test]
    fn base_text_equality_returns_without_freeing_or_writing() {
        let _heap = mock_heap();
        let mut base = [0u8; 8];
        let mut state = accum(base.as_mut_ptr(), base.as_mut_ptr());
        let before = (
            state.z_text,
            state.n_char,
            state.n_alloc,
            state.mx_alloc,
            state.malloc_failed,
            state.use_malloc,
            state.too_big,
        );

        unsafe { str_accum_reset(&mut state) };

        assert_eq!(free_log().0, 0, "zText == zBase skips sqlite3_free");
        assert_eq!(
            (
                state.z_text,
                state.n_char,
                state.n_alloc,
                state.mx_alloc,
                state.malloc_failed,
                state.use_malloc,
                state.too_big,
            ),
            before,
            "the equality return does not even clear zText"
        );
    }

    #[test]
    fn owned_text_is_freed_then_ztext_is_cleared() {
        let _heap = mock_heap();
        let mut base = [0u8; 8];
        let mut allocation = TrackedBlock::new();
        let payload = allocation.payload();
        let raw = allocation.raw();
        let mut state = accum(base.as_mut_ptr(), payload);

        unsafe { str_accum_reset(&mut state) };

        assert_eq!(free_log(), (1, raw, TAG_TRACKED));
        assert!(state.z_text.is_null(), "the post-free store clears zText");
        assert_eq!(state.z_base, base.as_mut_ptr());
        assert_eq!(
            (
                state.n_char,
                state.n_alloc,
                state.mx_alloc,
                state.malloc_failed,
                state.use_malloc,
                state.too_big,
            ),
            (17, 29, 43, 1, 0, 1),
            "reset writes only zText"
        );
    }
}
