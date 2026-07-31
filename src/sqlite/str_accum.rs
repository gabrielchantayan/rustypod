//! SQLite `StrAccum` reset support.
//!
//! The recovered [`StrAccum`] layout and its initializer live in the adjacent
//! `vdbe_op` port at 0x08384e84. This module adds only the reset operation.

use crate::heap::tracked::tracked_free;
pub use super::vdbe_op::StrAccum;

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
