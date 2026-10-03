//! Buffered-stream destruction — `FUN_08277eb0` @ 0x08277eb0.
//!
//! True extent: 68 bytes, seventeen A32 words through pop {r4,pc} at
//! 0x08277ef0; the next function begins at 0x08277ef4. Raw branch decoding
//! finds two incoming plain BLs and zero predicated BLs. The body has three
//! plain BLs (flush_pending, aligned_buffer_reset, operator_delete), zero
//! predicated BLs. Ghidra's noreturn annotation on delete is incorrect.
//!
//! If the aligned-buffer owner at +0x14 is nonzero, flush pending data,
//! reload the owner, reset and tag-2-delete it if still present, then clear
//! +0x10 and +0x14. Without an owner, leave every field untouched. Return
//! the original state pointer. Deliberate deviations: none beyond the
//! existing callees' documented heap dispatch; pointers remain target u32
//! words on hosts as well as ARM.

use super::buffered_stream_flush_pending::{buffered_stream_flush_pending, BufferedStreamState};
use crate::heap::aligned_buffer::aligned_buffer_reset;
use crate::heap::veneers::operator_delete;

/// Verified six-word buffered-stream state, including its aligned-buffer owner.
#[repr(C)]
pub struct OwnedBufferedStreamState {
    pub stream: BufferedStreamState,
    pub buffer_owner: u32,
}

/// Flushes and releases this state's owned aligned buffer, returning this.
///
/// # Safety
/// `state` must be writable and word-aligned. A nonzero owner must name a
/// writable two-word aligned-buffer object allocated with tag 2, whose
/// allocation word (if nonzero) names a live tag-3 allocation. The embedded
/// stream must satisfy `buffered_stream_flush_pending`'s safety requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffered_stream_destroy(
    state: *mut OwnedBufferedStreamState,
) -> *mut OwnedBufferedStreamState {
    if unsafe { (*state).buffer_owner } != 0 {
        unsafe { buffered_stream_flush_pending(core::ptr::addr_of_mut!((*state).stream)) };
        let owner = unsafe { (*state).buffer_owner };
        if owner != 0 {
            let buffer = owner as usize as *mut u8;
            unsafe { aligned_buffer_reset(buffer); operator_delete(buffer) };
        }
        unsafe { (*state).stream.flush_context = 0; (*state).buffer_owner = 0 };
    }
    state
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::buffered_stream_flush_pending::{
        BufferedStreamBacking, BUFFERED_STREAM_FLUSH_OPS,
    };
    use crate::heap::veneers::{HEAP_OPS, tests::mock_heap};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use std::sync::LazyLock;
    use std::vec::Vec;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BUFFERED_STREAM_DESTROY, 0x1000).map(|p| p as usize)
    });
    static mut FREES: Vec<(usize, usize, [u32; 2])> = Vec::new();
    static mut REMOVE_OWNER: bool = false;

    unsafe extern "C" fn observe_free(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        let words = if tag == 2 {
            unsafe { [ptr.cast::<u32>().read(), ptr.cast::<u32>().add(1).read()] }
        } else { [0; 2] };
        unsafe { (*core::ptr::addr_of_mut!(FREES)).push((ptr as usize, tag, words)) };
    }

    unsafe extern "C" fn flush(
        state: *mut BufferedStreamState, offset: u32, len: u32,
        _written: *mut u32, context: u32,
    ) -> u32 {
        assert_eq!((offset, len, context), (8, 2, 0x88));
        // The real helper may mutate the owner; the destructor must reload it.
        if unsafe { REMOVE_OWNER } {
            unsafe { (*state.cast::<OwnedBufferedStreamState>()).buffer_owner = 0 };
        }
        0x15
    }

    fn state(owner: u32) -> OwnedBufferedStreamState {
        OwnedBufferedStreamState {
            stream: BufferedStreamState {
                backing: 0, active: 1, pending: 1, unresolved_06: [0x12, 0x34],
                block_index: 2, unresolved_0c: 0x99, flush_context: 0x88,
            },
            buffer_owner: owner,
        }
    }

    #[test]
    fn absent_owner_preserves_dirty_state_and_context() {
        let mut value = state(0);
        let ptr = &mut value as *mut _;
        assert_eq!(unsafe { buffered_stream_destroy(ptr) }, ptr);
        assert_eq!(value.stream.pending, 1);
        assert_eq!(value.stream.flush_context, 0x88);
        assert_eq!(value.stream.unresolved_0c, 0x99);
    }

    #[test]
    fn releases_owned_buffer_after_flush_even_on_error_and_is_idempotent() {
        exercise(false);
    }

    #[test]
    fn flush_removing_owner_skips_reset_and_delete_but_clears_context() {
        exercise(true);
    }

    fn exercise(remove_owner: bool) {
        let _flush_guard = super::super::buffered_stream_flush_pending::tests::LOCK.lock();
        let _heap_guard = mock_heap();
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("app/buffered_stream_destroy"));
            return;
        };
        let backing = slab as *mut BufferedStreamBacking;
        let owner = (slab + 0x100) as *mut u32;
        unsafe {
            backing.write(BufferedStreamBacking { unresolved_00_to_1c: [0; 8], length: 10, unresolved_24_to_28: [0; 2], block_size: 4 });
            owner.write(0x1234); owner.add(1).write(0x5678);
        }
        let saved_flush = unsafe { BUFFERED_STREAM_FLUSH_OPS };
        let saved_heap = unsafe { HEAP_OPS };
        unsafe {
            BUFFERED_STREAM_FLUSH_OPS.flush_block = flush;
            HEAP_OPS.free = observe_free;
            (*core::ptr::addr_of_mut!(FREES)).clear();
            REMOVE_OWNER = remove_owner;
        }
        let mut value = state(owner as u32);
        value.stream.backing = backing as u32;
        let ptr = &mut value as *mut _;
        assert_eq!(unsafe { buffered_stream_destroy(ptr) }, ptr);
        assert_eq!((value.stream.pending, value.stream.flush_context, value.buffer_owner), (0, 0, 0));
        assert_eq!((value.stream.active, value.stream.block_index, value.stream.unresolved_0c, value.stream.unresolved_06), (1, 2, 0x99, [0x12, 0x34]));
        let expected = if remove_owner { std::vec![] } else {
            std::vec![(0x5678, 3, [0, 0]), (owner as usize, 2, [0, 0])]
        };
        assert_eq!(unsafe { &*core::ptr::addr_of!(FREES) }, &expected);
        assert_eq!(unsafe { buffered_stream_destroy(ptr) }, ptr);
        assert_eq!(unsafe { &*core::ptr::addr_of!(FREES) }, &expected);
        unsafe { BUFFERED_STREAM_FLUSH_OPS = saved_flush; HEAP_OPS = saved_heap };
    }
}
