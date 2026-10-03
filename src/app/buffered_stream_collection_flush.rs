//! Flush every buffered stream in a collection — FUN_082780cc @ 0x082780cc.
//!
//! True size: 56 bytes, ending at 0x08278104's separate function prologue.
//! Raw A32 decoding verifies two incoming plain BL calls (0x082788ac,
//! 0x08278964), zero predicated callers, one internal plain BL to
//! 0x08277d1c, and zero internal predicated BL calls.
//! Algorithm: walk the u32 pointer array at +8 until the end at +12,
//! flushing each state and OR-ing all statuses, including after errors.
//! Reload the end after every call, as the original does.
//! Deliberate deviations: reuse the existing pending-flush Rust port;
//! retain target-width pointer words on hosts and use volatile collection
//! reads to preserve callback-visible end changes. No allocation.

use super::buffered_stream_flush_pending::{buffered_stream_flush_pending, BufferedStreamState};

#[repr(C)]
pub struct BufferedStreamCollection {
    pub unresolved_00_to_04: [u32; 2],
    pub begin: u32,
    pub end: u32,
}

/// Flushes all entries and returns the bitwise union of their statuses.
///
/// # Safety
/// `collection` must be readable and its begin/end must delimit a valid aligned
/// array of u32 state addresses. Each state must satisfy pending-flush safety.
/// Callees may change end only to a valid reachable boundary of this array.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffered_stream_collection_flush(collection: *const BufferedStreamCollection) -> u32 {
    let mut cursor = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*collection).begin)) };
    let mut status = 0;
    while cursor != unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*collection).end)) } {
        let state = unsafe { (cursor as usize as *const u32).read() };
        status |= unsafe { buffered_stream_flush_pending(state as usize as *mut BufferedStreamState) };
        cursor = cursor.wrapping_add(4);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::buffered_stream_flush_pending::{BufferedStreamBacking, BUFFERED_STREAM_FLUSH_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static mut COLLECTION: *mut BufferedStreamCollection = core::ptr::null_mut();
    static mut SHRINK: bool = false;

    unsafe extern "C" fn flush(state: *mut BufferedStreamState, _: u32, _: u32, _: *mut u32, context: u32) -> u32 {
        if unsafe { SHRINK } {
            unsafe { (*COLLECTION).end = (*COLLECTION).begin + 4 };
        }
        // Check that each later stream still reaches the real pending-flush port.
        assert_eq!(unsafe { (*state).pending }, 1);
        context
    }

    #[test]
    fn empty_range_never_dereferences_null_begin() {
        let collection = BufferedStreamCollection { unresolved_00_to_04: [0; 2], begin: 0, end: 0 };
        assert_eq!(unsafe { buffered_stream_collection_flush(&collection) }, 0);
    }

    #[test]
    fn combines_errors_flushes_later_entries_and_observes_changed_end() {
        let _guard = super::super::buffered_stream_flush_pending::tests::LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::BUFFERED_STREAM_COLLECTION_FLUSH, 0x1000) else {
            assert!(note_missing_u32_fixture("app/buffered_stream_collection_flush"));
            return;
        };
        unsafe {
            let backing = slab.cast::<BufferedStreamBacking>();
            backing.write(BufferedStreamBacking { unresolved_00_to_1c: [0; 8], length: 16, unresolved_24_to_28: [0; 2], block_size: 4 });
            let states = slab.add(0x100).cast::<BufferedStreamState>();
            let entries = slab.add(0x200).cast::<u32>();
            for (index, context) in [0x8000_0001, 0, 0x22].into_iter().enumerate() {
                states.add(index).write(BufferedStreamState { backing: backing as u32, active: 1, pending: 1, unresolved_06: [0; 2], block_index: index as u32, unresolved_0c: 0, flush_context: context });
                entries.add(index).write(states.add(index) as u32);
            }
            let mut collection = BufferedStreamCollection { unresolved_00_to_04: [0; 2], begin: entries as u32, end: entries.add(3) as u32 };
            let saved = BUFFERED_STREAM_FLUSH_OPS;
            BUFFERED_STREAM_FLUSH_OPS.flush_block = flush;
            SHRINK = false;
            assert_eq!(buffered_stream_collection_flush(&collection), 0x8000_0023);
            for index in 0..3 { assert_eq!((*states.add(index)).pending, 0); }
            assert_eq!(buffered_stream_collection_flush(&collection), 0);
            for index in 0..3 { (*states.add(index)).pending = 1; }
            COLLECTION = &mut collection;
            SHRINK = true;
            assert_eq!(buffered_stream_collection_flush(core::ptr::addr_of!(collection)), 0x8000_0001);
            assert_eq!((*states).pending, 0);
            assert_eq!((*states.add(1)).pending, 1);
            assert_eq!((*states.add(2)).pending, 1);
            BUFFERED_STREAM_FLUSH_OPS = saved;
            COLLECTION = core::ptr::null_mut();
            SHRINK = false;
        }
    }
}
