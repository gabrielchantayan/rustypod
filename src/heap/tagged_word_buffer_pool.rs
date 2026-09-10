//! `tagged_word_buffer_pool_take` — the slot allocator for the 32-entry
//! tagged-word buffer pool.
//!
//! Original: `FUN_0803de0c` @ 0x0803de0c (100 bytes; 22 `bl` call sites).
//! The body is exactly the 0x0803de0c..0x0803de70 range in `osos.dec`: no
//! trailing literal pool, next function at 0x0803de70.
//!
//! The owner object is 0x2c0 bytes:
//! - +0x00 `slot_count` — the slot cursor this function advances.
//! - +0x04..+0x283 32 embedded [`TaggedWordBuffer`] slots.
//! - +0x284 `flags` — used by the sibling destructor.
//! - +0x288 `nesting_depth` — the caller-managed depth gate.
//! - +0x28c..+0x2b8 12 saved `slot_count` words for the sibling push/pop
//!   helpers.
//! - +0x2bc `overflow_reported` — latch for the one-shot diagnostic.
//!
//! Algorithm: choose the slot index from `nesting_depth` when depth >= 13,
//! otherwise from `slot_count`; if the chosen index is below 32, store
//! index + 1 back to `slot_count` and return `&mut slots[index]`. On
//! exhaustion, emit `diag_ring_record(3, 0x74, 0x6d, 0, 0)` once and return
//! NULL. No null guard: the original dereferences `this` immediately.

use crate::heap::tagged_word_buffer::TaggedWordBuffer;
use crate::kernel::diag_ring_record::diag_ring_record;

/// Embedded slot count in the 0x2c0-byte pool object.
pub const TAGGED_WORD_BUFFER_POOL_CAPACITY: usize = 32;
/// Depth threshold at which the current nesting depth becomes the selected
/// slot index instead of the mutable slot cursor.
pub const TAGGED_WORD_BUFFER_POOL_DEPTH_LIMIT: u32 = 13;

/// Target-layout pool object that owns 32 embedded tagged word buffers.
#[repr(C)]
pub struct TaggedWordBufferPool {
    /// +0x00: mutable slot cursor.
    pub slot_count: u32,
    /// +0x04..+0x283: 32 embedded 20-byte tagged word buffers.
    pub slots: [TaggedWordBuffer; TAGGED_WORD_BUFFER_POOL_CAPACITY],
    /// +0x284: control flags used by the sibling destructor.
    pub flags: u32,
    /// +0x288: nesting depth maintained by the sibling push/pop helpers.
    pub nesting_depth: u32,
    /// +0x28c..+0x2b8: saved slot cursors for the first 12 nesting levels.
    pub saved_slot_counts: [u32; 12],
    /// +0x2bc: one-shot overflow diagnostic latch.
    pub overflow_reported: u32,
}
/// tagged_word_buffer_pool_push — original: `FUN_0803dec8` @ 0x0803dec8
/// (36 bytes; 11 direct `bl` call sites).
///
/// Raw bytes span 0x0803dec8..0x0803deec; the independent
/// `three_buffer_owner_release` starts at 0x0803deec. Decoding every ARM
/// B/BL immediate in `osos.dec` found ten unconditional `bl` callers and
/// one `bleq` at 0x0803dd9c. The predicated caller invokes this only when
/// its current nesting depth is zero; this body itself has no NULL guard.
///
/// Saves the current slot cursor at nesting depths 0 through 11, then
/// increments the depth. The signed ARM `lt` condition deliberately also
/// admits values with bit 31 set, preserving the firmware's unchecked raw
/// pointer arithmetic. Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_pool_push(pool: *mut TaggedWordBufferPool) {
    let nesting_depth = (*pool).nesting_depth;

    if (nesting_depth as i32) < 12 {
        let saved_slot_count = core::ptr::addr_of_mut!((*pool).saved_slot_counts)
            .cast::<u32>()
            .wrapping_add(nesting_depth as usize);
        saved_slot_count.write((*pool).slot_count);
    }

    (*pool).nesting_depth = nesting_depth.wrapping_add(1);
}


/// tagged_word_buffer_pool_take — original: `FUN_0803de0c` @ 0x0803de0c
/// (100 bytes; 22 `bl` call sites).
///
/// Returns the next embedded [`TaggedWordBuffer`] slot or NULL on overflow.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_pool_take(
    this: *mut TaggedWordBufferPool,
) -> *mut TaggedWordBuffer {
    let depth = (*this).nesting_depth;
    let slot_index = if depth <= 12 {
        (*this).slot_count
    } else {
        depth
    };

    if slot_index < TAGGED_WORD_BUFFER_POOL_CAPACITY as u32 {
        (*this).slot_count = slot_index + 1;
        core::ptr::addr_of_mut!((*this).slots[slot_index as usize])
    } else {
        if (*this).overflow_reported == 0 {
            diag_ring_record(3, 0x74, 0x6d, 0, 0);
            (*this).overflow_reported = 1;
        }
        core::ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::mem::{size_of, zeroed};

    #[test]
    fn pool_layout_matches_the_recovered_extent() {
        assert_eq!(size_of::<TaggedWordBufferPool>(), 0x2c0);
    }

    #[test]
    fn push_saves_slot_cursor_at_first_nesting_depth() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 0x1234_5678;

        unsafe { tagged_word_buffer_pool_push(&mut pool) };

        assert_eq!(pool.saved_slot_counts[0], 0x1234_5678);
        assert_eq!(pool.nesting_depth, 1);
    }

    #[test]
    fn push_saves_last_slot_then_stops_at_depth_twelve() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 9;
        pool.nesting_depth = 11;

        unsafe { tagged_word_buffer_pool_push(&mut pool) };

        assert_eq!(pool.saved_slot_counts[11], 9);
        assert_eq!(pool.nesting_depth, 12);

        pool.slot_count = 13;
        unsafe { tagged_word_buffer_pool_push(&mut pool) };

        assert_eq!(pool.saved_slot_counts[11], 9);
        assert_eq!(pool.nesting_depth, 13);
    }

    #[test]
    fn take_uses_slot_cursor_when_depth_is_below_thirteen() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 5;
        pool.nesting_depth = 12;

        let slot = unsafe { tagged_word_buffer_pool_take(&mut pool) };

        assert_eq!(slot, core::ptr::addr_of_mut!(pool.slots[5]));
        assert_eq!(pool.slot_count, 6);
        assert_eq!(pool.nesting_depth, 12);
    }

    #[test]
    fn take_uses_nesting_depth_at_the_threshold() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 5;
        pool.nesting_depth = TAGGED_WORD_BUFFER_POOL_DEPTH_LIMIT;

        let slot = unsafe { tagged_word_buffer_pool_take(&mut pool) };

        assert_eq!(slot, core::ptr::addr_of_mut!(pool.slots[13]));
        assert_eq!(pool.slot_count, 14);
        assert_eq!(pool.nesting_depth, TAGGED_WORD_BUFFER_POOL_DEPTH_LIMIT);
    }

    #[test]
    fn take_overflow_returns_null_and_latches_once() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = TAGGED_WORD_BUFFER_POOL_CAPACITY as u32;
        pool.nesting_depth = 0;

        let first = unsafe { tagged_word_buffer_pool_take(&mut pool) };
        assert!(first.is_null());
        assert_eq!(pool.slot_count, TAGGED_WORD_BUFFER_POOL_CAPACITY as u32);
        assert_eq!(pool.overflow_reported, 1);

        let second = unsafe { tagged_word_buffer_pool_take(&mut pool) };
        assert!(second.is_null());
        assert_eq!(pool.overflow_reported, 1);
    }
}
