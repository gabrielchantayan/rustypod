//! Tagged-word buffer pool nesting and slot allocation.
//!
//! The sibling push/pop helpers preserve the slot cursor across nested work;
//! `tagged_word_buffer_pool_take` allocates the embedded slots.
//! The owner object is 0x2c0 bytes:
//! - +0x00 `slot_count` — the live allocation cursor.
//! - +0x04..+0x283 32 embedded [`TaggedWordBuffer`] slots.
//! - +0x284 `flags` — used by the sibling destructor.
//! - +0x288 `nesting_depth` — maintained by the nesting helpers.
//! - +0x28c..+0x2b8 12 saved `slot_count` words.
//! - +0x2bc `overflow_reported` — latch for the one-shot diagnostic.

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

/// tagged_word_buffer_pool_pop — original: `FUN_0803dd84` @ 0x0803dd84
/// (68 bytes; 11 direct `bl` call sites).
///
/// Raw bytes span exactly 0x0803dd84..0x0803ddc8; the separately linked
/// `three_buffer_owner_release` starts at 0x0803ddc8. Decoding every ARM
/// B/BL immediate in `osos.dec` found 11 unconditional `bl` callers and no
/// predicated calls. The body returns immediately for NULL; only its
/// conditional call to `tagged_word_buffer_pool_push` occurs after that
/// guard.
///
/// When depth is zero, save the current slot cursor and enter depth one with
/// `tagged_word_buffer_pool_push`. Clear the one-shot overflow latch,
/// decrement depth, then restore the saved cursor when the decremented depth
/// is signed less than 12. The signed condition deliberately preserves the
/// firmware's unchecked raw-pointer arithmetic for bit-31-set depths.
/// Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_pool_pop(pool: *mut TaggedWordBufferPool) {
    if pool.is_null() {
        return;
    }

    if (*pool).nesting_depth == 0 {
        tagged_word_buffer_pool_push(pool);
    }

    (*pool).overflow_reported = 0;
    let nesting_depth = (*pool).nesting_depth.wrapping_sub(1);
    (*pool).nesting_depth = nesting_depth;

    if (nesting_depth as i32) < 12 {
        let saved_slot_count = core::ptr::addr_of!((*pool).saved_slot_counts)
            .cast::<u32>()
            .wrapping_add(nesting_depth as usize);
        (*pool).slot_count = saved_slot_count.read();
    }
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
    fn pop_ignores_a_null_pool() {
        unsafe { tagged_word_buffer_pool_pop(core::ptr::null_mut()) };
    }

    #[test]
    fn pop_bootstraps_zero_depth_and_restores_its_saved_slot_cursor() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 0x1234_5678;

        unsafe { tagged_word_buffer_pool_pop(&mut pool) };

        assert_eq!(pool.slot_count, 0x1234_5678);
        assert_eq!(pool.nesting_depth, 0);
        assert_eq!(pool.saved_slot_counts[0], 0x1234_5678);
    }

    #[test]
    fn pop_restores_saved_cursor_below_threshold_and_resets_overflow_latch() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 3;
        pool.nesting_depth = 12;
        pool.saved_slot_counts[11] = 0xfeed_face;
        pool.overflow_reported = 1;

        unsafe { tagged_word_buffer_pool_pop(&mut pool) };

        assert_eq!(pool.slot_count, 0xfeed_face);
        assert_eq!(pool.nesting_depth, 11);
        assert_eq!(pool.overflow_reported, 0);

        pool.slot_count = 9;
        pool.nesting_depth = TAGGED_WORD_BUFFER_POOL_DEPTH_LIMIT;
        pool.overflow_reported = 1;
        unsafe { tagged_word_buffer_pool_pop(&mut pool) };

        assert_eq!(pool.slot_count, 9);
        assert_eq!(pool.nesting_depth, 12);
        assert_eq!(pool.overflow_reported, 0);
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
