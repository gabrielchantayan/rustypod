//! Clears the pending word for a selected 32-byte state slot.
//!
//! `clear_indexed_slot_pending_state` — original: `FUN_08193f24` @
//! `0x08193f24` (20 bytes; six direct callers, all unconditional `bl`,
//! binary-scanned from `osos.dec`: 0x0818ea34, 0x0818f40c, 0x0818fcd0,
//! 0x081908a4, 0x08192858, and 0x08193dac).
//!
//! # Algorithm
//!
//! If `slot < 3` under a signed comparison, clear word `+0x18` of the
//! 32-byte slot at `state + slot * 0x20`. There is deliberately no lower
//! bound check: negative slots satisfy the original `movlt`/`addlt`/`strlt`
//! sequence and address preceding slots.

/// The recovered 32-byte state slot. Only `pending_state` is touched here.
#[repr(C)]
pub struct IndexedSlotPendingState {
    opaque_00_14: [u32; 6],
    pub pending_state: u32,
    opaque_1c: u32,
}

const _: () = assert!(core::mem::size_of::<IndexedSlotPendingState>() == 0x20);
const _: () = assert!(core::mem::offset_of!(IndexedSlotPendingState, pending_state) == 0x18);

/// Clears the selected slot's pending word — original: `FUN_08193f24` @
/// `0x08193f24` (20 bytes; 6 unconditional `bl` call sites).
///
/// # Safety
///
/// `state.offset(slot)` must designate writable memory when `slot < 3`. The
/// original permits negative `slot` values and performs no NULL check.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clear_indexed_slot_pending_state(
    state: *mut IndexedSlotPendingState,
    slot: i32,
) {
    if slot < 3 {
        (*state.offset(slot as isize)).pending_state = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{clear_indexed_slot_pending_state, IndexedSlotPendingState};

    fn slot(value: u32) -> IndexedSlotPendingState {
        IndexedSlotPendingState {
            opaque_00_14: [0xa5a5_a5a5; 6],
            pending_state: value,
            opaque_1c: 0x5a5a_5a5a,
        }
    }

    #[test]
    fn clears_each_in_range_slot_and_preserves_every_other_word() {
        let mut slots = [slot(0x10), slot(0x20), slot(0x30), slot(0x40)];
        let before: [u32; 4] = core::array::from_fn(|index| slots[index].pending_state);

        unsafe {
            clear_indexed_slot_pending_state(slots.as_mut_ptr(), 0);
            clear_indexed_slot_pending_state(slots.as_mut_ptr(), 2);
        }

        assert_eq!(slots[0].pending_state, 0);
        assert_eq!(slots[2].pending_state, 0);
        assert_eq!(slots[1].pending_state, before[1]);
        assert_eq!(slots[3].pending_state, before[3]);
        for state in slots {
            assert_eq!(state.opaque_00_14, [0xa5a5_a5a5; 6]);
            assert_eq!(state.opaque_1c, 0x5a5a_5a5a);
        }
    }

    #[test]
    fn negative_slot_addresses_the_preceding_slot() {
        let mut slots = [slot(0x10), slot(0x20), slot(0x30)];

        unsafe {
            clear_indexed_slot_pending_state(slots.as_mut_ptr().add(1), -1);
        }

        assert_eq!(slots[0].pending_state, 0);
        assert_eq!(slots[1].pending_state, 0x20);
        assert_eq!(slots[2].pending_state, 0x30);
    }

    #[test]
    fn slot_three_and_above_leave_the_state_unchanged() {
        let mut slots = [slot(0x10), slot(0x20), slot(0x30), slot(0x40)];
        let before: [u32; 4] = core::array::from_fn(|index| slots[index].pending_state);

        unsafe {
            clear_indexed_slot_pending_state(slots.as_mut_ptr(), 3);
            clear_indexed_slot_pending_state(slots.as_mut_ptr(), i32::MAX);
        }

        assert_eq!(slots.map(|state| state.pending_state), before);
    }
}
