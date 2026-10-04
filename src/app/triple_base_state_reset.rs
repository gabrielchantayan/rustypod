//! Resets three adjacent base-vtable states, last to first.
//!
//! Original: `FUN_081f4078` @ `0x081f4078`; true extent 32 bytes
//! (`0x081f4078..0x081f4098`, where the next independent leaf begins).
//! Raw A32 decoding verifies two outbound unconditional BLs, no predicated
//! BLs, and one tail B. Whole-image decoding finds two inbound unconditional
//! BLs at `0x08153df8` and `0x08206e2c`, with no predicated BLs.
//!
//! Algorithm: reset the records at +0x20, +0x10, and +0x00, installing
//! vtable 0x08982fc4, clearing state, and setting both sentinels to all ones.
//! Each initializer preserves r0; the final result is the original pointer.
//!
//! Deliberate deviation: reuse `base_vtable_state_init` (0x081215c8), whose
//! raw stores and return match 0x081215ec exactly. The original BL targets
//! 0x0820c814 and 0x0818dce4, and tail target 0x0816745c, are verified plain
//! branch veneers to 0x081215ec. No concrete class identity is asserted.

use super::base_vtable_state_init::{base_vtable_state_init, BaseVtableState};

/// Resets exactly three target-layout records and returns `storage`.
///
/// # Safety
/// `storage` must point to three contiguous, writable, word-aligned
/// [`BaseVtableState`] records (48 bytes). No NULL or bounds checks are made.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn triple_base_state_reset(storage: *mut BaseVtableState) -> *mut BaseVtableState {
    unsafe {
        let last = base_vtable_state_init(storage.add(2));
        let middle = base_vtable_state_init(last.sub(1));
        base_vtable_state_init(middle.sub(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_all_records_preserves_neighbors_and_returns_start() {
        for seed in [0, u32::MAX, 0x1357_9bdf] {
            let mut words = [seed; 14];
            words[0] = 0x1234_5678;
            words[13] = 0x8765_4321;
            let start = unsafe { words.as_mut_ptr().add(1).cast::<BaseVtableState>() };
            let returned = unsafe { triple_base_state_reset(start) };
            assert_eq!(returned, start);
            assert_eq!(words, [
                0x1234_5678,
                0x0898_2fc4, 0, u32::MAX, u32::MAX,
                0x0898_2fc4, 0, u32::MAX, u32::MAX,
                0x0898_2fc4, 0, u32::MAX, u32::MAX,
                0x8765_4321,
            ]);
        }
    }

    #[test]
    fn reconstruction_clears_distinct_live_states() {
        let mut records = core::array::from_fn::<_, 3, _>(|i| BaseVtableState {
            vtable: 0x1000 + i as u32,
            state: 1 << i,
            first_sentinel: i as u32,
            second_sentinel: 100 + i as u32,
        });
        unsafe { triple_base_state_reset(records.as_mut_ptr()); }
        for record in records {
            assert_eq!([record.vtable, record.state, record.first_sentinel, record.second_sentinel],
                [0x0898_2fc4, 0, u32::MAX, u32::MAX]);
        }
    }
}
