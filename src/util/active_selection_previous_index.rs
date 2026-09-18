//! Active-selection previous-index lookup — original: `FUN_081446a0` @
//! `0x081446a0`.
//!
//! Load address: `0x081446a0`; true size: 44 bytes (`0x2c`), ending in
//! `bx lr` before the next real function at `0x081446cc`. Raw ARM decoding
//! verifies zero plain `bl` instructions and zero predicated `bl` instructions
//! in the body; a complete direct-call scan finds four unconditional inbound
//! `bl` call sites and no predicated inbound calls.
//!
//! Reads the active selection byte at `selection+0xa4`. It maps the three
//! nonzero selection slots to their previous slot in the cycle `1 -> 3 -> 2 ->
//! 1`; zero and every out-of-range byte produce zero. No deliberate deviations.

/// Returns the preceding nonzero active-selection slot, or zero when no valid
/// slot is selected.
///
/// `selection` must address the retailOS layout through byte offset `0xa4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.active_selection_previous_index"]
pub unsafe extern "C" fn active_selection_previous_index(selection: *const u8) -> u32 {
    let active_selection_index = *selection.add(0xa4);
    if active_selection_index == 1 {
        3
    } else if active_selection_index == 2 {
        1
    } else if active_selection_index == 3 {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static SELECTION: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ACTIVE_SELECTION_PREVIOUS_INDEX, 0x1000)
            .map(|pointer| pointer as usize)
    });

    #[test]
    fn maps_each_valid_slot_and_rejects_every_other_byte() {
        let Some(selection) = *SELECTION else {
            assert!(note_missing_u32_fixture("util/active_selection_previous_index"));
            return;
        };
        let selection = selection as *mut u8;

        for (state, expected) in [(0, 0), (1, 3), (2, 1), (3, 2), (4, 0), (u8::MAX, 0)] {
            unsafe {
                selection.add(0xa4).write(state);
                assert_eq!(active_selection_previous_index(selection), expected, "state {state}");
            }
        }
    }
}
