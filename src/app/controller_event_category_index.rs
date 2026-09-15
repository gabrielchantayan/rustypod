//! Controller event-category slot selection.
//!
//! `controller_event_category_index` — original: `FUN_081842e8` @
//! **0x081842e8**. Raw ARM establishes the exact **52-byte** extent,
//! `0x081842e8..0x0818431c`; the next separately linked function starts with
//! `push {r4-r8,lr}` at `0x0818431c`. Decoding every aligned ARM B/BL-immediate
//! word in `osos.dec` finds five inbound direct calls, all unconditional `bl`,
//! at `0x0817f418`, `0x0817f524`, `0x0817f6d8`, `0x08180fa8`, and
//! `0x08182780`; there are no predicated BL forms.
//!
//! # Algorithm
//!
//! Maps the event category values 1 through 4 to their zero-based controller
//! slot indices; every other value returns -1. The incoming `r0` controller
//! word is deliberately ignored, as the raw body only compares `r1`.
//!
//! # Deliberate deviations
//!
//! None.

/// Maps a controller event category to its zero-based slot index.
///
/// Original: `FUN_081842e8` @ `0x081842e8` (52 bytes; **5 unconditional `bl`
/// call sites**, no predicated calls). Categories 1, 2, 3, and 4 return 0, 1,
/// 2, and 3 respectively; all other `u32` values return -1. The unused first
/// ABI word is retained so callers preserve the retail calling convention.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn controller_event_category_index(_controller: *mut u8, category: u32) -> i32 {
    match category {
        1 => 0,
        2 => 1,
        3 => 2,
        4 => 3,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::controller_event_category_index;

    #[test]
    fn maps_each_supported_category_to_its_slot() {
        for (category, expected) in [(1, 0), (2, 1), (3, 2), (4, 3)] {
            assert_eq!(controller_event_category_index(core::ptr::null_mut(), category), expected);
        }
    }

    #[test]
    fn rejects_values_outside_the_four_category_domain() {
        for category in [0, 5, u32::MAX] {
            assert_eq!(controller_event_category_index(core::ptr::null_mut(), category), -1);
        }
    }
}
