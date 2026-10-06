//! Context queued-entry flag clearing — `FUN_08185b60` @ `0x08185b60`.
//!
//! True extent: 56 bytes, `0x08185b60..0x08185b98`; the next function
//! starts with `ldr r1,[pc,#8]`. Whole-image aligned A32 decoding finds
//! two plain inbound BLs (0x08094324, 0x080d6b8c), zero predicated BLs.
//! The body has one plain BL to active_slot_count, zero predicated BLs.
//! Recount the contiguous active prefix before each indexed byte clear.
//! Since clearing slot zero makes the next count zero, only slot zero can
//! be cleared, even when all four slots were active. Keep the original loop
//! and u8 index rather than replacing the recount with a cached count.
//! Deliberate deviation: volatile byte access follows the count port's
//! convention; opaque bytes preserve the 20-byte target stride on hosts.

use crate::active_slot_count::active_slot_count;

/// # Safety
/// `slots` must contain four readable 20-byte slots, with writable active
/// bytes at +16. No NULL guard exists in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clear_context_entry_flags(slots: *mut u8) {
    let mut index = 0u8;
    while active_slot_count(slots) > index {
        slots.add(index as usize * 20 + 16).write_volatile(0);
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_first_flag_for_every_active_pattern_and_preserves_payload() {
        for mask in 0..16 {
            for active in [1, 0x80, 0xff] {
                let mut slots = [0xa5u8; 80];
                for index in 0..4 {
                    slots[index * 20 + 16] = if mask & (1 << index) != 0 { active } else { 0 };
                }
                let mut expected = slots;
                expected[16] = 0;
                unsafe { clear_context_entry_flags(slots.as_mut_ptr()) };
                assert_eq!(slots, expected, "mask={mask}, active={active}");
                unsafe { clear_context_entry_flags(slots.as_mut_ptr()) };
                assert_eq!(slots, expected, "repeat must preserve later flags");
            }
        }
    }
}
