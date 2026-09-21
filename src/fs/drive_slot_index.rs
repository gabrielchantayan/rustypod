//! Four-slot drive-index validator.
//!
//! `drive_slot_index_is_valid` is retailOS `FUN_082e4b3c` at `0x082e4b3c`
//! (16 bytes). Raw `osos.dec` words establish the body through `bx lr` at
//! `0x082e4b48`; the next independently entered function begins at
//! `0x082e4b4c` with `movs r2, r0`. Whole-image ARM B/BL decoding finds three
//! direct inbound calls, all plain `bl` (0x082e0708, 0x082e07b0, and
//! 0x082e37bc), and no predicated BL calls.
//!
//! It compares the unsigned drive index with four and returns one for slots
//! zero through three, zero otherwise. The two predicated `mov` instructions
//! explicitly materialize a 0/1 `u32` result.
//!
//! Deliberate deviations: none.

/// Returns whether `index` selects one of the four retailOS drive slots.
///
/// Original: `FUN_082e4b3c` at `0x082e4b3c`, 16 bytes; three binary-verified
/// direct plain-`bl` call sites and zero predicated BL call sites.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.drive_slot_index_is_valid")]
#[inline(never)]
pub extern "C" fn drive_slot_index_is_valid(index: u32) -> u32 {
    (index < 4) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exactly_the_four_unsigned_drive_slots() {
        for index in 0..=3 {
            assert_eq!(drive_slot_index_is_valid(index), 1, "index {index}");
        }

        for index in [4, 5, u32::MAX] {
            assert_eq!(drive_slot_index_is_valid(index), 0, "index {index}");
        }
    }
}
