//! Validates and returns a two-bit width held in an optional flagged byte.
//!
//! `mov_checked_flagged_width` — original: `FUN_08164de8` at load address
//! `0x08164de8` (**24 bytes**, `0x08164de8..0x08164dff`). Raw `osos.dec`
//! disassembly establishes the next separately linked function at `0x08164e00`.
//! A complete aligned ARM B/BL-immediate decode finds **five direct `bl` call
//! sites**, all unconditional/plain (`0x08163f0c`, `0x08164a40`, `0x08164ad4`,
//! `0x08164e48`, and `0x08164efc`); there are no predicated calls.
//!
//! The function reads the optional byte selected by the field's high-bit flag,
//! masks it to its low two bits, and terminates through `heap_panic` when both
//! bits are set. A clear flag produces width zero without reading the optional
//! byte. No deliberate deviations.

use crate::heap::veneers::heap_panic;
use super::optional_flagged_byte::optional_flagged_byte;


/// Returns the checked low-two-bit width encoded after a high-bit field flag.
///
/// # Safety
///
/// `flagged_field` must be readable. When its high bit is set,
/// `flagged_field.add(1)` must also be readable. The original has no null,
/// bounds, or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_checked_flagged_width(flagged_field: *const u8) -> u8 {
    let optional_width = optional_flagged_byte(flagged_field);
    let width = optional_width & 3;
    if width == 3 {
        heap_panic();
    }
    width
}

#[cfg(test)]
mod tests {
    use super::mov_checked_flagged_width;

    #[test]
    fn clear_flag_returns_zero_without_using_optional_byte() {
        let field = [0x7f, 0xff];
        assert_eq!(unsafe { mov_checked_flagged_width(field.as_ptr()) }, 0);
    }

    #[test]
    fn flagged_width_accepts_each_nonfatal_low_bit_pattern() {
        for (encoded, expected) in [(0x80, 0), (0x81, 1), (0xfe, 2)] {
            let field = [0x80, encoded];
            assert_eq!(unsafe { mov_checked_flagged_width(field.as_ptr()) }, expected);
        }
    }
}
