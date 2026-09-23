//! Validates the compact encoded-field layout length.
//!
//! `encoded_field_layout_validate` — original: `FUN_08164e24` at load address
//! `0x08164e24` (**120 bytes**, `0x08164e24..0x08164e9b`). Raw `osos.dec`
//! words establish the next separately linked function at `0x08164e9c`.
//! Ghidra finds three direct inbound `bl` callers. The body contains five
//! plain `bl` instructions (to `0x08164ec4`, `0x08164e9c`, `0x08164de8`,
//! `0x08164db8`, and `0x08164c80`) and one predicated `blcs` to `heap_panic`
//! at `0x08030f44`.
//!
//! It sums the low header tag, primary prefix length, and—when the optional
//! width is nonzero—the optional width, its prefix length, marker byte, and
//! optional bit-4 byte. It then verifies the resulting field span plus two
//! trailing bytes is below 26. The checked-width helper rejects the only
//! malformed optional width before this final bound can be exceeded. No
//! deliberate deviations.

use crate::app::encoded_field_prefix_size::encoded_field_prefix_size;
use crate::heap::veneers::heap_panic;
use crate::mov::checked_flagged_width::mov_checked_flagged_width;
use crate::mov::optional_flagged_byte::optional_flagged_byte;
use crate::util::tagged_header_low_bits::tagged_header_low_bits;

/// Validates the encoded field beginning at `field`.
///
/// # Safety
///
/// `field` must be readable. If its high bit is set and the optional width is
/// nonzero, `field.add(1)` must also be readable. The original has no null or
/// bounds guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn encoded_field_layout_validate(field: *const u8) {
    let tag_size = tagged_header_low_bits(field);
    let primary_prefix_size = encoded_field_prefix_size(field);
    let optional_width = mov_checked_flagged_width(field) as u32;
    let optional_size = if optional_width == 0 {
        0
    } else {
        let optional_prefix_size = encoded_field_prefix_size(field.add(1));
        let optional_marker_size = 1 + u32::from(optional_flagged_byte(field) & 0x10 != 0);
        optional_width + optional_prefix_size + optional_marker_size
    };

    if tag_size + primary_prefix_size + optional_size + 2 >= 26 {
        heap_panic();
    }
}

#[cfg(test)]
mod tests {
    use super::encoded_field_layout_validate;

    #[test]
    fn accepts_every_valid_primary_and_optional_encoding() {
        for first in 0u8..=u8::MAX {
            for optional in [0x00, 0x01, 0x02, 0x10, 0x11, 0x12, 0x80, 0x81, 0x82, 0x90, 0x91, 0x92] {
                unsafe { encoded_field_layout_validate([first, optional].as_ptr()) };
            }
        }
    }

    #[test]
    fn clear_optional_flag_does_not_require_a_second_byte() {
        for first in 0u8..0x80 {
            unsafe { encoded_field_layout_validate(&first) };
        }
    }
}
