//! Validates the compact encoded-field layout length.
//!
//! `encoded_field_layout_validate` — original: `FUN_08164e24` at load address
//! `0x08164e24` (**120 bytes**, `0x08164e24..0x08164e9b`). Raw `osos.dec`
//! words establish the next separately linked function at `0x08164e9c`.
//! Ghidra finds three direct inbound `bl` callers. The body contains six
//! plain `bl` instructions (to `0x08164ec4`, `0x08164e9c`, `0x08164de8`,
//! `0x08164db8`, `0x08164c80`, and `heap_panic` at `0x08030f44`) and no
//! predicated calls.
//!
//! It sums the low header tag, primary prefix length, and—when the optional
//! width is nonzero—the optional width, its prefix length, marker byte, and
//! optional bit-4 byte. It then verifies the resulting field span plus two
//! trailing bytes is below 26, returning the pointer just past those bytes.
//! The checked-width helper rejects the only malformed optional width before
//! this final bound can be exceeded. Host pointer arithmetic retains native
//! width; the target uses wrapping 32-bit addresses like the original.

use crate::app::encoded_field_prefix_size::encoded_field_prefix_size;
use crate::heap::veneers::heap_panic;
use crate::mov::checked_flagged_width::mov_checked_flagged_width;
use crate::mov::optional_flagged_byte::optional_flagged_byte;
use super::optional_prefix_size::optional_prefix_size;
use crate::util::tagged_header_low_bits::tagged_header_low_bits;

/// Validates the encoded field and returns its payload pointer.
///
/// # Safety
///
/// `field` must be readable. If its high bit is set and the optional width is
/// nonzero, `field.add(1)` must also be readable. The original has no null or
/// bounds guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn encoded_field_layout_validate(field: *const u8) -> *const u8 {
    let tag_size = tagged_header_low_bits(field);
    let primary_prefix_size = encoded_field_prefix_size(field);
    let optional_width = mov_checked_flagged_width(field) as u32;
    let optional_size = if optional_width == 0 {
        0
    } else {
        let optional_prefix_size = optional_prefix_size(field);
        let optional_marker_size = 1 + u32::from(optional_flagged_byte(field) & 0x10 != 0);
        optional_width + optional_prefix_size + optional_marker_size
    };

    let payload = field.wrapping_add((tag_size + primary_prefix_size + optional_size + 2) as usize);
    if payload as usize >= field.wrapping_add(26) as usize {
        heap_panic();
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::encoded_field_layout_validate;

    #[test]
    fn returns_payload_after_primary_optional_and_trailing_fields() {
        for (header, optional, offset) in [
            (0x00, 0x00, 2), (0x0f, 0x00, 9),
            (0x80, 0x0c, 2), (0x80, 0x01, 5),
            (0x80, 0x1e, 10), (0x8f, 0x1e, 17),
        ] {
            let field = [header, optional];
            assert_eq!(
                unsafe { encoded_field_layout_validate(field.as_ptr()) },
                field.as_ptr().wrapping_add(offset),
            );
        }
    }
}
