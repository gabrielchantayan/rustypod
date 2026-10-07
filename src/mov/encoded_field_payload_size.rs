//! Returns the bytes remaining in a 28-byte compact encoded field.
//!
//! `encoded_field_payload_size` — original: `FUN_08164e00` at load address
//! `0x08164e00` (36 bytes, `[0x08164e00, 0x08164e24)`). The next real
//! function begins with `push {r4,r5,r6,lr}` at `0x08164e24`. Whole-image
//! aligned ARM decoding verifies two incoming plain BL calls, at `0x08163f50`
//! and `0x08164ccc`, and zero predicated BL calls. The body has two plain BLs
//! and zero predicated BLs.
//!
//! Obtain the payload pointer from the existing layout validator, subtract it
//! from field+28, mask to eight bits, and return when the result is <=26;
//! otherwise terminate through heap_panic. Ghidra's byte argument and void
//! return are incorrect: r0 is a field pointer on entry and a length on return.
//! Deliberate deviations: native-width host pointer arithmetic; target address
//! arithmetic remains wrapping 32-bit. No new callee seam.

use super::encoded_field_layout_validate::encoded_field_layout_validate;
use crate::heap::veneers::heap_panic;

/// Returns the compact field's remaining payload length.
///
/// # Safety
/// `field` must point to a readable header byte and, when its high bit is set,
/// a readable optional byte. The original has no null or allocation guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn encoded_field_payload_size(field: *const u8) -> u32 {
    let payload = encoded_field_layout_validate(field);
    let size = (field as usize).wrapping_add(28).wrapping_sub(payload as usize) as u8;
    if size > 26 {
        heap_panic();
    }
    size as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_valid_headers_match_independent_layout_reference() {
        for header in 0u8..=255 {
            for optional in 0u8..=255 {
                if header & 0x80 != 0 && optional & 3 == 3 { continue; }
                let primary_width = (header & 3) as u32;
                let primary_prefix = if primary_width == 0 { 0 } else { 1 + ((header >> 2) & 3) as u32 };
                let optional_width = if header & 0x80 == 0 { 0 } else { (optional & 3) as u32 };
                let optional_span = if optional_width == 0 { 0 } else {
                    optional_width + 1 + ((optional >> 2) & 3) as u32
                        + 1 + u32::from(optional & 0x10 != 0)
                };
                let expected = 26 - primary_width - primary_prefix - optional_span;
                let field = [header, optional];
                assert_eq!(unsafe { encoded_field_payload_size(field.as_ptr()) }, expected,
                    "header={header:#04x}, optional={optional:#04x}");
            }
        }
    }

    #[test]
    fn single_byte_headers_and_maximum_metadata_span() {
        let header = 0u8;
        assert_eq!(unsafe { encoded_field_payload_size(&header) }, 26);
        let field = [0x8f, 0x1e];
        assert_eq!(unsafe { encoded_field_payload_size(field.as_ptr()) }, 11);
    }
}
