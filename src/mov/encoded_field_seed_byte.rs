//! Encoded-field transform seed byte accessor.
//!
//! Original: `FUN_08164ed8` @ load address `0x08164ed8`, **84 bytes**
//! (`0x08164ed8..0x08164f2c`; next function starts with push {r0-r6,lr}).
//! Full-image aligned ARM BL decoding verifies two inbound plain BL calls at
//! 0x08163f44 and 0x08164cd8, zero predicated calls. The body has four plain
//! BLs and zero predicated BLs.
//!
//! Add the primary tag width and prefix size. Add the optional low-two-bit
//! width and prefix size, plus its marker only when that sum is nonzero.
//! Return the byte one position beyond the combined fields. The caller at
//! 0x08164c98 uses this byte to seed its byte transform.
//!
//! Deliberate deviations: express the unported optional-prefix helper through
//! the existing prefix-size seam, gated by the high header bit. Express the
//! raw 0x08164de8 width mask directly: its unsigned <=3 return accepts all
//! masked values, unlike the existing Rust seam's erroneous width-3 rejection.
//! Unreachable fatal checks in these masked helpers are omitted. No bit-4
//! extra byte is added (unlike the adjacent payload-address routine).

use crate::app::encoded_field_prefix_size::encoded_field_prefix_size;
use crate::util::tagged_header_low_bits::tagged_header_low_bits;
use super::optional_flagged_byte::optional_flagged_byte;

/// # Safety
/// `field` must be readable through the computed seed offset (at most 16).
/// No null or length checks are added, matching the firmware.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn encoded_field_seed_byte(field: *const u8) -> u8 {
    let primary_size = (tagged_header_low_bits(field)
        + encoded_field_prefix_size(field)) as u8;
    let optional_width = optional_flagged_byte(field) & 3;
    let optional_prefix = if *field & 0x80 != 0 {
        encoded_field_prefix_size(field.add(1)) as u8
    } else {
        0
    };
    let optional_size = optional_width.wrapping_add(optional_prefix);
    let optional_size = if optional_size == 0 {
        0
    } else {
        optional_size.wrapping_add(1)
    };
    *field.add(primary_size as usize + optional_size as usize + 1)
}

#[cfg(test)]
mod tests {
    use super::encoded_field_seed_byte;

    #[test]
    fn every_header_and_optional_byte_selects_reference_offset() {
        for header in 0u8..=255 {
            for optional in 0u8..=255 {
                let mut field = [0u8; 17];
                for (offset, byte) in field.iter_mut().enumerate() {
                    *byte = 0x40 + offset as u8;
                }
                field[0] = header;
                field[1] = optional;
                // Independent bit-field reference, including width 3 and bit 4.
                let tag = usize::from(header & 3);
                let primary = if tag == 0 { 0 } else { usize::from((header >> 2) & 3) + 1 };
                let second = if header & 0x80 == 0 { 0 } else { optional };
                let width = usize::from(second & 3);
                let extension = if width == 0 { 0 } else { usize::from((second >> 2) & 3) + 1 };
                let extra = if width == 0 { 0 } else { width + extension + 1 };
                let expected = field[1 + tag + primary + extra];
                assert_eq!(unsafe { encoded_field_seed_byte(field.as_ptr()) }, expected,
                    "header={header:#04x}, optional={optional:#04x}");
            }
        }
    }

    #[test]
    fn absent_optional_field_needs_only_seed_byte() {
        let field = [0x70, 0xab];
        assert_eq!(unsafe { encoded_field_seed_byte(field.as_ptr()) }, 0xab);
    }
}
