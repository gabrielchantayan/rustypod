//! Optional encoded-field prefix length.
//!
//! Original: `FUN_08164db8` at load address `0x08164db8`, 48 bytes,
//! `[0x08164db8, 0x08164de8)`. The next real function begins with push
//! {r4,lr} at 0x08164de8. Whole-image aligned ARM BL decoding finds two
//! incoming plain calls (0x08164e54, 0x08164f08), no predicated incoming
//! calls. The body has one plain BL to optional_flagged_byte (0x08164c80)
//! and one BLHI to heap_panic (0x08030f44).
//!
//! Read the optional byte only when header bit 7 is set. Return zero when
//! its low two bits are zero; otherwise return bits 2..3 plus one (1..4).
//! Deliberate deviation: omit the unreachable unsigned >4 fatal check;
//! masking with 0x0c proves the computed length cannot exceed four.

use super::optional_flagged_byte::optional_flagged_byte;

/// # Safety
/// `field` must point to a readable header byte and, when bit 7 is set,
/// a readable following byte. No null or allocation checks are added.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn optional_prefix_size(field: *const u8) -> u32 {
    let optional = optional_flagged_byte(field);
    if optional & 3 == 0 {
        0
    } else {
        u32::from((optional & 0x0c) >> 2) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::optional_prefix_size;

    #[test]
    fn every_header_and_optional_byte_matches_bit_field_reference() {
        for header in 0u8..=255 {
            for optional in 0u8..=255 {
                let field = [header, optional];
                let widths = [1, 2, 3, 4];
                let expected = if header < 128 || optional % 4 == 0 {
                    0
                } else {
                    widths[usize::from(optional / 4 % 4)]
                };
                assert_eq!(unsafe { optional_prefix_size(field.as_ptr()) }, expected,
                    "header={header:#04x}, optional={optional:#04x}");
            }
        }
    }

    #[test]
    fn absent_optional_byte_accepts_one_byte_field() {
        for header in 0u8..128 {
            assert_eq!(unsafe { optional_prefix_size(&header) }, 0);
        }
    }
}
