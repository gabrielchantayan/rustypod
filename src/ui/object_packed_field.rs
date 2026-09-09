//! Two-bit field accessor for an unidentified UI object.
//!
//! `object_packed_field` — original: `FUN_08054468` @ `0x08054468` (24
//! bytes; 16 binary-verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM extent is exactly `0x08054468..0x0805447c`; the next separately
//! linked function starts at `0x08054480`. The leaf loads the byte at
//! `object + 0x1c`, then returns the two-bit field selected by bits 0..6 of
//! `selector[1]`: `(object[0x1c] >> ((selector[1] & 0x7f) << 1)) & 3`.
//! Indices 0..3 select the four fields; larger masked indices return zero.
//! The selector's high bit is deliberately ignored because ARM's register
//! shift uses only its low eight bits after the `lsl #1`.
//!
//! Every direct caller is a plain `bl`; there are no predicated calls, tail
//! branches, or aligned DATA words that hold this address. The leaf has no
//! null or alignment guard and dereferences both arguments immediately.
//! Deliberate deviations: none.

/// Reads the two-bit packed field selected by `selector[1]`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_packed_field(object: *const u8, selector: *const u8) -> u32 {
    let packed_fields = object.add(0x1c).read() as u32;
    let packed_field_index = selector.add(1).read();
    let shift = ((packed_field_index & 3) as u32) << 1;
    let selected_field = (packed_fields >> shift) & 3;
    let in_range_mask = 0u32.wrapping_sub(((packed_field_index & 0x7c) == 0) as u32);

    selected_field & in_range_mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Object {
        before_packed_fields: [u8; 0x1c],
        packed_fields: u8,
    }

    #[repr(C)]
    struct Selector {
        ignored_byte: u8,
        packed_field_index: u8,
    }

    fn call(packed_fields: u8, packed_field_index: u8) -> u32 {
        let object = Object {
            before_packed_fields: [0xa5; 0x1c],
            packed_fields,
        };
        let selector = Selector {
            ignored_byte: 0x5a,
            packed_field_index,
        };

        unsafe {
            object_packed_field(
                core::ptr::addr_of!(object).cast(),
                core::ptr::addr_of!(selector).cast(),
            )
        }
    }

    #[test]
    fn selects_each_two_bit_field_in_low_to_high_order() {
        let packed_fields = 0b11_10_01_00;
        assert_eq!(call(packed_fields, 0), 0);
        assert_eq!(call(packed_fields, 1), 1);
        assert_eq!(call(packed_fields, 2), 2);
        assert_eq!(call(packed_fields, 3), 3);
    }

    #[test]
    fn arm_shift_count_masks_selector_high_bit() {
        for packed_fields in 0u8..=u8::MAX {
            for packed_field_index in 0u8..=u8::MAX {
                let shift = ((packed_field_index & 0x7f) as u32) << 1;
                let expected = if shift < u8::BITS {
                    ((packed_fields as u32) >> shift) & 3
                } else {
                    0
                };
                assert_eq!(
                    call(packed_fields, packed_field_index),
                    expected,
                    "packed_fields={packed_fields:#04x}, index={packed_field_index:#04x}",
                );
            }
        }
    }
}
