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
/// `set_object_packed_field` — original: `FUN_08067244` @ `0x08067244` (48
/// bytes; six binary-verified direct call sites: four unconditional `bl`, one
/// `bleq`, and one `blne`).
///
/// Raw ARM covers `0x08067244..0x08067270`; the next independently linked
/// function begins at `0x08067274`. Clears the two-bit field selected by
/// `selector[1]` in `object + 0x1c`, writes that intermediate byte, then ORs
/// in `selected` at the same shift and writes again. ARM's first `lsl #1`
/// leaves only selector bits 0..6 in the following register-shift count;
/// indices 4..127 leave the byte unchanged after truncation, while indices
/// 128..255 repeat the corresponding low-seven-bit behavior. There is no
/// null, bounds, or value guard. Deliberate deviations: none.
///
/// # Safety
///
/// `object + 0x1c` and `selector + 1` must be readable, and the packed byte
/// must be writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn set_object_packed_field(selected: u32, object: *mut u8, selector: *const u8) {
    let packed_fields = object.add(0x1c);
    let clear_index = selector.add(1).read();
    let clear_shift = ((clear_index & 0x7f) as u32) << 1;
    let clear_mask = if clear_shift < 32 { 3u32 << clear_shift } else { 0 };
    let cleared = packed_fields.read() & !(clear_mask as u8);
    packed_fields.write(cleared);

    let set_index = selector.add(1).read();
    let set_shift = ((set_index & 0x7f) as u32) << 1;
    let set_mask = if set_shift < 32 { selected << set_shift } else { 0 };
    packed_fields.write(cleared | set_mask as u8);
}

#[cfg(test)]
mod setter_tests {
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

    fn call(initial_fields: u8, selected: u32, packed_field_index: u8) -> u8 {
        let mut object = Object {
            before_packed_fields: [0xa5; 0x1c],
            packed_fields: initial_fields,
        };
        let selector = Selector {
            ignored_byte: 0x5a,
            packed_field_index,
        };

        unsafe {
            set_object_packed_field(
                selected,
                core::ptr::addr_of_mut!(object).cast(),
                core::ptr::addr_of!(selector).cast(),
            );
        }
        object.packed_fields
    }

    fn reference(initial_fields: u8, selected: u32, packed_field_index: u8) -> u8 {
        let shift = ((packed_field_index & 0x7f) as u32) << 1;
        if shift < u8::BITS {
            let field_mask = (3u32 << shift) as u8;
            (initial_fields & !field_mask) | (selected << shift) as u8
        } else {
            initial_fields
        }
    }

    #[test]
    fn writes_packed_field_for_every_selector_byte_value() {
        for initial_fields in 0u8..=u8::MAX {
            for packed_field_index in 0u8..=u8::MAX {
                for selected in [0, 1, 2, 3, 0xfeed_beef, u32::MAX] {
                    assert_eq!(
                        call(initial_fields, selected, packed_field_index),
                        reference(initial_fields, selected, packed_field_index),
                        "initial={initial_fields:#04x}, selected={selected:#010x}, index={packed_field_index:#04x}",
                    );
                }
            }
        }
    }
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
