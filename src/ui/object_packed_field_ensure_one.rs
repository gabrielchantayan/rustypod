//! Ensures a selected UI object's packed two-bit field is one.
//!
//! `ensure_object_packed_field_is_one` — original: `FUN_080616a0` @
//! `0x080616a0` (64 bytes; two plain `bl` calls and one predicated `bleq`
//! call, binary-verified).
//!
//! Raw ARM spans `0x080616a0..0x080616dc`; the next separately linked
//! function starts at `0x080616e0`. It reads the packed field selected by
//! `selector[1]`; if it is zero, it conditionally calls
//! `set_object_packed_field(1, object, selector)`, then reads the field again
//! and returns whether it is exactly one. The predicated call preserves the
//! original's no-write path for nonzero fields. Deliberate deviations: none.

use super::object_packed_field::{object_packed_field, set_object_packed_field};

/// Ensures the selected packed field is one and reports whether it is one.
///
/// # Safety
///
/// `object + 0x1c` and `selector + 1` must be readable, and `object + 0x1c`
/// must be writable when the selected field is zero.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ensure_object_packed_field_is_one(
    object: *mut u8,
    selector: *const u8,
) -> bool {
    if object_packed_field(object, selector) == 0 {
        set_object_packed_field(1, object, selector);
    }

    object_packed_field(object, selector) == 1
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

    fn call(initial_fields: u8, packed_field_index: u8) -> (bool, u8) {
        let mut object = Object {
            before_packed_fields: [0xa5; 0x1c],
            packed_fields: initial_fields,
        };
        let selector = Selector {
            ignored_byte: 0x5a,
            packed_field_index,
        };

        let result = unsafe {
            ensure_object_packed_field_is_one(
                core::ptr::addr_of_mut!(object).cast(),
                core::ptr::addr_of!(selector).cast(),
            )
        };
        (result, object.packed_fields)
    }

    fn reference(initial_fields: u8, packed_field_index: u8) -> (bool, u8) {
        let shift = ((packed_field_index & 3) as u32) << 1;
        let selected = (initial_fields as u32 >> shift) & 3;
        let in_range = packed_field_index & 0x7c == 0;
        if in_range && selected == 0 {
            let updated = initial_fields | (1 << shift) as u8;
            (true, updated)
        } else {
            (in_range && selected == 1, initial_fields)
        }
    }

    #[test]
    fn matches_all_packed_fields_and_selector_bytes() {
        for initial_fields in 0u8..=u8::MAX {
            for packed_field_index in 0u8..=u8::MAX {
                assert_eq!(
                    call(initial_fields, packed_field_index),
                    reference(initial_fields, packed_field_index),
                    "initial={initial_fields:#04x}, index={packed_field_index:#04x}",
                );
            }
        }
    }
}
