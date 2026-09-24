//! Tests whether a selected UI object's packed field remains other than one.
//!
//! `object_packed_field_is_not_one` — original: `FUN_08061578` @ `0x08061578`
//! (20 bytes; one plain `bl` call and no predicated calls, binary-verified).
//!
//! Raw ARM spans `0x08061578..0x08061588`; the following `cmp r0, #0` at
//! `0x0806158c` starts the next independently linked function. It calls
//! `ensure_object_packed_field_is_one`, then computes a normalized logical
//! negation: zero yields one and every nonzero result yields zero. Deliberate
//! deviations: the Rust boolean negation replaces the ARM `rsbs`/`movcc`
//! normalization while preserving its zero/nonzero result contract.

use super::object_packed_field_ensure_one::ensure_object_packed_field_is_one;

/// Ensures a selected packed field is one, then reports whether it is not one.
///
/// # Safety
///
/// Has the same memory requirements as [`ensure_object_packed_field_is_one`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_packed_field_is_not_one(
    object: *mut u8,
    selector: *const u8,
) -> bool {
    !ensure_object_packed_field_is_one(object, selector)
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
            object_packed_field_is_not_one(
                core::ptr::addr_of_mut!(object).cast(),
                core::ptr::addr_of!(selector).cast(),
            )
        };
        (result, object.packed_fields)
    }

    fn reference(initial_fields: u8, packed_field_index: u8) -> (bool, u8) {
        let shift = ((packed_field_index & 3) as u32) << 1;
        let selected = (initial_fields as u32 >> shift) & 3;
        if packed_field_index & 0x7c != 0 {
            return (true, initial_fields);
        }
        if selected == 0 {
            return (false, initial_fields | (1 << shift) as u8);
        }
        (selected != 1, initial_fields)
    }

    #[test]
    fn normalizes_the_ensured_field_result_for_every_selector() {
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
