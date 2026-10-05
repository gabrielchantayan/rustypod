//! `alternate_error_object_construct` — FUN_081b9f30 @ 0x081b9f30.
//! True extent: 24 bytes (20 instruction bytes and the vtable literal at
//! 0x081b9f44); the next real entry starts at 0x081b9f48 with cmp r0,#0.
//! Raw aligned ARM BL decoding finds two inbound plain calls at 0x08148038
//! and 0x081d1768, no predicated calls, and one outbound plain BL to
//! 0x081d17c8. Construct the flag/state/payload base, replace its returned
//! object's vtable with 0x0898c758, and return that pointer. No NULL checks.
//! Deliberate deviations: reuse the existing Rust base port, use volatile
//! field access consistently with it, and describe only verified fields.

use super::vtable_flag_state_payload_construct::vtable_flag_state_payload_construct;

pub const ALTERNATE_ERROR_OBJECT_VTABLE: u32 = 0x0898_c758;

/// Construct the alternate error object's 16-byte prefix.
///
/// # Safety
/// `this` must satisfy the base constructor's requirements; its returned
/// pointer must be four-byte aligned with at least 16 writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn alternate_error_object_construct(this: *mut u8, payload: u32) -> *mut u8 {
    let object = unsafe { vtable_flag_state_payload_construct(this, payload) };
    unsafe { object.cast::<u32>().write_volatile(ALTERNATE_ERROR_OBJECT_VTABLE) };
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_exact_prefix_preserving_padding_and_neighbors() {
        for payload in [0, 1, 0x8000_0000, u32::MAX] {
            let mut words = [0xa5a5_a5a5u32; 6];
            let object = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
            assert_eq!(unsafe { alternate_error_object_construct(object, payload) }, object);
            assert_eq!(words, [0xa5a5_a5a5, ALTERNATE_ERROR_OBJECT_VTABLE,
                u32::from_ne_bytes([0, 0xa5, 0xa5, 0xa5]), 0, payload, 0xa5a5_a5a5]);
        }
    }
}
