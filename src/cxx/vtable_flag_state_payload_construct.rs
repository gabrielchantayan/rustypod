//! `vtable_flag_state_payload_construct` — `FUN_081d17c8` @ **0x081d17c8**.
//! 36 instruction bytes plus the four-byte literal at 0x081d17ec (40 bytes
//! through the next real function at 0x081d17f0). Raw ARM decoding verifies
//! two inbound plain BLs (0x0815faf4, 0x081b9f34), zero predicated BLs;
//! the body has one plain BL to 0x08135788 and zero predicated BLs.
//!
//! Preserve the payload across the base constructor, install vtable
//! 0x0898dd10 on its returned pointer, write payload at +12, clear the word
//! at +8, and return that pointer. The base clears byte +4; bytes +5..+7
//! remain untouched. Neither constructor checks NULL or alignment.
//!
//! Deliberate deviations: reuse the existing volatile, replaceable
//! 0x08135788 boundary in `vtable_flag_payload_construct`, whose default
//! models the verified base stores, rather than creating another seam.
//! Use semantic field names without inferring a wider class identity.

use super::vtable_flag_payload_construct::{
    VtableFlagBaseConstruct, VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS,
};

/// Derived vtable literal from 0x081d17ec.
pub const VTABLE_FLAG_STATE_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0898_dd10;

unsafe fn construct_with_base(
    this: *mut u8,
    payload: u32,
    construct_base: VtableFlagBaseConstruct,
) -> *mut u8 {
    let constructed = unsafe { construct_base(this) };
    unsafe {
        constructed.cast::<u32>().write_volatile(VTABLE_FLAG_STATE_PAYLOAD_VTABLE_ADDRESS);
        constructed.cast::<u32>().add(3).write_volatile(payload);
        constructed.cast::<u32>().add(2).write_volatile(0);
    }
    constructed
}

/// Initialize the vtable, flag, state word, and payload prefix.
///
/// # Safety
/// `this` must satisfy the installed base constructor's requirements. Its
/// result must be four-byte aligned and point to at least 16 writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_flag_state_payload_construct(
    this: *mut u8,
    payload: u32,
) -> *mut u8 {
    let ops = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS))
    };
    unsafe { construct_with_base(this, payload, ops.construct_base) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::vtable_flag_payload_construct::DEFAULT_VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS;

    #[test]
    fn initializes_fields_and_preserves_padding_and_surrounding_words() {
        for payload in [0, 1, 0x8000_0000, u32::MAX] {
            let mut words = [0xa5a5_a5a5u32; 6];
            let object = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
            let result = unsafe {
                construct_with_base(object, payload,
                    DEFAULT_VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS.construct_base)
            };
            assert_eq!(result, object);
            assert_eq!(words, [0xa5a5_a5a5, VTABLE_FLAG_STATE_PAYLOAD_VTABLE_ADDRESS,
                u32::from_ne_bytes([0, 0xa5, 0xa5, 0xa5]), 0, payload, 0xa5a5_a5a5]);
        }
    }

    // A distinct base result catches accidentally writing derived fields to
    // the input rather than r0 after the call. No global seam mutation needed.
    unsafe extern "C" fn next_object(this: *mut u8) -> *mut u8 {
        unsafe { this.add(16) }
    }

    #[test]
    fn initializes_base_result_not_input() {
        let mut words = [0x3c3c_3c3cu32; 9];
        let input = words.as_mut_ptr().cast::<u8>();
        let result = unsafe { construct_with_base(input, 0x1357_9bdf, next_object) };
        assert_eq!(result, unsafe { input.add(16) });
        assert_eq!(words, [0x3c3c_3c3c, 0x3c3c_3c3c, 0x3c3c_3c3c, 0x3c3c_3c3c,
            VTABLE_FLAG_STATE_PAYLOAD_VTABLE_ADDRESS, 0x3c3c_3c3c, 0, 0x1357_9bdf,
            0x3c3c_3c3c]);
    }
}
