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
//! Deliberate deviations: none. Reuse the direct Rust base constructor
//! without inferring a wider class identity.

use super::vtable_flag_base_construct::vtable_flag_base_construct;

/// Derived vtable literal from 0x081d17ec.
pub const VTABLE_FLAG_STATE_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0898_dd10;

/// Initialize the vtable, flag, state word, and payload prefix.
///
/// # Safety
/// `this` must be four-byte aligned and point to at least 16 writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_flag_state_payload_construct(
    this: *mut u8,
    payload: u32,
) -> *mut u8 {
    let constructed = unsafe { vtable_flag_base_construct(this) };
    unsafe {
        constructed.cast::<u32>().write_volatile(VTABLE_FLAG_STATE_PAYLOAD_VTABLE_ADDRESS);
        constructed.cast::<u32>().add(3).write_volatile(payload);
        constructed.cast::<u32>().add(2).write_volatile(0);
    }
    constructed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_fields_and_preserves_padding_and_surrounding_words() {
        for payload in [0, 1, 0x8000_0000, u32::MAX] {
            let mut words = [0xa5a5_a5a5u32; 6];
            let object = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
            let result = unsafe {
                vtable_flag_state_payload_construct(object, payload)
            };
            assert_eq!(result, object);
            assert_eq!(words, [0xa5a5_a5a5, VTABLE_FLAG_STATE_PAYLOAD_VTABLE_ADDRESS,
                u32::from_ne_bytes([0, 0xa5, 0xa5, 0xa5]), 0, payload, 0xa5a5_a5a5]);
        }
    }

}
