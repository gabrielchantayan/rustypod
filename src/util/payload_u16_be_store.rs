//! Big-endian halfword update through an optional payload handle.
//!
//! Original: `FUN_0809c7ec` @ 0x0809c7ec, 56 bytes, ending at 0x0809c820;
//! next real function starts at 0x0809c824. Verified incoming calls: one
//! plain BL (0x0805a564), one BLNE (0x0805a13c). Outgoing: one plain BL
//! to store_u16_le_last_byte @ 0x080eda28, zero predicated BLs.
//! Return -50 for a NULL handle; otherwise load its first pointer, swap the
//! low halfword of value, and use the existing byte store at payload+8.
//! Return zero regardless of the byte store's returned pointer. No payload
//! NULL check is present. Deliberate deviation: the typed handle pointer
//! widens on hosts; its single pointer load retains the target's word layout.

use crate::util::u16_le_store_last_byte::store_u16_le_last_byte;

/// # Safety
/// A non-NULL handle must point to a readable payload pointer whose payload
/// has writable bytes at offsets 8 and 9. The payload need not be aligned.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn payload_u16_be_store(handle: *const *mut u8, value: u32) -> i32 {
    if handle.is_null() {
        return -50;
    }
    let payload = handle.read();
    store_u16_le_last_byte(payload.add(8), (value as u16).swap_bytes() as u32);
    0
}

#[cfg(test)]
mod tests {
    use super::payload_u16_be_store;

    #[test]
    fn null_handle_returns_parameter_error() {
        for value in [0, 0xffff, u32::MAX] {
            assert_eq!(unsafe { payload_u16_be_store(core::ptr::null(), value) }, -50);
        }
    }

    #[test]
    fn stores_every_low_halfword_big_endian_and_preserves_neighbors_and_handle() {
        for offset in 0..4 {
            for low in 0..=u16::MAX {
                let mut bytes = [0xa5u8; 16];
                let payload = unsafe { bytes.as_mut_ptr().add(offset) };
                let handle = payload;
                let value = 0xc37a_0000 | low as u32;
                assert_eq!(unsafe { payload_u16_be_store(&handle, value) }, 0);
                let mut expected = [0xa5u8; 16];
                expected[offset + 8..offset + 10].copy_from_slice(&low.to_be_bytes());
                assert_eq!(bytes, expected);
                assert_eq!(handle, payload);
            }
        }
    }
}
