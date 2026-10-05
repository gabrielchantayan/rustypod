//! class_8c00_byte_d4_get — original: `FUN_081a56f4` @ `0x081a56f4`.
//! True extent: 8 bytes, ending at the next function's push at 0x081a56fc.
//! Raw words: e5d000d4 (ldrb r0,[r0,#0xd4]), e12fff1e (bx lr).
//! Whole-image aligned A32 decoding verifies two inbound plain BL calls
//! (0x0810999c, 0x0812fe74), zero predicated BL calls; no outbound calls.
//!
//! Return the unsigned byte at +0xd4 of the registry-class-0x8c00 object
//! supplied by singleton_class_8c00. Callers test zero versus nonzero, but
//! the field's domain is unknown: preserve all 256 values, not a bool.
//! No deliberate deviations; no NULL check, mutation, or synchronization.

const BYTE_OFFSET: usize = 0xd4;

/// Read the class-0x8c00 object's opaque byte field at +0xd4.
///
/// # Safety
/// `object` must be non-NULL and readable through byte +0xd4. No alignment
/// is required for this byte access. The field must not be concurrently written.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn class_8c00_byte_d4_get(object: *const u8) -> u8 {
    unsafe { object.add(BYTE_OFFSET).read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_unsigned_byte_without_touching_neighbors() {
        for alignment in 0..4 {
            let mut storage = [0xa5u8; BYTE_OFFSET + 5];
            for value in 0..=u8::MAX {
                storage[alignment + BYTE_OFFSET] = value;
                let before = storage;
                let object = unsafe { storage.as_ptr().add(alignment) };
                assert_eq!(unsafe { class_8c00_byte_d4_get(object) }, value);
                assert_eq!(storage, before);
            }
        }
    }
}
