//! object_byte_0x21 — original: `FUN_0814d1bc` @ 0x0814d1bc (8 bytes;
//! five unconditional `bl` call sites, zero predicated `bl` call sites,
//! binary-scanned).
//!
//! Raw `osos.dec` words establish the complete function: `ldrb r0,[r0,#0x21]`
//! at 0x0814d1bc and `bx lr` at 0x0814d1c0. The next separately linked
//! function starts at 0x0814d1c4. It returns the unsigned byte at offset
//! 0x21 of an unchecked object pointer. The object's concrete type is not
//! recovered, so the field-offset name preserves the verified behavior.
//!
//! Deliberate deviations: none. The unchecked dereference intentionally
//! retains the firmware's null and invalid-pointer fault behavior.

/// Returns the unsigned byte at offset 0x21 of `object`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_byte_0x21(object: *const u8) -> u8 {
    *object.add(0x21)
}

#[cfg(test)]
mod tests {
    use super::object_byte_0x21;

    #[test]
    fn reads_the_byte_at_offset_0x21_without_widening() {
        let mut object = [0x55u8; 0x22];
        object[0x20] = 0x12;
        object[0x21] = 0xfe;

        assert_eq!(unsafe { object_byte_0x21(object.as_ptr()) }, 0xfe);
    }

    #[test]
    fn returns_zero_and_maximum_byte_values() {
        let mut object = [0u8; 0x22];
        assert_eq!(unsafe { object_byte_0x21(object.as_ptr()) }, 0);

        object[0x21] = u8::MAX;
        assert_eq!(unsafe { object_byte_0x21(object.as_ptr()) }, u8::MAX);
    }
}
