//! object_set_byte_0x18 — original: `FUN_08121404` @ 0x08121404 (8 bytes;
//! four unconditional `bl` call sites, zero predicated `bl` call sites,
//! binary-scanned).
//!
//! Raw `osos.dec` words establish the complete function: `strb r1,[r0,#0x18]`
//! at 0x08121404 and `bx lr` at 0x08121408. The next separately linked
//! function starts at 0x0812140c. It stores the supplied byte at offset 0x18
//! of an unchecked object pointer. The object's concrete type and this field's
//! enum are not recovered from its callers.
//!
//! Deliberate deviations: none. The unchecked store intentionally retains the
//! firmware's null and invalid-pointer fault behavior.

/// Stores `value` in the byte at offset 0x18 of `object`.
///
/// # Safety
///
/// `object` must address writable storage at `+0x18`; as in stock, there is
/// no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_set_byte_0x18(object: *mut u8, value: u8) {
    object.add(0x18).write(value);
}

#[cfg(test)]
mod tests {
    use super::object_set_byte_0x18;

    #[test]
    fn stores_only_the_byte_at_offset_0x18() {
        let mut object = [0x55u8; 0x1a];

        unsafe { object_set_byte_0x18(object.as_mut_ptr(), 0xa5) };

        assert_eq!(object[0x17], 0x55);
        assert_eq!(object[0x18], 0xa5);
        assert_eq!(object[0x19], 0x55);
    }

    #[test]
    fn stores_zero_and_maximum_byte_values() {
        let mut object = [0x55u8; 0x19];

        unsafe { object_set_byte_0x18(object.as_mut_ptr(), 0) };
        assert_eq!(object[0x18], 0);

        unsafe { object_set_byte_0x18(object.as_mut_ptr(), u8::MAX) };
        assert_eq!(object[0x18], u8::MAX);
    }
}
