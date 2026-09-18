//! object_set_byte_0x27 — original: `FUN_08174714` @ 0x08174714 (8 bytes;
//! four unconditional `bl` call sites, zero predicated `bl` call sites,
//! binary-scanned).
//!
//! Raw `osos.dec` words establish the complete function: `strb r1,[r0,#0x27]`
//! at 0x08174714 and `bx lr` at 0x08174718. The next separately linked
//! function starts at 0x0817471c. It stores the supplied byte at offset 0x27
//! of an unchecked object pointer. The object's concrete type and this field's
//! enum are not recovered from its four callers.
//!
//! Deliberate deviations: none. The unchecked store intentionally retains the
//! firmware's null and invalid-pointer fault behavior.

/// Stores `value` in the byte at offset 0x27 of `object`.
///
/// # Safety
///
/// `object` must address writable storage at `+0x27`; as in stock, there is
/// no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_set_byte_0x27(object: *mut u8, value: u8) {
    object.add(0x27).write(value);
}

#[cfg(test)]
mod tests {
    use super::object_set_byte_0x27;

    #[test]
    fn stores_only_the_byte_at_offset_0x27() {
        let mut object = [0x55u8; 0x29];

        unsafe { object_set_byte_0x27(object.as_mut_ptr(), 0xa5) };

        assert_eq!(object[0x26], 0x55);
        assert_eq!(object[0x27], 0xa5);
        assert_eq!(object[0x28], 0x55);
    }

    #[test]
    fn stores_zero_and_maximum_byte_values() {
        let mut object = [0x55u8; 0x28];

        unsafe { object_set_byte_0x27(object.as_mut_ptr(), 0) };
        assert_eq!(object[0x27], 0);

        unsafe { object_set_byte_0x27(object.as_mut_ptr(), u8::MAX) };
        assert_eq!(object[0x27], u8::MAX);
    }
}
