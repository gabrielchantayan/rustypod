//! object_set_word_0x40 — original: `FUN_081660f0` @ 0x081660f0 (8 bytes;
//! four unconditional `bl` call sites, zero predicated `bl` call sites,
//! binary-scanned).
//!
//! Raw `osos.dec` words establish the complete function: `str r1,[r0,#0x40]`
//! at 0x081660f0 and `bx lr` at 0x081660f4. The next separately linked
//! function starts at 0x081660f8 with `push {r4, lr}`. It stores the supplied
//! target word at offset 0x40 of an unchecked object pointer. The concrete
//! object type and the meaning of this word are not recovered from its four
//! callers.
//!
//! Deliberate deviations: none. The unchecked store intentionally retains the
//! firmware's null and invalid-pointer fault behavior.

/// Stores `value` in the target word at offset 0x40 of `object`.
///
/// # Safety
///
/// `object` must address writable, four-byte-aligned storage at `+0x40`; as in
/// stock, there is no NULL or alignment check.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_set_word_0x40(object: *mut u8, value: u32) {
    object.add(0x40).cast::<u32>().write(value);
}

#[cfg(test)]
mod tests {
    use super::object_set_word_0x40;

    #[test]
    fn stores_only_the_word_at_offset_0x40() {
        let mut object = [0xa5a5_a5a5u32; 18];

        unsafe { object_set_word_0x40(object.as_mut_ptr().cast(), 0x1234_5678) };

        assert_eq!(object[15], 0xa5a5_a5a5);
        assert_eq!(object[16], 0x1234_5678);
        assert_eq!(object[17], 0xa5a5_a5a5);
    }

    #[test]
    fn stores_zero_and_maximum_word_values() {
        let mut object = [0xa5a5_a5a5u32; 17];

        unsafe { object_set_word_0x40(object.as_mut_ptr().cast(), 0) };
        assert_eq!(object[16], 0);

        unsafe { object_set_word_0x40(object.as_mut_ptr().cast(), u32::MAX) };
        assert_eq!(object[16], u32::MAX);
    }
}
