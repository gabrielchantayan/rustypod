//! object_set_word_0x20 — original: `thunk_FUN_08214368` @ 0x0822b060
//! (4 bytes; three unconditional `bl` call sites, zero predicated `bl` call
//! sites, whole-image A32 decoded).
//!
//! Raw `osos.dec` establishes this as a one-instruction veneer: `b 0x08214368`
//! at 0x0822b060. That target begins with `str r1,[r0,#0x20]`; the following
//! `push {r4,lr}` at 0x0822b064 begins the next real function. This port stores
//! the supplied word at offset 0x20 of an unchecked object pointer.
//!
//! Deliberate deviation: the veneer tail-branch is folded into its verified
//! store rather than modeled as a seam for an unnamed callee. Its dedicated
//! text section keeps this real exported BL target rather than permitting
//! identical-code folding.

/// Stores `value` in the target word at offset 0x20 of `object`.
///
/// # Safety
///
/// `object` must address writable, four-byte-aligned storage at `+0x20`; as in
/// stock, there is no NULL or alignment check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_set_word_0x20")]
#[inline(never)]
pub unsafe extern "C" fn object_set_word_0x20(object: *mut u8, value: u32) {
    object.add(0x20).cast::<u32>().write(value);
}

#[cfg(test)]
mod tests {
    use super::object_set_word_0x20;

    #[test]
    fn stores_only_the_word_at_offset_0x20() {
        let mut object = [0xa5a5_a5a5u32; 10];

        unsafe { object_set_word_0x20(object.as_mut_ptr().cast(), 0x1234_5678) };

        assert_eq!(object[7], 0xa5a5_a5a5);
        assert_eq!(object[8], 0x1234_5678);
        assert_eq!(object[9], 0xa5a5_a5a5);
    }

    #[test]
    fn stores_zero_and_maximum_word_values() {
        let mut object = [0xa5a5_a5a5u32; 9];

        unsafe { object_set_word_0x20(object.as_mut_ptr().cast(), 0) };
        assert_eq!(object[8], 0);

        unsafe { object_set_word_0x20(object.as_mut_ptr().cast(), u32::MAX) };
        assert_eq!(object[8], u32::MAX);
    }
}
