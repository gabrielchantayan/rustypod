//! object_subobject_0x3c — original: `FUN_08280834` @ `0x08280834`
//! (8 bytes; three unconditional plain `bl` call sites, zero predicated `bl`
//! call sites).
//!
//! Raw `osos.dec` words establish the complete function: `add r0,r0,#0x3c`
//! at `0x08280834` followed by `bx lr` at `0x08280838`. The next independently
//! entered function begins with `push {r4,r5,r6,r7,lr}` at `0x0828083c`, so the
//! true extent is `0x08280834..0x0828083c`. Whole-image A32 branch decoding
//! finds the three inbound calls at `0x08115d64`, `0x081f0980`, and
//! `0x0822b404`; none is predicated. The function performs no calls itself.
//!
//! # Algorithm
//!
//! Returns the unchecked byte address 0x3c bytes into an object. Callers use
//! the returned subobject as a virtual-dispatch receiver. The concrete object
//! type is unrecovered, so the field-offset name preserves the verified
//! behavior. Deliberate deviations: none.

/// Returns the byte address of `object`'s subobject at offset 0x3c.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_subobject_0x3c")]
#[inline(never)]
pub unsafe extern "C" fn object_subobject_0x3c(object: *mut u8) -> *mut u8 {
    object.wrapping_add(0x3c)
}

#[cfg(test)]
mod tests {
    use super::object_subobject_0x3c;

    #[test]
    fn returns_the_offset_subobject_without_dereferencing_it() {
        assert_eq!(unsafe { object_subobject_0x3c(core::ptr::null_mut()) }, 0x3cusize as *mut u8);
    }

    #[test]
    fn preserves_the_exact_byte_offset_for_aligned_and_unaligned_objects() {
        let mut storage = [0u8; 0x80];
        for offset in [0, 1, 3, 4] {
            let object = unsafe { storage.as_mut_ptr().add(offset) };
            assert_eq!(unsafe { object_subobject_0x3c(object) }, unsafe { object.add(0x3c) });
        }
    }
}
