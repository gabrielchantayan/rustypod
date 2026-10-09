//! Descriptor/vector owner constructor — `FUN_08104ad8` @ `0x08104ad8`.
//! True extent: 68 bytes through the next function at 0x08104b1c: 64 bytes
//! of instructions and the vtable literal at 0x08104b18. Raw A32 decoding
//! finds two inbound plain BLs (0x08162b50, 0x08280ec8), no predicated BLs;
//! the body has two plain BLs and no predicated BLs.
//!
//! Install vtable 0x08980a18, clear the vector head at +4/+8/+12, clear
//! state word +48 and flag byte +52, then forward-copy the 32-byte descriptor
//! to +16 and return the original object. Bytes +53..+55 are untouched.
//! Deliberate deviations: reuse the existing clear and IRAM-copy ports;
//! recover the object from the input rather than the clear helper's unchanged
//! r0 (its Rust signature returns void). Omit unused r2/r3 and the unused
//! stack argument passed to that helper. No broader class identity inferred.

use super::three_word_clear_tenth::three_word_clear_tenth;
use crate::libc::iram_veneers::iram_memcpy_veneer;

pub const DESCRIPTOR_VECTOR_OWNER_VTABLE_ADDRESS: u32 = 0x0898_0a18;

/// # Safety
/// `object` must be aligned and writable for 53 bytes; `descriptor` must be
/// word-aligned and readable for 32 bytes. Overlap follows the existing ADS
/// forward-copy routine, including constructor writes preceding the copy.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn descriptor_vector_owner_construct(
    object: *mut u8,
    descriptor: *const u8,
) -> *mut u8 {
    unsafe {
        object.cast::<u32>().write(DESCRIPTOR_VECTOR_OWNER_VTABLE_ADDRESS);
        three_word_clear_tenth(object.cast::<u32>().add(1));
        object.cast::<u32>().add(12).write(0);
        object.add(52).write(0);
        iram_memcpy_veneer(object.add(16), descriptor, 32);
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_descriptor_and_preserves_padding_and_guards() {
        for descriptor in [[0u32; 8], [u32::MAX; 8],
            [0, 1, 0x8000_0000, 0x1234_5678, 4, 5, 6, 7]] {
            let mut words = [0xa5a5_a5a5u32; 16];
            let object = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
            assert_eq!(unsafe {
                descriptor_vector_owner_construct(object, descriptor.as_ptr().cast())
            }, object);
            assert_eq!(words[0], 0xa5a5_a5a5);
            assert_eq!(&words[1..5], &[DESCRIPTOR_VECTOR_OWNER_VTABLE_ADDRESS, 0, 0, 0]);
            assert_eq!(&words[5..13], &descriptor);
            assert_eq!(words[13], 0);
            assert_eq!(words[14].to_ne_bytes(), [0, 0xa5, 0xa5, 0xa5]);
            assert_eq!(words[15], 0xa5a5_a5a5);
        }
    }

    #[test]
    fn aliased_descriptor_observes_initialization_and_forward_block_order() {
        let mut words = [0x1111_1111u32; 14];
        words[4..8].copy_from_slice(&[4, 5, 6, 7]);
        let object = words.as_mut_ptr().cast::<u8>();
        unsafe { descriptor_vector_owner_construct(object, object) };
        // The first 16-byte group copies the newly initialized prefix;
        // the second group loads those just-written descriptor words.
        assert_eq!(words, [DESCRIPTOR_VECTOR_OWNER_VTABLE_ADDRESS, 0, 0, 0,
            DESCRIPTOR_VECTOR_OWNER_VTABLE_ADDRESS, 0, 0, 0,
            DESCRIPTOR_VECTOR_OWNER_VTABLE_ADDRESS, 0, 0, 0,
            0, u32::from_ne_bytes([0, 0x11, 0x11, 0x11])]);
    }
}
