//! `vtable_object_construct_with_text_buffer` — original: `FUN_0818cab4` @
//! 0x0818cab4 (60 bytes, 0x0818cab4..0x0818caec).
//!
//! # Extent and call count, binary-verified
//!
//! Raw A32 decoding starts with `push {r4,lr}` at 0x0818cab4 and ends with
//! `pop {r4,pc}` at 0x0818cae8; 0x0818caec is the literal-pool word and
//! `cmp r0,#0` at 0x0818caf0 starts the next real function. The body has two
//! unconditional direct `bl` instructions (`0x0818cab8 -> 0x081d6380` and
//! `0x0818cac8 -> 0x08186380`) and no predicated `bl`. A whole-image decode
//! finds three incoming plain `bl` sites (0x081d6148, 0x081f1af8, and
//! 0x08267c5c), with no predicated incoming `bl` forms.
//!
//! # Algorithm
//!
//! Construct the 28-byte vtable-backed base, replace its vtable with the
//! 0x08989a40 literal, construct a 50-byte text buffer at +28, then clear the
//! word at +40, byte at +44, and words at +48, +52, and +56. The text-buffer
//! constructor's returned pointer is the base for the trailing stores, as in
//! the ARM post-indexed sequence.
//!
//! # Deliberate deviations
//!
//! On ARM this calls the existing text-buffer port directly. Host pointers are
//! wider than the target's four-byte text-buffer pointer fields, so host builds
//! model only the target-layout writes made before the text buffer's allocator
//! boundary; this permits byte-accurate fixture tests without imposing host
//! pointer offsets on the firmware object.

use crate::cxx::vtable_object_base_construct::vtable_object_base_construct;
#[cfg(target_os = "none")]
use crate::cxx::text_buffer::{text_buffer_construct_with_capacity, TextBuffer};

/// The literal-pool vtable installed after the base constructor.
pub const VTABLE_ADDRESS: u32 = 0x0898_9a40;

#[cfg(not(target_os = "none"))]
unsafe fn construct_target_layout_text_buffer(buffer: *mut u8) -> *mut u8 {
    buffer.cast::<u32>().write_volatile(0x0898_96bc);
    buffer.add(4).cast::<u32>().write_volatile(0);
    buffer.add(8).cast::<u32>().write_volatile(0);
    buffer
}

/// Constructs the 60-byte vtable-backed object with its embedded text buffer.
///
/// # Safety
///
/// `this` must point to at least 60 writable bytes and be four-byte aligned.
/// The original dereferences it and both direct callees without null or bounds
/// checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_object_construct_with_text_buffer")]
#[inline(never)]
pub unsafe extern "C" fn vtable_object_construct_with_text_buffer(
    this: *mut u8,
    input_at_8: u32,
    input_at_12: u32,
) -> *mut u8 {
    let object = vtable_object_base_construct(this, input_at_8, input_at_12);
    object.cast::<u32>().write_volatile(VTABLE_ADDRESS);

    #[cfg(target_os = "none")]
    let text_buffer = text_buffer_construct_with_capacity(object.add(28).cast::<TextBuffer>(), 50)
        .cast::<u8>();
    #[cfg(not(target_os = "none"))]
    let text_buffer = construct_target_layout_text_buffer(object.add(28));

    let object = text_buffer.sub(28);
    object.add(40).cast::<u32>().write_volatile(0);
    object.add(44).write_volatile(0);
    object.add(48).cast::<u32>().write_volatile(0);
    object.add(52).cast::<u32>().write_volatile(0);
    object.add(56).cast::<u32>().write_volatile(0);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct AlignedBytes([u8; 68]);

    unsafe fn word_at(bytes: *const u8, offset: usize) -> u32 {
        unsafe { bytes.add(offset).cast::<u32>().read() }
    }

    #[test]
    fn constructs_target_layout_and_preserves_base_inputs() {
        let mut storage = AlignedBytes([0xa5; 68]);
        let object = unsafe { storage.0.as_mut_ptr().add(4) };
        let returned = unsafe {
            vtable_object_construct_with_text_buffer(object, 0xfeed_face, 0x89ab_cdef)
        };

        assert_eq!(returned, object);
        assert_eq!(unsafe { word_at(object, 0) }, VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(object, 4) }, 0);
        assert_eq!(unsafe { word_at(object, 8) }, 0xfeed_face);
        assert_eq!(unsafe { word_at(object, 12) }, 0x89ab_cdef);
        assert_eq!(unsafe { object.add(16).read() }, 0);
        assert_eq!(unsafe { word_at(object, 20) }, 0);
        assert_eq!(unsafe { word_at(object, 24) }, 0);
        assert_eq!(unsafe { word_at(object, 28) }, 0x0898_96bc);
        assert_eq!(unsafe { word_at(object, 32) }, 0);
        assert_eq!(unsafe { word_at(object, 36) }, 0);
        assert_eq!(unsafe { word_at(object, 40) }, 0);
        assert_eq!(unsafe { object.add(44).read() }, 0);
        assert_eq!(unsafe { word_at(object, 48) }, 0);
        assert_eq!(unsafe { word_at(object, 52) }, 0);
        assert_eq!(unsafe { word_at(object, 56) }, 0);
    }

    #[test]
    fn preserves_padding_and_neighbouring_bytes() {
        let mut storage = AlignedBytes([0x3c; 68]);
        let object = unsafe { storage.0.as_mut_ptr().add(4) };
        unsafe { vtable_object_construct_with_text_buffer(object, 1, 2) };

        assert_eq!(&storage.0[..4], &[0x3c; 4]);
        assert_eq!(&storage.0[21..24], &[0x3c; 3]);
        assert_eq!(&storage.0[64..], &[0x3c; 4]);
    }
}
