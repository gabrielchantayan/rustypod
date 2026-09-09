//! `vtable_object_base_construct` — original: `FUN_081d6380` @ 0x081d6380
//! (40 bytes).
//!
//! # Extent and reachability, binary-verified
//!
//! The raw ARM body is ten words from 0x081d6380 through 0x081d63a4; the
//! literal-pool vtable word at 0x081d63a8 is part of the function. The next
//! separately linked function begins at 0x081d63ac. Decoding every ARM B/BL
//! word in `osos.dec` finds 14 direct call sites: all are unconditional `bl`;
//! there are no predicated calls, plain-`b` tail calls, or aligned data-word
//! references to 0x081d6380.
//!
//! # Algorithm
//!
//! Construct the 28-byte vtable-backed base object at `this`: install vtable
//! 0x0898e004, copy the two input words to offsets +8 and +12, clear the word
//! at +4, byte at +16, and words at +20 and +24, then return `this` unchanged.
//! Bytes +17 through +19 are deliberately preserved. No argument, null, or
//! alignment guard exists in the ARM body. Deliberate deviations: none.

/// The literal-pool vtable installed by the ARM constructor.
pub const VTABLE_ADDRESS: u32 = 0x0898_e004;

/// Constructs the common 28-byte vtable-backed base object and returns `this`.
///
/// # Safety
///
/// `this` must point to at least 28 writable bytes and be 4-byte aligned for
/// the word stores. The original dereferences it without a null check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_object_base_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_object_base_construct(
    this: *mut u8,
    input_at_8: u32,
    input_at_12: u32,
) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write_volatile(VTABLE_ADDRESS);
        this.add(8).cast::<u32>().write_volatile(input_at_8);
        this.add(12).cast::<u32>().write_volatile(input_at_12);
        this.add(4).cast::<u32>().write_volatile(0);
        this.add(16).write_volatile(0);
        this.add(20).cast::<u32>().write_volatile(0);
        this.add(24).cast::<u32>().write_volatile(0);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct AlignedBytes([u8; 36]);

    unsafe fn word_at(bytes: *const u8, offset: usize) -> u32 {
        unsafe { bytes.add(offset).cast::<u32>().read() }
    }

    #[test]
    fn initializes_all_fields_and_returns_the_same_object() {
        let mut storage = AlignedBytes([0xa5; 36]);
        let object = storage.0.as_mut_ptr().wrapping_add(4);

        let returned = unsafe {
            vtable_object_base_construct(object, 0xfeed_face, 0x89ab_cdef)
        };

        assert_eq!(returned, object);
        assert_eq!(unsafe { word_at(object, 0) }, VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(object, 4) }, 0);
        assert_eq!(unsafe { word_at(object, 8) }, 0xfeed_face);
        assert_eq!(unsafe { word_at(object, 12) }, 0x89ab_cdef);
        assert_eq!(unsafe { object.wrapping_add(16).read() }, 0);
        assert_eq!(unsafe { word_at(object, 20) }, 0);
        assert_eq!(unsafe { word_at(object, 24) }, 0);
    }

    #[test]
    fn preserves_byte_padding_and_neighbouring_memory() {
        let mut storage = AlignedBytes([0x3c; 36]);
        let object = storage.0.as_mut_ptr().wrapping_add(4);

        unsafe { vtable_object_base_construct(object, u32::MAX, 0x8000_0000) };

        assert_eq!(&storage.0[..4], &[0x3c; 4]);
        assert_eq!(&storage.0[21..24], &[0x3c; 3]);
        assert_eq!(&storage.0[32..], &[0x3c; 4]);
        assert_eq!(unsafe { word_at(object, 8) }, u32::MAX);
        assert_eq!(unsafe { word_at(object, 12) }, 0x8000_0000);
    }
}
