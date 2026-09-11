//! `vtable_two_pair_derived_construct` — original: `FUN_081d0d98` @
//! **0x081d0d98** (20 bytes of ARM instructions, followed by its four-byte
//! literal-pool vtable word at 0x081d0dac).
//!
//! # Extent and reachability, binary-verified
//!
//! The raw ARM body is `push {r4,lr}; bl 0x0811050c; ldr r1,=0x0898dcb0;
//! str r1,[r0]; pop {r4,pc}` from 0x081d0d98 through 0x081d0da8. Its literal
//! pool word follows at 0x081d0dac; the next separately linked function
//! starts at 0x081d0db0. Decoding every ARM B/BL immediate in `osos.dec`
//! finds exactly ten inbound calls, all unconditional `bl` (0x08135c74,
//! 0x08135de8, 0x08136130, 0x0813634c, 0x0816c8f0, 0x0816c9d8, 0x08186f38,
//! 0x081dcb34, 0x081dcc20, 0x081dcd08). There are no predicated `bl`, tail
//! `b`, or aligned data-word references to the entry.
//!
//! # Algorithm
//!
//! Forward `this` and both pair-source registers to the already ported
//! [`super::vtable_two_pair_base_construct::vtable_two_pair_base_construct`],
//! then overwrite the base vtable at the pointer it returns with the derived
//! vtable literal `0x0898dcb0`, and return that pointer. The retail callers
//! pass only `this` deliberately; as with the base constructor, their `r1`
//! and `r2` pair-source values are stale caller registers. This ABI therefore
//! retains both explicit pair-source arguments despite Ghidra reporting none.
//!
//! # Deliberate deviations
//!
//! The port calls the existing direct base-constructor port instead of adding
//! a dispatch seam. The final volatile store preserves the decoded ordered
//! post-call vtable replacement.

use super::vtable_two_pair_base_construct::vtable_two_pair_base_construct;

/// Literal-pool vtable installed after the common two-pair base construction.
pub const DERIVED_VTABLE_ADDRESS: u32 = 0x0898_dcb0;

/// Constructs the derived two-pair vtable object and returns the base result.
///
/// # Safety
///
/// `this` and both source pairs carry the requirements of
/// [`vtable_two_pair_base_construct`]. The retail function has no null or
/// alignment guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_two_pair_derived_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_two_pair_derived_construct(
    this: *mut u8,
    src_pair_at_4: *const u8,
    src_pair_at_12: *const u8,
) -> *mut u8 {
    let base_result = unsafe {
        vtable_two_pair_base_construct(this, src_pair_at_4, src_pair_at_12)
    };
    unsafe { base_result.cast::<u32>().write_volatile(DERIVED_VTABLE_ADDRESS) };
    base_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::vtable_two_pair_base_construct::VTABLE_ADDRESS as BASE_VTABLE_ADDRESS;

    #[repr(C, align(4))]
    struct AlignedBytes([u8; 28]);

    unsafe fn word_at(bytes: *const u8, offset: usize) -> u32 {
        unsafe { bytes.add(offset).cast::<u32>().read() }
    }

    #[test]
    fn constructs_pairs_then_replaces_the_base_vtable() {
        let mut storage = AlignedBytes([0xa5; 28]);
        let object = storage.0.as_mut_ptr().wrapping_add(4);
        let pair_at_4: [u32; 2] = [0xdead_beef, 0x0bad_f00d];
        let pair_at_12: [u32; 2] = [0x1234_5678, 0x9abc_def0];

        let returned = unsafe {
            vtable_two_pair_derived_construct(
                object,
                pair_at_4.as_ptr().cast(),
                pair_at_12.as_ptr().cast(),
            )
        };

        assert_eq!(returned, object);
        assert_eq!(unsafe { word_at(object, 0) }, DERIVED_VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(object, 4) }, 0xdead_beef);
        assert_eq!(unsafe { word_at(object, 8) }, 0x0bad_f00d);
        assert_eq!(unsafe { word_at(object, 12) }, 0x1234_5678);
        assert_eq!(unsafe { word_at(object, 16) }, 0x9abc_def0);
        assert_eq!(&storage.0[..4], &[0xa5; 4]);
        assert_eq!(&storage.0[24..], &[0xa5; 4]);
    }

    #[test]
    fn forwards_aliasing_pair_sources_before_replacing_vtable() {
        // The base writes its vtable before loading pair_at_4. Pair_at_12 then
        // aliases that copied result; this wrapper replaces only word zero.
        let mut storage = AlignedBytes([0x3c; 28]);
        let object = storage.0.as_mut_ptr().wrapping_add(4);

        unsafe {
            vtable_two_pair_derived_construct(object, storage.0.as_ptr(), object.add(4))
        };

        assert_eq!(unsafe { word_at(object, 0) }, DERIVED_VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(object, 4) }, 0x3c3c_3c3c);
        assert_eq!(unsafe { word_at(object, 8) }, BASE_VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(object, 12) }, 0x3c3c_3c3c);
        assert_eq!(unsafe { word_at(object, 16) }, BASE_VTABLE_ADDRESS);
    }
}
