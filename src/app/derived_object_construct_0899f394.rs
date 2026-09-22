//! `derived_object_construct_0899f394` — original: `FUN_0822434c` @
//! 0x0822434c (20 bytes, 0x0822434c..0x08224360). The literal-pool word is at
//! 0x08224360; the next real function starts at 0x08224364. Raw A32 decoding
//! finds **one unconditional plain `bl`** (`0x08224350 -> 0x081d6380`) and no
//! predicated `bl` instructions. The image contains three incoming plain `bl`
//! call sites and no predicated incoming calls.
//!
//! # Algorithm
//!
//! Forwards the three constructor registers to the base constructor at
//! 0x081d6380, then replaces the returned object's first word with the
//! otherwise unnamed derived vtable 0x0899f394 and returns that pointer.
//!
//! # Deliberate deviations
//!
//! The base constructor has no recovered semantic identity. This port reuses
//! `derived_object_construct`'s verified target-address call and host seam.
//! The ARM `str` is a volatile word write so LLVM cannot elide the externally
//! visible vtable installation.

pub const DERIVED_OBJECT_VTABLE_0899F394: u32 = 0x0899_f394;

/// Constructs the derived object with vtable `0x0899f394` in caller-provided storage.
///
/// # Safety
/// The base constructor's returned pointer must designate a writable,
/// word-aligned first word. The retail code performs no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn derived_object_construct_0899f394(
    storage: *mut u32,
    first: u32,
    second: u32,
) -> *mut u32 {
    let object = crate::app::derived_object_construct::base_construct(storage, first, second);
    object.write_volatile(DERIVED_OBJECT_VTABLE_0899F394);
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::derived_object_construct::{missing_base_construct, BaseConstruct, BASE_CONSTRUCT};
    use core::ptr;

    static mut SEEN: (*mut u32, u32, u32) = (ptr::null_mut(), 0, 0);
    static mut RETURNED: *mut u32 = ptr::null_mut();

    unsafe extern "C" fn recording_base_construct(storage: *mut u32, first: u32, second: u32) -> *mut u32 {
        SEEN = (storage, first, second);
        RETURNED
    }

    #[test]
    fn forwards_constructor_registers_and_installs_vtable_on_returned_object() {
        let _guard = crate::testing::BASE_CONSTRUCT_TEST_LOCK.lock();
        let mut storage = [0x1111_1111u32; 2];
        let mut returned = [0x2222_2222u32; 2];

        unsafe {
            SEEN = (ptr::null_mut(), 0, 0);
            RETURNED = returned.as_mut_ptr();
            BASE_CONSTRUCT = recording_base_construct as BaseConstruct;

            let result = derived_object_construct_0899f394(storage.as_mut_ptr(), 0x1234_5678, 0x9abc_def0);

            assert_eq!(result, returned.as_mut_ptr());
            assert_eq!(SEEN, (storage.as_mut_ptr(), 0x1234_5678, 0x9abc_def0));
            assert_eq!(storage, [0x1111_1111, 0x1111_1111]);
            assert_eq!(returned, [DERIVED_OBJECT_VTABLE_0899F394, 0x2222_2222]);

            BASE_CONSTRUCT = missing_base_construct;
            RETURNED = ptr::null_mut();
        }
    }
}
