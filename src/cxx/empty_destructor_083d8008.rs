//! `empty_destructor_083d8008` — original: `FUN_083d8008` @ 0x083d8008
//! (4 bytes).
//!
//! Raw ARM confirms this is exactly one `mov pc, lr` (`0xe1a0f00e`), not a
//! veneer: the prior separately linked function ends with its tail branch at
//! 0x083d8004 and the next starts at 0x083d800c. The instruction neither
//! reads nor writes a register other than `pc`, so it returns the incoming
//! `r0` unchanged.
//!
//! Decoding every immediate ARM B/BL word in `osos.dec` finds exactly eight
//! inbound direct call sites, all unconditional plain `bl` at 0x08038e6c,
//! 0x08266dd4, 0x08266e10, 0x08266e78, 0x08266fcc, 0x082a7550, 0x082a7564,
//! and 0x083d7c38; there are no predicated forms or direct `b` tail calls.
//! All direct callers materialize a stack object and use the preserved `r0`
//! afterward, matching a statically bound empty C++ destructor. One image data
//! word at 0x0895e4bc equals this address, but its surrounding untyped data
//! does not establish the object's or table's identity.
//!
//! Algorithm: read and write nothing, then return `object` unchanged.
//! Deliberate deviations: none. Its own text section prevents LLVM from
//! folding this export into another identical empty destructor.

use core::ffi::c_void;

/// `empty_destructor_083d8008` — original: `FUN_083d8008` @ 0x083d8008
/// (4 bytes; 8 unconditional plain `bl` call sites, binary-scanned over the
/// complete decrypted image).
///
/// Performs no destruction work and returns `object` unchanged in `r0`.
/// The original dereferences nothing, so `object` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_083d8008")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_083d8008(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_object_for_the_caller_after_destruction() {
        for address in [0usize, 1, 0x0800_0001, 0x083d_8008, usize::MAX] {
            let object = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_083d8008(object) }, object, "{address:#x}");
        }
    }

    #[test]
    fn writes_no_byte_of_the_destroyed_object() {
        let mut object = [0xa5u8; 0x20];
        let before = object;

        let returned = unsafe { empty_destructor_083d8008(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the one-instruction body performs no stores");
    }
}
