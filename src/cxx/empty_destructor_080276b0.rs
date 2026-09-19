//! `empty_destructor_080276b0` — original: `FUN_080276b0` @ 0x080276b0
//! (4 bytes).
//!
//! Raw `osos.dec` confirms the exact extent is 0x080276b0..0x080276b4: it is
//! one `bx lr` (`0xe12fff1e`), after the separately linked `FUN_080276ac` and
//! before `FUN_080276b4`. It is an empty C++ destructor, not a veneer: it
//! contains neither `ldr pc,[pc,#-4]` nor a branch target.
//!
//! Decoding every immediate ARM B/BL word in the complete decrypted image
//! finds exactly four inbound calls, all unconditional plain `bl` at
//! 0x082f8eb0, 0x082fa874, 0x0831317c, and 0x08332948. There are no predicated
//! `bl` forms or direct `b` tail calls. Every caller passes a stack object and
//! does not consume the returned `r0`; no aligned image data word equals this
//! address, so it is statically bound, rather than vtable-dispatched.
//!
//! Algorithm: read and write nothing, then return the incoming object address
//! unchanged in `r0`. Deliberate deviations: none. A dedicated section keeps
//! this hook target distinct from other byte-identical empty destructors.

use core::ffi::c_void;

/// Performs no destruction work and preserves `object` in `r0`.
///
/// The original dereferences nothing, so `object` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_080276b0")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_080276b0(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_object_address() {
        for address in [0usize, 1, 0x0800_0001, 0x0802_76b0, usize::MAX] {
            let object = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_080276b0(object) }, object, "{address:#x}");
        }
    }

    #[test]
    fn writes_no_byte_of_the_object() {
        let mut object = [0xa5u8; 0x20];
        let before = object;

        let returned = unsafe { empty_destructor_080276b0(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the one-instruction body performs no stores");
    }
}
