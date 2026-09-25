//! `empty_destructor_080276b4` — original: `FUN_080276b4` @ 0x080276b4
//! (4 bytes).
//!
//! Raw `osos.dec` confirms the exact extent is 0x080276b4..0x080276b8: it is
//! one `bx lr` (`0xe12fff1e`), after the separately linked `FUN_080276b0` and
//! before `FUN_080276b8`. It is an empty C++ destructor, not a veneer: it
//! contains neither `ldr pc,[pc,#-4]` nor a branch target.
//!
//! Decoding every immediate ARM B/BL word in the complete decrypted image
//! finds exactly three inbound calls, all unconditional plain `bl` at
//! 0x082fc11c, 0x083436b0, and 0x0834849c. There are no predicated `bl` forms
//! or direct `b` tail calls. The raw instruction preserves `r0`.
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
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_080276b4")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_080276b4(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_object_address() {
        for address in [0usize, 1, 0x0800_0001, 0x0802_76b4, usize::MAX] {
            let object = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_080276b4(object) }, object, "{address:#x}");
        }
    }

    #[test]
    fn writes_no_byte_of_the_object() {
        let mut object = [0xa5u8; 0x20];
        let before = object;

        let returned = unsafe { empty_destructor_080276b4(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the one-instruction body performs no stores");
    }
}
