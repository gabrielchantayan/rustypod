//! `empty_destructor_165bfc` — original: `FUN_08165bfc` @ 0x08165bfc (4 bytes).
//!
//! Raw `osos.dec` word `e12fff1e` is `bx lr`; the next real function starts at
//! 0x08165c00 with `mov r0, #0; bx lr`. Ghidra's four-byte extent is therefore
//! exact. Whole-image ARM B/BL decoding finds three direct inbound calls, all
//! unconditional plain `bl` (0x08054efc, 0x081500d0, 0x081500d8), and no
//! predicated `bl` form.
//!
//! Algorithm: read and write nothing, then return `this` unchanged in r0.
//! Deliberate deviation: a distinct text section keeps this independently
//! linked BL target from being folded with identical empty destructor bodies.

use core::ffi::c_void;

/// Performs no destruction work and preserves `this` in r0.
///
/// The retail instruction dereferences nothing, so `this` may be NULL,
/// unaligned, or dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_165bfc")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_165bfc(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_all_pointer_values() {
        for address in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_165bfc(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn does_not_modify_object_storage() {
        let mut object = [0xa5u8; 0x24];
        let before = object;

        let returned = unsafe { empty_destructor_165bfc(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the bare return performs no stores");
    }
}
