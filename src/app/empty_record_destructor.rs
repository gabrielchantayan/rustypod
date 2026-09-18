//! `empty_record_destructor` — original: `FUN_08163b18` @ **0x08163b18**
//! (4 bytes).
//!
//! Raw `osos.dec` confirms the true extent: its sole word is `bx lr`
//! (`0xe12fff1e`) at 0x08163b18. The preceding function ends at 0x08163b14,
//! and the next separately linked function begins at 0x08163b1c with
//! `stmdb sp!, {r4-r11, lr}`. It is neither a literal-pool veneer nor a tail
//! branch. Decoding every ARM B/BL immediate finds exactly 4 direct callers,
//! all unconditional plain `bl` (0x0818fdbc, 0x08190578, 0x08190770, and
//! 0x081928a0); there are no predicated `bl` forms.
//!
//! Algorithm: accept the record object's first word in `r0`, access no memory,
//! and return that word unchanged in `r0`, so the immediately following
//! `operator_delete` call receives it. Deliberate deviations: none. A distinct
//! text section prevents LLVM from folding this real BL target with another
//! empty return export.

use core::ffi::c_void;

/// Returns the record object unchanged without destructing it.
///
/// The ARM body dereferences nothing, so `object` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_record_destructor")]
#[inline(never)]
pub unsafe extern "C" fn empty_record_destructor(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_object_word() {
        for object_word in [0usize, 1, 0x0800_0001, 0x08a2_55e4, usize::MAX] {
            let object = object_word as *mut c_void;
            assert_eq!(unsafe { empty_record_destructor(object) }, object, "object={object_word:#x}");
        }
    }

    #[test]
    fn does_not_access_object_memory() {
        let mut object = [0xa5u8; 32];
        let before = object;
        let returned = unsafe { empty_record_destructor(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the bare return writes no object byte");
    }
}
