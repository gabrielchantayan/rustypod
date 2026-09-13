//! `empty_destructor_1f3ff0` — original: `FUN_081f3ff0` @ `0x081f3ff0` (4 bytes).
//!
//! Raw `osos.dec` contains only `bx lr` (`0xe12fff1e`); the next separately
//! linked function begins at `0x081f3ff4`, confirming the four-byte extent.
//!
//! Decoding every ARM B/BL instruction in the image finds six direct callers:
//! `0x08121160`, `0x0812118c`, `0x081e6030`, `0x081e606c`, `0x0820c738`, and
//! `0x0820c7b4`. Every direct caller is an unconditional `bl` (condition AL);
//! there are no predicated `bl` call sites or aligned raw word references to
//! the entry. Each caller destroys the single-byte iteration index constructed
//! by `FUN_081f3fe8`; none observes the preserved return register.
//!
//! Algorithm: read and write nothing, then return `this` unchanged. Deliberate
//! deviations: a target-only text section prevents LLVM from folding this
//! hookable identity with another empty destructor export.

use core::ffi::c_void;

/// Performs no destruction work and returns `this` unchanged in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_1f3ff0")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_1f3ff0(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_all_pointer_bit_patterns() {
        for address in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_1f3ff0(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn does_not_write_the_destroyed_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor_1f3ff0(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
