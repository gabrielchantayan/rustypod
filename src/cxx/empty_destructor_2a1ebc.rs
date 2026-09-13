//! `empty_destructor_2a1ebc` — original: `FUN_082a1ebc` @ `0x082a1ebc` (4 bytes).
//!
//! Raw `osos.dec` contains only `bx lr` (`0xe12fff1e`): the preceding
//! independently linked leaf ends at `0x082a1ebc`, and the next begins with
//! `ldr r0, [r0, #8]` at `0x082a1ec0`, confirming the four-byte extent.
//!
//! Decoding every ARM B/BL word in the image finds six direct callers:
//! `0x081042fc`, `0x08104308`, `0x08104328`, `0x08104344`, `0x08104624`, and
//! `0x08104708`. Every call is an unconditional `bl` (condition AL); there
//! are no predicated calls, tail branches, or aligned data-word references.
//! The callers pass object pointers in r0 and use the value left in r0, so the
//! leaf is a statically bound empty C++ destructor despite Ghidra's `void`
//! prototype.
//!
//! Algorithm: read and write nothing, then return `this` unchanged. Deliberate
//! deviations: none. A target-only text section prevents LLVM from folding
//! this hookable identity with another empty destructor export.

use core::ffi::c_void;

/// Performs no destruction work and returns `this` unchanged in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_2a1ebc")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_2a1ebc(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_all_pointer_bit_patterns() {
        for address in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_2a1ebc(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn does_not_write_the_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor_2a1ebc(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
