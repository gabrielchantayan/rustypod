//! `empty_destructor_2a1e98` — original: `FUN_082a1e98` @ `0x082a1e98` (4 bytes).
//!
//! Raw `osos.dec` contains only `bx lr` (`0xe12fff1e`); the next independently
//! linked function begins at `0x082a1e9c` with `add r0, r0, #0x1c`, confirming
//! the four-byte extent. Decoding every ARM `B`/`BL` word in the image finds
//! three direct callers (`0x0807a4bc`, `0x0807a4d4`, and `0x08296920`), all
//! unconditional `bl` instructions; there are no predicated `bl` calls.
//!
//! The callers pass result objects in r0 and immediately call adjacent result
//! accessors, so this is a statically bound empty C++ destructor despite
//! Ghidra's `void` prototype. Algorithm: read and write nothing, then return
//! `this` unchanged. Deliberate deviations: none. A target-only text section
//! prevents LLVM from folding this hookable identity with another empty
//! destructor export.

use core::ffi::c_void;

/// Performs no destruction work and returns `this` unchanged in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_2a1e98")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_2a1e98(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_all_pointer_bit_patterns() {
        for address in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_2a1e98(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn does_not_write_the_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor_2a1e98(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
