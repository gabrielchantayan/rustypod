//! `empty_destructor_1d85d4` — original: `FUN_081d85d4` @ 0x081d85d4 (4 bytes).
//!
//! Raw `osos.dec` confirms the exact extent is 0x081d85d4..0x081d85d8: its
//! sole instruction is `bx lr` (`0xe12fff1e`). The next distinct function
//! begins at 0x081d85d8 with `ldr r0,[r0,#0xc]`; this is neither a veneer nor
//! a branch. Decoding every A32 B/BL word finds five direct call sites, all
//! unconditional plain `bl` forms, with no predicated calls: 0x081c2344,
//! 0x081c2b64, 0x081c3274, 0x081c4074, and 0x081c7e58.
//!
//! Algorithm: read and write nothing, then return `this` unchanged. Deliberate
//! deviations: none. A dedicated text section prevents LLVM identical-code
//! folding with other hookable empty destructor exports.

use core::ffi::c_void;

/// Performs no destruction work and returns `this` unchanged in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_1d85d4")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_1d85d4(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_callers_that_continue_after_destruction() {
        for address in [0usize, 1, 0x0800_0001, 0x081c_2344, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_1d85d4(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn touches_no_byte_of_the_destroyed_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor_1d85d4(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
