//! `empty_destructor` — original: `FUN_0826fc64` @ 0x0826fc64 (4 bytes).
//!
//! Raw ARM confirms that this is exactly one `bx lr`: the preceding function's
//! literal-pool word is at 0x0826fc60 and the next separately linked function
//! starts at 0x0826fc68. It is an empty C++ destructor, not a veneer: the body
//! contains neither `ldr pc, [pc, #-4]` nor a branch target.
//!
//! Decoding every ARM B/BL word in `osos.dec` finds 25 direct call sites: all
//! are unconditional plain `bl`; there are no predicated `bl` forms and no
//! plain-B tail calls. The address occurs in no image data word, so callers
//! bind the destructor statically rather than through a vtable. In particular,
//! 0x083d4a70 calls it immediately before `operator_delete` at 0x082aad24;
//! `bx lr` preserves r0 for that delete call. The port therefore returns
//! `this` despite Ghidra's void prototype.
//!
//! Algorithm: read and write nothing, then return `this` unchanged. Deliberate
//! deviations: none. A separate text section prevents identical-code folding
//! with the other empty destructor ports.

use core::ffi::c_void;

/// Performs no destruction work and returns `this` unchanged in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_the_following_operator_delete() {
        for address in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn touches_no_byte_of_the_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
