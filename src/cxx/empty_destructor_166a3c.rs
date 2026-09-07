//! `empty_destructor_166a3c` — original: `FUN_08166a3c` @ 0x08166a3c (4 bytes).
//!
//! A second statically bound empty C++ destructor body: one instruction,
//! `bx lr`. Raw bytes confirm there is no veneer or branch target here, so the
//! function reads and writes nothing and simply returns with r0 unchanged.
//!
//! Decoding every ARM B/BL word in `osos.dec` finds 21 direct call sites: all
//! are unconditional plain `bl`, with no predicated `bl` forms and no plain-B
//! tail calls. The calls all pass an object pointer in r0 and discard the
//! result, which matches a destructor that owns nothing. The body is therefore
//! behaviorally identical to the other empty destructor export at
//! 0x0826fc64.
//!
//! Algorithm: read and write nothing, then return `this` unchanged. Deliberate
//! deviations: a separate text section keeps this alias distinct from the other
//! empty destructor export so LLVM does not merge the symbols.

use core::ffi::c_void;

/// Performs no destruction work and returns `this` unchanged in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_166a3c")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_166a3c(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_the_following_operator_delete() {
        for address in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_166a3c(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn touches_no_byte_of_the_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor_166a3c(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
