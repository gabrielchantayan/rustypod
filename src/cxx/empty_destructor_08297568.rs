//! `empty_destructor_08297568` — original: `FUN_08297568` @ 0x08297568 (4 bytes).
//!
//! Raw ARM establishes the exact extent: `bx lr` at 0x08297568, following the
//! preceding function's return at 0x08297560 and literal-pool word at
//! 0x08297564; the next separately linked function begins at 0x0829756c.
//! Decoding aligned ARM branch-immediate words in `osos.dec` finds five
//! unconditional plain `bl` inbound calls and no predicated `bl` calls.
//!
//! Algorithm: read and write nothing, then return `this` unchanged. The
//! callers destroy stack-backed four-word stream state after consuming it, but
//! the firmware body has no data reference or virtual dispatch, so no stronger
//! type identity is asserted. Deliberate deviation: LLVM emits a frame
//! prologue/epilogue rather than the stock single `bx lr`; it preserves r0 and
//! has the same observable behavior.

use core::ffi::c_void;

/// Performs no destruction work and preserves `this` in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_08297568")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_08297568(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_all_pointer_values() {
        for address in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_08297568(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn touches_no_byte_of_the_object() {
        let mut object = [0xa5u8; 16];
        let before = object;

        let returned = unsafe { empty_destructor_08297568(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
