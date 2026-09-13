//! `empty_destructor_1e741c` — original: `thunk_FUN_08207688` @ 0x081e741c
//! (4 bytes).
//!
//! Raw ARM makes this a one-word tail veneer, not Ghidra's standalone void
//! function: `b 0x08207688` (`0xea008099`). Its target is itself the exact
//! one-word `bx lr` empty C++ destructor at 0x08207688. The following sibling
//! begins at 0x081e7420 with `cmp r1,#0`, fixing the veneer extent at four
//! bytes.
//!
//! Decoding every ARM B/BL word in `osos.dec` finds six direct callers, all
//! unconditional plain `bl` (0x0814c73c, 0x081682c8, 0x081a8014, 0x081ba814,
//! 0x08236268, and 0x0828c194); there are no predicated `bl` forms and no
//! plain-B tail callers. Each caller consumes r0 after the call — e.g.
//! 0x0814c740 subtracts four from it — so the target's `bx lr` pass-through
//! is part of the ABI despite Ghidra's void prototype. No aligned image word
//! contains 0x081e741c, so it has no static virtual-dispatch evidence.
//!
//! Algorithm: perform no reads or writes, then return `this` unchanged. The
//! port deliberately collapses the veneer branch and its empty target to the
//! identical direct return; this preserves the final registers and memory
//! state observable by every caller. Its dedicated text section keeps the
//! hook target distinct from other byte-identical empty-destructor exports.

use core::ffi::c_void;

/// Collapses the verified empty-destructor veneer while preserving `this` in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_1e741c")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_1e741c(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_edge_pointer_for_the_following_adjustment() {
        for address in [0usize, 1, 0x0800_0001, 0x0898_f1b4, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_1e741c(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn writes_no_byte_of_the_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor_1e741c(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty target body performs no stores");
    }
}
