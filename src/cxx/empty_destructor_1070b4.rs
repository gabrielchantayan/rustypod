//! `empty_destructor_1070b4` — original: `FUN_081070b4` @ 0x081070b4 (4 bytes).
//!
//! Raw ARM confirms this is exactly one `bx lr`. The preceding instruction at
//! 0x081070b0 is another separately linked `bx lr`, and the next function
//! starts at 0x081070b8 with `cmp r0, #0`; there is no literal-pool word,
//! `ldr pc, [pc, #-4]`, or branch target to conceal a veneer.
//!
//! Decoding every ARM B/BL word in `osos.dec` finds exactly 8 direct call
//! sites, all unconditional plain `bl` forms (no predicated calls and no
//! `b` tail calls): 0x08143444, 0x0814a968, 0x0814ab08, 0x081b7690,
//! 0x08224144, 0x0829df88, 0x082c8564, and 0x083d3c04. No aligned image word
//! equals 0x081070b4, so it is not reached from a virtual table. The final
//! caller invokes `operator_delete` immediately afterward, proving that `r0`
//! must pass through despite Ghidra's void prototype.
//!
//! Algorithm: read and write nothing, then return `this` unchanged.
//! Deliberate deviations: none. Its separate text section prevents LLVM from
//! folding this export into another byte-identical empty destructor.

use core::ffi::c_void;

/// Performs no destruction work and returns `this` unchanged in r0.
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_1070b4")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_1070b4(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_the_following_operator_delete() {
        for address in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_1070b4(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn touches_no_byte_of_the_destroyed_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor_1070b4(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
