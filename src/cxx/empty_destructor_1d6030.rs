//! `empty_destructor_1d6030` — original: `FUN_081d6030` @ 0x081d6030 (4 bytes).
//!
//! Raw `osos.dec` confirms the exact extent is 0x081d6030..0x081d6034: the
//! preceding function ends at 0x081d6030 and the distinct next function begins
//! at 0x081d6034 with `push {r4, r5, r6, lr}`. The lone instruction is `bx lr`
//! (`0xe12fff1e`), not an `ldr pc, [pc, #-4]` veneer or a branch.
//!
//! Decoding every A32 B/BL word in `osos.dec` finds exactly six direct call
//! sites, all unconditional plain `bl` forms (no predicated calls and no
//! plain-B tail calls): 0x081b7e2c, 0x081cd2cc, 0x081fd0dc, 0x0820a560,
//! 0x0822028c, and 0x0822bb2c. No aligned image word equals 0x081d6030, so no
//! static vtable dispatch reaches this entry. The caller at 0x081fd0dc uses r0
//! to recover its enclosing object, proving that the `this` value must pass
//! through despite Ghidra's void prototype.
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
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_1d6030")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_1d6030(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_for_enclosing_object_recovery() {
        for address in [0usize, 1, 0x0800_0001, 0x081f_d0dc, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_1d6030(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn touches_no_byte_of_the_destroyed_object() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { empty_destructor_1d6030(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
