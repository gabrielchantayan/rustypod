//! `state_object_destroy` — original: `FUN_08076920` @ 0x08076920 (4 bytes).
//!
//! Raw ARM confirms this is exactly one `bx lr` (the word 0xe12fff1e): the
//! preceding function's code ends at 0x0807691c and the next separately
//! linked function — the object-init helper @ 0x08076924 — starts right
//! after. Not a veneer: the body contains neither `ldr pc, [pc, #-4]` nor
//! a branch target. Ghidra's 4-byte extent is correct.
//!
//! ## What it destroys
//!
//! The empty destructor of the 0x20-byte state-machine base subobject
//! initialized by the helper @ 0x08076924, whose layout is:
//!
//! ```text
//! +0x00 u32  link field, zeroed
//! +0x04 u32  zeroed
//! +0x08 u32  zeroed
//! +0x0c u32  class-descriptor word (ctor argument r1)
//! +0x10 u32  init argument (ctor argument r2)
//! +0x14 u32  zeroed (ctor argument r3, always 0 at the timer ctor)
//! +0x18 u32  state FourCC, initialized to 'stop' (0x73746f70)
//! +0x1c u32  zeroed
//! ```
//!
//! The timer class embeds this subobject at offset 0: its constructor @
//! 0x0812c65c calls the init helper with the class descriptor from
//! 0x089cb26c, then layers its own state FourCC at +0x20. Many other
//! classes embed the same base further in.
//!
//! ## Call-site evidence
//!
//! Decoding every ARM B/BL word in `osos.dec`: **22 `bl` call sites, 0
//! predicated forms, 0 plain-`b` tail calls**, and the address occurs in
//! **no image data word** — statically bound everywhere, never through a
//! vtable. Every site is a base-object destructor running member cleanup:
//! the `bl` is immediately preceded by `add r0, r<base>, #offset` (offsets
//! observed: 0x8, 0x14, 0x1c, 0x28, 0x48, 0x4c, 0x60, 0x64, 0x98, 0x114,
//! 0x238) and followed either by the `add` for the next member or by
//! `mov r0, r4/r5` restoring the base pointer. r0 is dead after the call
//! at all 22 sites — no caller chains this destructor into
//! `operator_delete` (0x082aad24) with the pointer live.
//!
//! Algorithm: read and write nothing, then return `this` unchanged in r0
//! (that is what `bx lr` leaves behind, and the crate's other empty
//! destructor ports keep the same pass-through contract). Deliberate
//! deviations: none. A separate text section prevents identical-code
//! folding with `empty_destructor` (0x0826fc64) and `trivial_destructor`
//! (0x082646ac), which share this body.

use core::ffi::c_void;

/// state_object_destroy — original: `FUN_08076920` @ 0x08076920 (4 bytes;
/// 22 `bl` call sites, 0 `b`, binary-scanned over the whole image).
///
/// Destroys the state-machine base subobject, which owns no resource, and
/// hands the same pointer back in r0. It reads and writes nothing, so
/// `this` may be NULL, unaligned, or dangling.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.state_object_destroy")]
#[inline(never)]
pub unsafe extern "C" fn state_object_destroy(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_this_in_r0() {
        for address in [0usize, 1, 0x0800_0001, 0x089c_b26c, usize::MAX] {
            let this = address as *mut c_void;
            assert_eq!(unsafe { state_object_destroy(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn touches_no_byte_of_the_subobject() {
        // The base subobject is 0x20 bytes; a timer embeds it at offset 0
        // inside a larger allocation, so use a full-size fixture.
        let mut object = [0xa5u8; 0x2c];
        let before = object;

        let returned = unsafe { state_object_destroy(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body performs no stores");
    }
}
