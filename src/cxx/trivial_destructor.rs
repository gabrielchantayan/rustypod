//! `trivial_destructor` — original: `FUN_082646ac` @ 0x082646ac (4 bytes).
//!
//! A statically bound shared **empty destructor body**: one instruction, `bx
//! lr`. Binary-verified from `work/firmware/osos.dec` rather than from
//! Ghidra, because a 4-byte "function" is usually a mis-sized veneer. It is
//! not one:
//!
//! ```text
//! 08264694  ldr r1, [pc, #12]        @ tail of the ctor @ 0x0826467c
//! 08264698  mov r0, r4
//! 0826469c  bl  0x08264518
//! 082646a0  mov r0, r4
//! 082646a4  pop {r4, pc}
//! 082646a8  .word 0x08a77c3c         @ that ctor's literal pool
//! 082646ac  bx  lr                   @ <- the whole function
//! 082646b0  mov r1, #0               @ the next function starts here
//! ```
//!
//! There is no `ldr pc, [pc, #-4]` and no `b`, so the extent really is four
//! bytes with no trailing literal word: Ghidra's size is right for once.
//!
//! ## Why it is a destructor
//!
//! Scanning every B/BL word in the decrypted image: **112 `bl` call sites,
//! 0 `b`**, and **0 occurrences of 0x082646ac as a data word**, so it is
//! never reached through a virtual table — every caller binds it statically,
//! which is what a compiler does for a known-type destructor. The call sites
//! come in exactly two destructor shapes:
//!
//! - 79 sites are `add r0, sp, #N` immediately followed by the `bl` — the
//!   end-of-scope destruction of a stack temporary.
//! - 24 sites are `bl 0x082646ac` immediately followed by `bl 0x082aad24`
//!   (`operator_delete`, ported in `heap/veneers.rs`), the standard
//!   destroy-then-free pair. `names.yaml` already records one of them from
//!   the other side: the view destructor @ 0x0819ba64 disposes of its
//!   +0x220 drawable with "0x082646ac then operator delete".
//!
//! The remaining sites are the same two shapes with the object pointer
//! materialized a few instructions earlier.
//!
//! ## The one load-bearing detail: r0 passes through
//!
//! `bx lr` leaves r0 untouched, so the function returns its argument. That
//! is not cosmetic — in the destroy-then-free shape the following
//! `bl operator_delete` takes the pointer *in r0 as this function left it*,
//! for example at 0x081023d0:
//!
//! ```text
//! ldr r0, [r0, #0xa8]
//! cmp r0, #0
//! beq 0x081023d8
//! bl  0x082646ac            @ r0 must survive
//! bl  0x082aad24            @ operator_delete(r0)
//! ```
//!
//! A `void` port would compile to the same `bx lr` today but would document
//! the wrong contract, so the signature returns `this`.
//!
//! Deviations: none. The port is behaviorally the identity function.

use core::ffi::c_void;

/// trivial_destructor — original: `FUN_082646ac` @ 0x082646ac (4 bytes;
/// 112 `bl` call sites, 0 `b`, binary-scanned over the whole image).
///
/// Destroys an object that needs no cleanup and hands the same pointer
/// back in r0 for a chained `operator_delete`. It reads and writes
/// nothing, so `this` may be NULL, unaligned, or dangling.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn trivial_destructor(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_object_pointer_survives_for_a_chained_operator_delete() {
        for object in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let this = object as *mut c_void;
            assert_eq!(unsafe { trivial_destructor(this) }, this, "{object:#x}");
        }
    }

    #[test]
    fn no_byte_of_the_destroyed_object_is_written() {
        let mut object = [0xa5u8; 0x30];
        let before = object;

        let returned = unsafe { trivial_destructor(object.as_mut_ptr().cast()) };

        assert_eq!(returned, object.as_mut_ptr().cast::<c_void>());
        assert_eq!(object, before, "the empty body touches no memory");
    }
}
