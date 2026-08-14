//! `clock_source_destroy` — original: `FUN_08262908` @ 0x08262908
//! (4 bytes).
//!
//! One instruction, `bx lr` (the word 0xe12fff1e). Binary-verified from
//! `work/firmware/osos.dec` rather than trusted from Ghidra, because a
//! 4-byte "function" is usually a mis-sized veneer. It is not one — a
//! veneer is `ldr pc, [pc, #-4]` (0xe51ff004) plus a target word, or a
//! plain `b`:
//!
//! ```text
//! 082628f4  ldr  r2, [pc, #8]     @ the base constructor
//! 082628f8  str  r2, [r0]         @   this->vtable = <literal>
//! 082628fc  strb r1, [r0, #4]     @   this->flag   = kind
//! 08262900  bx   lr
//! 08262904  .word 0x089a80b0      @ that constructor's literal pool
//! 08262908  bx   lr               @ <- the whole function
//! 0826290c  b    0x082e8070       @ the next function (a real veneer)
//! ```
//!
//! So the extent really is four bytes with no trailing literal word.
//!
//! # Why it is the destructor of the object 0x082628f4 builds
//!
//! Decoding every B/BL word in the image: **45 `bl` call sites, 0 `b`,
//! 0 predicated forms**, and **0 occurrences of 0x08262908 as a data
//! word** — it is never reached through a vtable, so every caller binds
//! it statically, which is what a compiler does for a known-type
//! destructor.
//!
//! The call sites carry the pairing. Eighteen of them are literally
//! `add r0, sp, #N` / `bl 0x08262958` … `add r0, sp, #N` / `bl
//! 0x08262908` on the *same* stack slot — construct, use, destroy — and
//! two more pair the same way with the sibling constructor 0x08262a9c.
//! The rest are the same shape with the object pointer materialized a
//! few instructions earlier (`mov r0, r5`, `mov r0, r4`). No site is
//! followed by `operator delete`: every one of the 45 destroys a stack
//! temporary.
//!
//! Those two constructors are siblings over the base at 0x082628f4:
//!
//! ```text
//! 08262958  push {r4, lr} / mov r1, #1 / bl 0x082628f4
//!           ldr r1, [pc, #4] / str r1, [r0] / pop {r4, pc}
//! 08262a9c  push {r4, lr} / mov r1, #0 / bl 0x082628f4
//!           ldr r1, [pc, #4] / str r1, [r0] / pop {r4, pc}
//! ```
//!
//! i.e. one base class `{ vtable, u8 kind }`, two derived classes that
//! differ only by the `kind` byte and their own vtable, and one shared
//! empty destructor — this one. Nothing in the hierarchy owns storage,
//! so the body is empty in the original and stays empty here.
//!
//! # What the object is
//!
//! A clock. The canonical use, at 0x081944b4 and a dozen more:
//!
//! ```text
//! add r0, sp, #12 / bl 0x08262958      @ construct the clock
//! ldr r0, [sp, #12] / ldr r2, [r0, #12]
//! add r0, sp, #12 / add r1, sp, #4 / blx r2   @ read into a {sec, nsec}
//! add r0, sp, #4  / bl 0x082a1c30      @ -> milliseconds
//! add r0, sp, #12 / bl 0x08262908      @ destroy the clock
//! ```
//!
//! 0x082a1c30 is `sec * 1000 + nsec / 1000000` (it divides by the
//! literal 1000000 @ 0x082a1c58 through 0x08031568, then
//! `mla r0, #1000, sec, quotient`), and the reader at 0x08262ab8
//! subtracts two such pairs field by field. Callers use the difference
//! as an elapsed time — 0x081643cc compares it against 500. So the
//! `kind` byte selects which clock, and this is the destructor a scoped
//! clock reader needs but has nothing to do in.
//!
//! # The one load-bearing detail: r0 passes through
//!
//! `bx lr` leaves r0 untouched, so the function returns its argument —
//! the ADS convention for a destructor. No caller of *this* destructor
//! chains into `operator delete` today, but a `void` port would document
//! the wrong contract, so the signature returns `this`, matching
//! `cxx::trivial_destructor`.
//!
//! Deviations: none. The port is behaviorally the identity function. It
//! carries its own `link_section` because it compiles to bytes identical
//! to `cxx::trivial_destructor` @ 0x082646ac, and LLVM's
//! identical-code folding would otherwise collapse the two exports into
//! one — they are separate functions in the original and must stay
//! separately hookable.

use core::ffi::c_void;

/// clock_source_destroy — original: `FUN_08262908` @ 0x08262908
/// (4 bytes; 45 `bl` call sites, 0 `b`, 0 data-word references,
/// binary-scanned over the whole image).
///
/// Destroys the scoped clock object built by 0x08262958 / 0x08262a9c,
/// which needs no cleanup, and hands the same pointer back in r0. It
/// reads and writes nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.clock_source_destroy")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clock_source_destroy(this: *mut c_void) -> *mut c_void {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_object_pointer_survives_in_r0() {
        for object in [0usize, 1, 0x0826_2909, 0x089a_80d0, usize::MAX] {
            let this = object as *mut c_void;
            assert_eq!(unsafe { clock_source_destroy(this) }, this, "{object:#x}");
        }
    }

    #[test]
    fn no_byte_of_the_destroyed_clock_is_written() {
        // The object is `{ vtable, u8 kind }`; give it room to spare.
        let mut clock = [0xa5u8; 0x10];
        let before = clock;

        let returned = unsafe { clock_source_destroy(clock.as_mut_ptr().cast()) };

        assert_eq!(returned, clock.as_mut_ptr().cast::<c_void>());
        assert_eq!(clock, before, "the empty body touches no memory");
    }

    /// Both empty destructors agree on the pass-through contract; the
    /// `link_section` above is what keeps them separately hookable on
    /// the device, where a folded symbol would silently serve both
    /// hooks.
    #[test]
    fn it_agrees_with_the_other_empty_destructor_on_every_pointer() {
        for object in [0usize, 4, 0x0800_0001, usize::MAX] {
            let this = object as *mut c_void;
            assert_eq!(unsafe { clock_source_destroy(this) }, unsafe {
                crate::cxx::trivial_destructor::trivial_destructor(this)
            });
        }
    }
}
