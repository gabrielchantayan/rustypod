//! C++ guard-release literal veneer — `FUN_080036f0` @ 0x080036f0.
//!
//! Raw ARM:
//!
//! ```text
//! 080036f0  ldr pc, [pc, #-4]
//! 080036f4  .word 0x082a0460
//! ```
//!
//! The true extent is eight bytes: the literal is part of the veneer and the
//! next independently callable literal veneer starts at 0x080036f8. Decoding
//! all direct ARM branch-with-link instructions in `osos.dec` finds five
//! callers, all plain `bl`; no predicated `bl` reaches this address.
//!
//! The veneer changes no register and retains LR, tail-branching to its retail
//! target at 0x082a0460. All five callers use it as the C++ static-initializer
//! guard-release edge, immediately after a constructor and destructor
//! registration. ARM builds retain its exact instruction and literal. The
//! target is not a Rust ABI seam, so host builds deliberately dispatch to the
//! already ported no-op guard release rather than attempting to map or call the
//! raw target.

/// Fixed ARM instruction at 0x080036f0: `ldr pc, [pc, #-4]`.
pub const CXA_GUARD_RELEASE_VENEER_INSN: u32 = 0xe51f_f004;

/// Literal tail target at 0x080036f4.
pub const CXA_GUARD_RELEASE_VENEER_TARGET: u32 = 0x082a_0460;

#[cfg(target_arch = "arm")]
extern "C" {
    /// cxa_guard_release_veneer — original: `FUN_080036f0` @ 0x080036f0.
    pub fn cxa_guard_release_veneer(guard: *mut u32);
}

/// Host-only semantic counterpart for the guard-release call sites.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxa_guard_release_veneer(guard: *mut u32) {
    crate::runtime::cxa_guard::cxa_guard_release(guard);
}

// `ldr pc` preserves LR and all general registers while transferring directly
// to the literal target; a Rust wrapper would not preserve that ABI.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl cxa_guard_release_veneer
    .type cxa_guard_release_veneer, %function
cxa_guard_release_veneer:
    ldr     pc, [pc, #-4]
    .word   0x082a0460
    .size cxa_guard_release_veneer, . - cxa_guard_release_veneer
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veneer_words_match_the_retail_literal_dispatch() {
        assert_eq!(CXA_GUARD_RELEASE_VENEER_INSN, 0xe51f_f004);
        assert_eq!(CXA_GUARD_RELEASE_VENEER_TARGET, 0x082a_0460);
    }

    #[cfg(not(target_arch = "arm"))]
    #[test]
    fn host_guard_release_preserves_the_published_guard() {
        let mut guard = 1u32;
        unsafe { cxa_guard_release_veneer(&mut guard) };
        assert_eq!(guard, 1);
    }
}
