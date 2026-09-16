//! C++ guard-acquire literal veneer — `FUN_080036e0` @ 0x080036e0.
//!
//! Raw ARM:
//!
//! ```text
//! 080036e0  ldr pc, [pc, #-4]
//! 080036e4  .word 0x082a0444
//! ```
//!
//! The true extent is eight bytes: the literal is part of the veneer and the
//! next independently callable literal veneer starts at 0x080036e8. Decoding
//! every direct ARM branch-with-link instruction in `osos.dec` finds five
//! callers, all plain `bl`; no predicated `bl` reaches this address.
//!
//! Each caller passes a C++ static-initialization guard before constructing an
//! object, registering its destructor, and releasing the guard, identifying
//! the target as the ADS `__cxa_guard_acquire` entry. The veneer changes no
//! register and retains LR, tail-branching to its retail target at 0x082a0444.
//! ARM builds retain its exact instruction and literal. The target is not a
//! Rust ABI seam, so host builds deliberately dispatch to the ported
//! `cxa_guard_acquire` implementation.

/// Fixed ARM instruction at 0x080036e0: `ldr pc, [pc, #-4]`.
pub const CXA_GUARD_ACQUIRE_VENEER_INSN: u32 = 0xe51f_f004;

/// Literal tail target at 0x080036e4.
pub const CXA_GUARD_ACQUIRE_VENEER_TARGET: u32 = 0x082a_0444;

#[cfg(target_arch = "arm")]
extern "C" {
    /// cxa_guard_acquire_veneer — original: `FUN_080036e0` @ 0x080036e0.
    pub fn cxa_guard_acquire_veneer(guard: *mut u32) -> u32;
}

/// Host-only semantic counterpart for C++ static-initialization guards.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxa_guard_acquire_veneer(guard: *mut u32) -> u32 {
    crate::runtime::cxa_guard::cxa_guard_acquire(guard)
}

// `ldr pc` preserves LR and all general registers while transferring directly
// to the literal target; a Rust wrapper would not preserve that ABI.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl cxa_guard_acquire_veneer
    .type cxa_guard_acquire_veneer, %function
cxa_guard_acquire_veneer:
    ldr     pc, [pc, #-4]
    .word   0x082a0444
    .size cxa_guard_acquire_veneer, . - cxa_guard_acquire_veneer
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veneer_words_match_the_retail_literal_dispatch() {
        assert_eq!(CXA_GUARD_ACQUIRE_VENEER_INSN, 0xe51f_f004);
        assert_eq!(CXA_GUARD_ACQUIRE_VENEER_TARGET, 0x082a_0444);
    }

    #[cfg(not(target_arch = "arm"))]
    #[test]
    fn host_guard_acquire_publishes_only_once() {
        let mut guard = 0u32;
        assert_eq!(unsafe { cxa_guard_acquire_veneer(&mut guard) }, 1);
        assert_eq!(guard, 1);
        assert_eq!(unsafe { cxa_guard_acquire_veneer(&mut guard) }, 0);
        assert_eq!(guard, 1);
    }

    #[cfg(not(target_arch = "arm"))]
    #[test]
    fn host_guard_acquire_refuses_a_nonzero_guard_without_bit_zero() {
        let mut guard = 2u32;
        assert_eq!(unsafe { cxa_guard_acquire_veneer(&mut guard) }, 0);
        assert_eq!(guard, 2);
    }
}
