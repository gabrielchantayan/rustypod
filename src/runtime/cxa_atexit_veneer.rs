//! C++ destructor-registration literal veneer — `FUN_080036e8` @ 0x080036e8.
//!
//! Raw ARM:
//!
//! ```text
//! 080036e8  ldr pc, [pc, #-4]
//! 080036ec  .word 0x082a02f0
//! ```
//!
//! The true extent is eight bytes: the literal is part of the veneer and the
//! next independently callable literal veneer starts at 0x080036f0. Decoding
//! every direct ARM branch-with-link instruction in `osos.dec` finds five
//! callers, all plain `bl`; no predicated `bl` reaches this address.
//!
//! Each caller follows a C++ static constructor with `(object, destructor,
//! __dso_handle)`, identifying the target as the ADS `__cxa_atexit`
//! registration entry. The veneer changes no register and retains LR,
//! tail-branching to its retail target at 0x082a02f0. ARM builds retain its
//! exact instruction and literal. The target is not a Rust ABI seam, so host
//! builds deliberately dispatch to the ported `cxa_atexit` implementation.

/// Fixed ARM instruction at 0x080036e8: `ldr pc, [pc, #-4]`.
pub const CXA_ATEXIT_VENEER_INSN: u32 = 0xe51f_f004;

/// Literal tail target at 0x080036ec.
pub const CXA_ATEXIT_VENEER_TARGET: u32 = 0x082a_02f0;

#[cfg(target_arch = "arm")]
extern "C" {
    /// cxa_atexit_veneer — original: `FUN_080036e8` @ 0x080036e8.
    pub fn cxa_atexit_veneer(
        object: *mut core::ffi::c_void,
        destructor: crate::runtime::shutdown_chain::ShutdownHandlerFn,
        dso_handle: i32,
    ) -> i32;
}

/// Host-only semantic counterpart for C++ destructor registrations.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxa_atexit_veneer(
    object: *mut core::ffi::c_void,
    destructor: crate::runtime::shutdown_chain::ShutdownHandlerFn,
    dso_handle: i32,
) -> i32 {
    crate::runtime::shutdown_chain::cxa_atexit(object, destructor, dso_handle)
}

// `ldr pc` preserves LR and all general registers while transferring directly
// to the literal target; a Rust wrapper would not preserve that ABI.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl cxa_atexit_veneer
    .type cxa_atexit_veneer, %function
cxa_atexit_veneer:
    ldr     pc, [pc, #-4]
    .word   0x082a02f0
    .size cxa_atexit_veneer, . - cxa_atexit_veneer
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veneer_words_match_the_retail_literal_dispatch() {
        assert_eq!(CXA_ATEXIT_VENEER_INSN, 0xe51f_f004);
        assert_eq!(CXA_ATEXIT_VENEER_TARGET, 0x082a_02f0);
    }
}
