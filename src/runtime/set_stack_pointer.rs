//! Port of `FUN_08038c80` @ 0x08038c80 (8 bytes; four plain `bl` callers,
//! zero predicated `bl` callers).
//!
//! Algorithm: replace the ARM stack pointer (`sp`) with the `new_stack_pointer`
//! argument in `r0`, then return through `lr`. The instruction has no alignment
//! check, memory access, or return-value write; every 32-bit value is installed
//! verbatim. The adjacent 0x08038c88 entry shares the `mov sp, r0` word but
//! tail-dispatches through `r1`, so it is deliberately not part of this port.
//!
//! Deliberate deviation: the target body is verbatim ARM `global_asm!`, because
//! changing `sp` in a Rust ABI function would invalidate its compiler-generated
//! frame. Host builds expose the state-transition model for tests; they cannot
//! install an arbitrary host stack pointer.

/// Models the sole architectural effect of `set_stack_pointer`.
#[inline(always)]
const fn installed_stack_pointer(new_stack_pointer: u32) -> u32 {
    new_stack_pointer
}

// The ARM body is a BL target whose return must use the replacement stack.
// A normal Rust function cannot preserve that ABI invariant around a prologue.
#[cfg(target_arch = "arm")]
extern "C" {
    pub fn set_stack_pointer(new_stack_pointer: u32);
}

/// Host-only declaration substitute; the target implementation is raw ARM.
#[cfg(not(target_arch = "arm"))]
pub unsafe extern "C" fn set_stack_pointer(new_stack_pointer: u32) {
    let _ = new_stack_pointer;
    unreachable!("set_stack_pointer is provided by global_asm on ARM targets")
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl set_stack_pointer
    .type set_stack_pointer, %function
set_stack_pointer:
    mov     sp, r0
    bx      lr
    .size set_stack_pointer, . - set_stack_pointer
"#
);

#[cfg(test)]
mod tests {
    use super::installed_stack_pointer;

    #[test]
    fn installs_every_stack_pointer_word_verbatim() {
        for requested in [0, 1, 0x0800_0000, 0x2200_8a84, u32::MAX] {
            assert_eq!(installed_stack_pointer(requested), requested);
        }
    }
}
