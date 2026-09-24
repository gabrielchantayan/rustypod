//! `always_zero` — original: `FUN_08111084` at load address `0x08111084`.
//!
//! True size: 8 bytes (`mov r0, #0; bx lr`); `0x0811108c` starts the next
//! independently linked function. Full-image raw A32 decoding finds three
//! inbound plain `bl` calls (`0x0814b6d4`, `0x0817cfbc`, and `0x0818477c`)
//! and no predicated `bl` calls.
//!
//! Algorithm: ignore all incoming argument registers and return zero.
//!
//! # Deliberate deviations
//!
//! None. The device implementation is written in A32 assembly to retain the
//! retail two-instruction body and its callable symbol.

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.always_zero,"ax",%progbits
    .globl always_zero
    .type always_zero,%function
always_zero:
    mov r0, #0
    bx lr
    .size always_zero, . - always_zero
"#
);

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub extern "C" fn always_zero() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::always_zero;

    #[test]
    fn returns_zero() {
        assert_eq!(always_zero(), 0);
    }
}
