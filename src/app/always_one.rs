//! `always_one` — original: `FUN_082cb17c` at load address `0x082cb17c`.
//!
//! True size: 8 bytes (`mov r0, #1; bx lr`); `0x082cb184` starts the next
//! independently linked function. Full-image raw A32 decoding finds two inbound
//! plain `bl` calls (`0x08142a94` and `0x0816e8a0`) and no predicated `bl`
//! calls.
//!
//! Algorithm: ignore all incoming argument registers and return one.
//!
//! # Deliberate deviations
//!
//! None. The device implementation is written in A32 assembly to retain the
//! retail two-instruction body and its callable symbol.

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.always_one,"ax",%progbits
    .globl always_one
    .type always_one,%function
always_one:
    mov r0, #1
    bx lr
    .size always_one, . - always_one
"#
);

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub extern "C" fn always_one() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::always_one;

    #[test]
    fn returns_one() {
        assert_eq!(always_one(), 1);
    }
}
