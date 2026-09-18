//! `identity_noop` — original: `FUN_0815a00c` at load address `0x0815a00c`
//! (4 bytes: `bx lr`; the following `push {r3,r4,r5,r6,r7,r8,r9,lr}` at
//! `0x0815a010` begins the next independently linked function).
//!
//! Full-image raw A32 decoding finds four inbound plain `bl` calls
//! (`0x081c256c`, `0x081c2d64`, `0x081c348c`, and `0x081c4330`) and no
//! predicated `bl` calls.
//!
//! Algorithm: return the incoming `r0` word unchanged. The call contexts all
//! pass an opaque non-null result before an immediate fatal handler, but the
//! empty body cannot establish a higher-level callee identity.
//!
//! # Deliberate deviations
//!
//! None.

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.identity_noop,"ax",%progbits
    .globl identity_noop
    .type identity_noop,%function
identity_noop:
    bx lr
    .size identity_noop, . - identity_noop
"#
);

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub extern "C" fn identity_noop(value: u32) -> u32 {
    value
}
#[cfg(test)]
mod tests {
    use super::identity_noop;

    #[test]
    fn preserves_all_argument_bits() {
        for value in [0, 1, 0xffff_ffff, 0x8000_0000, 0x1234_5678] {
            assert_eq!(identity_noop(value), value);
        }
    }
}
