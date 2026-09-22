//! `fixed16_matrix_identity_init` — original: `FUN_0827d324` at load address
//! `0x0827d324` (92 bytes, `0x0827d324..0x0827d380`; `0x0827d380` begins the
//! next independently linked function).
//!
//! Raw A32 decoding finds no direct calls in the body and three inbound plain
//! `bl` calls; it has no predicated `bl` calls. The body initializes the
//! 4-by-4 Q16.16 matrix at offsets 4..=64 to identity: the four diagonal words
//! receive `0x0001_0000` and every other matrix word receives zero. Offset 0
//! is deliberately untouched.
//!
//! # Deliberate deviations
//!
//! The target export is the exact retail instruction sequence. The host
//! implementation uses byte stores so its tests do not require ARM-aligned
//! word stores; its observable bytes are identical for aligned inputs.

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.fixed16_matrix_identity_init,"ax",%progbits
    .globl fixed16_matrix_identity_init
    .type fixed16_matrix_identity_init,%function
fixed16_matrix_identity_init:
    push {{r4, r5, r6, r7, r8, r9, sl, lr}}
    mov r1, #0x10000
    str r1, [r0, #64]
    str r1, [r0, #44]
    str r1, [r0, #24]
    str r1, [r0, #4]
    mov r1, #0
    str r1, [r0, #60]
    str r1, [r0, #56]
    str r1, [r0, #52]
    str r1, [r0, #48]
    str r1, [r0, #40]
    str r1, [r0, #36]
    str r1, [r0, #32]
    add r8, r0, #20
    str r1, [r0, #28]
    add r9, r0, #16
    str r1, [r8]
    add sl, r0, #12
    str r1, [r9]
    str r1, [sl]
    str r1, [r0, #8]
    pop {{r4, r5, r6, r7, r8, r9, sl, pc}}
    .size fixed16_matrix_identity_init, . - fixed16_matrix_identity_init
"#
);

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn fixed16_matrix_identity_init(matrix_with_leading_word: *mut u8) {
    for offset in 4..68 {
        matrix_with_leading_word.add(offset).write_volatile(0);
    }
    for offset in [4, 24, 44, 64] {
        matrix_with_leading_word
            .add(offset)
            .cast::<u32>()
            .write_unaligned(0x0001_0000);
    }
}

#[cfg(test)]
mod tests {
    use super::fixed16_matrix_identity_init;

    #[test]
    fn initializes_only_the_fixed16_matrix() {
        let mut bytes = [0xa5; 80];
        let matrix = unsafe { bytes.as_mut_ptr().add(4) };

        unsafe { fixed16_matrix_identity_init(matrix) };

        assert_eq!(&bytes[..8], &[0xa5; 8]);
        assert_eq!(&bytes[72..], &[0xa5; 8]);
        for word in 0..16 {
            let value = u32::from_le_bytes(bytes[8 + word * 4..12 + word * 4].try_into().unwrap());
            assert_eq!(value, if word % 5 == 0 { 0x0001_0000 } else { 0 });
        }
    }

    #[test]
    fn host_implementation_accepts_an_unaligned_fixture() {
        let mut bytes = [0x5a; 76];
        let matrix = unsafe { bytes.as_mut_ptr().add(1) };

        unsafe { fixed16_matrix_identity_init(matrix) };

        assert_eq!(bytes[0], 0x5a);
        assert_eq!(&bytes[1..5], &[0x5a; 4]);
        assert_eq!(&bytes[69..], &[0x5a; 7]);
        for word in 0..16 {
            let value = u32::from_le_bytes(bytes[5 + word * 4..9 + word * 4].try_into().unwrap());
            assert_eq!(value, if word % 5 == 0 { 0x0001_0000 } else { 0 });
        }
    }
}
