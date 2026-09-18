//! `zero_nine_words` — original: `FUN_08158d08` at load address `0x08158d08`
//! (104 bytes, `0x08158d08..0x08158d70`; the `mov r1, #0` at `0x08158d70`
//! begins the next independently linked function).
//!
//! Full-image raw A32 decoding finds four inbound plain `bl` calls and no
//! predicated `bl` calls. The body clears 36 bytes: byte stores cover offsets
//! 0..15 and 32..35, while aligned word stores cover offsets 16, 20, 24, and
//! 28. It has no calls.
//!
//! # Deliberate deviations
//!
//! The host implementation uses byte stores for all 36 bytes so its fixture
//! need not rely on target word alignment. The target export is the exact
//! original instruction sequence, including its aligned word stores and the
//! writeback to `r0` at offset 32.

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.zero_nine_words,"ax",%progbits
    .globl zero_nine_words
    .type zero_nine_words,%function
zero_nine_words:
    mov r1, #0
    strb r1, [r0]
    strb r1, [r0, #1]
    strb r1, [r0, #2]
    strb r1, [r0, #3]
    strb r1, [r0, #4]
    strb r1, [r0, #5]
    strb r1, [r0, #6]
    strb r1, [r0, #7]
    strb r1, [r0, #8]
    strb r1, [r0, #9]
    strb r1, [r0, #10]
    strb r1, [r0, #11]
    strb r1, [r0, #12]
    strb r1, [r0, #13]
    strb r1, [r0, #14]
    strb r1, [r0, #15]
    str r1, [r0, #16]
    str r1, [r0, #20]
    str r1, [r0, #24]
    str r1, [r0, #28]
    strb r1, [r0, #32]!
    strb r1, [r0, #1]
    strb r1, [r0, #2]
    strb r1, [r0, #3]
    bx lr
    .size zero_nine_words, . - zero_nine_words
"#
);

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn zero_nine_words(dst: *mut u8) {
    for offset in 0..36 {
        dst.add(offset).write_volatile(0);
    }
}

#[cfg(test)]
mod tests {
    use super::zero_nine_words;

    #[test]
    fn zeroes_exactly_nine_words() {
        let mut bytes = [0xa5; 44];

        unsafe { zero_nine_words(bytes.as_mut_ptr().wrapping_add(4)) };

        assert_eq!(&bytes[..4], &[0xa5; 4]);
        assert_eq!(&bytes[4..40], &[0; 36]);
        assert_eq!(&bytes[40..], &[0xa5; 4]);
    }

    #[test]
    fn accepts_an_unaligned_host_fixture() {
        let mut bytes = [0xff; 39];

        unsafe { zero_nine_words(bytes.as_mut_ptr().wrapping_add(1)) };

        assert_eq!(bytes[0], 0xff);
        assert_eq!(&bytes[1..37], &[0; 36]);
        assert_eq!(&bytes[37..], &[0xff; 2]);
    }
}
