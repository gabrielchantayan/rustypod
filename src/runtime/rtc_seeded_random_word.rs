//! `rtc_seeded_random_word` — original: `FUN_0834f3e4` @ `0x0834f3e4`.
//!
//! True extent: 68 bytes (`0x0834f3e4..0x0834f428`): 16 ARM instruction
//! words followed by the `0x3370d3fd` literal. The next real function starts
//! at `0x0834f42c` with `push {r4, r5, r6, lr}`. Four plain `bl` call sites
//! reach this function; no predicated `bl` calls were found.
//!
//! # Algorithm
//!
//! Set r0 to zero, r1 to one greater than the literal-pool word, retain the
//! incoming r2/r3 words, and call the RTC-seeded random-word service at
//! `0x080548ec`. Return that service's r0 result. The retail control flow
//! expresses this as a three-state subtraction loop; it always performs one
//! call.
//!
//! # Deliberate deviations
//!
//! Target builds retain the original instruction sequence, including its
//! register preservation. Host builds call the ported service directly; r4 is
//! unavailable through the host C ABI and is consequently zero there.

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rtc_seeded_random_word(
    _discarded_r0: u32,
    _discarded_r1: u32,
    retained_r2: u32,
    retained_r3: u32,
) -> u32 {
    crate::runtime::rtc_seeded_random_service::rtc_seeded_random_service(
        0, SERVICE_R1_LITERAL.wrapping_add(1), retained_r2, retained_r3,
    )
}

const SERVICE_R1_LITERAL: u32 = 0x3370_d3fd;


#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl rtc_seeded_random_word
    .type rtc_seeded_random_word, %function
rtc_seeded_random_word:
    push    {{r4, r5, r6, lr}}
    ldr     r1, 1f
    mov     r0, #0
    mov     r4, r1
    add     r5, r1, #2
    add     r6, r1, #1
0:  subs    r1, r1, r4
    beq     2f
    cmp     r1, #1
    beq     3f
    cmp     r1, #2
    popeq   {{r4, r5, r6, pc}}
2:  mov     r1, r6
    b       0b
3:  bl      rtc_seeded_random_service
    mov     r1, r5
    b       0b
1:  .word   0x3370d3fd
    .size rtc_seeded_random_word, . - rtc_seeded_random_word
"#
);

