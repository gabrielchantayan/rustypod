//! `rtc_seeded_random_result` — original: `FUN_0835a2f8` @ `0x0835a2f8`.
//!
//! True extent: 68 bytes (`0x0835a2f8..0x0835a33c`): 16 ARM instruction
//! words followed by the `0xde8743fe` literal. The next real function starts
//! at `0x0835a33c` with `push {r0-r11, lr}`. Two plain `bl` call sites reach
//! this function (`0x0832c830`, `0x0832e5e4`); no predicated `bl` calls were
//! found. Its one internal call is a plain `bl 0x0834f3e4`.
//!
//! # Algorithm
//!
//! Discard incoming r0/r1, retain r2/r3, and invoke the RTC-seeded random-word
//! wrapper once. Return its random word. The retail three-state subtraction
//! loop always reaches that one call before returning.
//!
//! # Deliberate deviations
//!
//! Target builds retain the retail instruction sequence, including r4-r6
//! preservation and the literal pool. Host builds call the already ported
//! wrapper directly because the host C ABI cannot preserve the target's
//! register-only behavior.

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rtc_seeded_random_result(
    _discarded_r0: u32,
    _discarded_r1: u32,
    retained_r2: u32,
    retained_r3: u32,
) -> u32 {
    crate::runtime::rtc_seeded_random_word::rtc_seeded_random_word(
        0, RANDOM_WORD_R1_LITERAL.wrapping_add(1), retained_r2, retained_r3,
    )
}

const RANDOM_WORD_R1_LITERAL: u32 = 0xde87_43fe;

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl rtc_seeded_random_result
    .type rtc_seeded_random_result, %function
rtc_seeded_random_result:
    push    {{r4, r5, r6, lr}}
    ldr     r1, 1f
    mov     r0, #0
    rsb     r4, r1, r0
    add     r5, r1, #1
    add     r6, r1, #2
0:  adds    r1, r1, r4
    moveq   r1, r5
    beq     0b
    cmp     r1, #1
    beq     2f
    cmp     r1, #2
    popeq   {{r4, r5, r6, pc}}
2:  bl      rtc_seeded_random_word
    mov     r1, r6
    b       0b
1:  .word   0xde8743fe
    .size rtc_seeded_random_result, . - rtc_seeded_random_result
"#
);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    static mut CALLS: u32 = 0;

    unsafe extern "C" fn acquire() -> u32 { 0xfeed_beef }
    unsafe extern "C" fn read_word() -> u32 { CALLS += 1; 0x1234_5678 }
    unsafe extern "C" fn release(_: u32) {}

    #[test]
    fn returns_one_rtc_seeded_random_word_after_discarding_arguments() {
        let _lock = crate::testing::RTC_SEEDED_RANDOM_SERVICE_TEST_LOCK.lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe {
            let mut initialized = 1u32;
            let saved = (
                crate::runtime::rtc_seeded_random_service::ENTROPY_SESSION_ACQUIRE,
                crate::runtime::rtc_seeded_random_service::ENTROPY_WORD_READ,
                crate::runtime::rtc_seeded_random_service::ENTROPY_SESSION_RELEASE,
                crate::runtime::rtc_seeded_random_service::INITIALIZED,
            );
            CALLS = 0;
            (
                crate::runtime::rtc_seeded_random_service::ENTROPY_SESSION_ACQUIRE,
                crate::runtime::rtc_seeded_random_service::ENTROPY_WORD_READ,
                crate::runtime::rtc_seeded_random_service::ENTROPY_SESSION_RELEASE,
                crate::runtime::rtc_seeded_random_service::INITIALIZED,
            ) = (acquire, read_word, release, core::ptr::addr_of_mut!(initialized));
            assert_eq!(rtc_seeded_random_result(0, 0, 0, 0), 0x1234_5678);
            assert_eq!(CALLS, 1);
            (
                crate::runtime::rtc_seeded_random_service::ENTROPY_SESSION_ACQUIRE,
                crate::runtime::rtc_seeded_random_service::ENTROPY_WORD_READ,
                crate::runtime::rtc_seeded_random_service::ENTROPY_SESSION_RELEASE,
                crate::runtime::rtc_seeded_random_service::INITIALIZED,
            ) = saved;
        }
    }
}
