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
//! register preservation and direct call veneer. Host builds expose the
//! unported service as a replaceable callback so its complete four-register
//! ABI is testable.

/// ABI of the unported RTC-seeded random-word service at `0x080548ec`.
pub type RtcSeededRandomService = unsafe extern "C" fn(u32, u32, u32, u32) -> u32;

const SERVICE_R1_LITERAL: u32 = 0x3370_d3fd;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_rtc_seeded_random_service(
    _r0: u32,
    _r1: u32,
    _r2: u32,
    _r3: u32,
) -> u32 {
    0
}

/// Host-only replacement for the retail service at `0x080548ec`.
#[cfg(not(target_arch = "arm"))]
pub static mut RTC_SEEDED_RANDOM_SERVICE: RtcSeededRandomService = missing_rtc_seeded_random_service;

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rtc_seeded_random_word(
    _discarded_r0: u32,
    _discarded_r1: u32,
    retained_r2: u32,
    retained_r3: u32,
) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(RTC_SEEDED_RANDOM_SERVICE))(
        0,
        SERVICE_R1_LITERAL.wrapping_add(1),
        retained_r2,
        retained_r3,
    )
}

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
3:  bl      retail_rtc_seeded_random_service
    mov     r1, r5
    b       0b
1:  .word   0x3370d3fd
    .size rtc_seeded_random_word, . - rtc_seeded_random_word

retail_rtc_seeded_random_service:
    ldr     pc, [pc, #-4]
    .word   0x080548ec
    .size retail_rtc_seeded_random_service, . - retail_rtc_seeded_random_service
"#
);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED: (u32, u32, u32, u32) = (0, 0, 0, 0);

    unsafe extern "C" fn record_service(r0: u32, r1: u32, r2: u32, r3: u32) -> u32 {
        OBSERVED = (r0, r1, r2, r3);
        0xa5a5_5a5a
    }

    #[test]
    fn replaces_the_first_two_registers_and_retains_the_last_two() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = RTC_SEEDED_RANDOM_SERVICE;
            RTC_SEEDED_RANDOM_SERVICE = record_service;
            assert_eq!(rtc_seeded_random_word(0xffff_ffff, 0x1234_5678, 0, u32::MAX), 0xa5a5_5a5a);
            assert_eq!(OBSERVED, (0, 0x3370_d3fe, 0, u32::MAX));
            RTC_SEEDED_RANDOM_SERVICE = saved;
        }
    }
}
