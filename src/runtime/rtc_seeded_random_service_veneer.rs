//! RTC-seeded random-service veneer — `thunk_FUN_080548ec` @ `0x0805b0cc`.
//!
//! True extent: 4 bytes (`0x0805b0cc..0x0805b0d0`); the next real function
//! begins at `0x0805b0d0`. The sole instruction is `b 0x080548ec`
//! (`0xeaffe606`). Decoding every ARM B/BL word in `osos.dec` finds one plain
//! `bl` call site (`0x080aac98`), one predicated `bleq` call site
//! (`0x08062168`), and one direct tail-branch site (`0x0805b0cc`) to the
//! underlying service.
//!
//! # Algorithm
//!
//! Tail-dispatches to `rtc_seeded_random_service` without changing registers,
//! LR, or the caller's stack; in particular, the target receives the caller's
//! inherited r4 entropy contribution unchanged.
//!
//! # Deliberate deviation
//!
//! The host implementation expresses the tail branch as a normal Rust call so
//! its result can be tested. The ARM implementation emits the verified branch
//! word exactly.

/// The verified ARM instruction at 0x0805b0cc: `b 0x080548ec`.
pub const RTC_SEEDED_RANDOM_SERVICE_VENEER_INSN: u32 = 0xeaff_e606;

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rtc_seeded_random_service_veneer(
    r0: u32, r1: u32, r2: u32, r3: u32,
) -> u32 {
    crate::runtime::rtc_seeded_random_service::rtc_seeded_random_service(r0, r1, r2, r3)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl rtc_seeded_random_service_veneer
    .type rtc_seeded_random_service_veneer, %function
rtc_seeded_random_service_veneer:
    .word 0xeaffe606
    .size rtc_seeded_random_service_veneer, . - rtc_seeded_random_service_veneer
"#);
