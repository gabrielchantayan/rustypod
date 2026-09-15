//! `feedback_level_mode_set` — original: `FUN_082bc9ec` at load address
//! `0x082bc9ec`, 76 bytes (19 ARM words); the next function starts at
//! `0x082bca38`.
//!
//! # Verified behavior
//!
//! Binary decoding finds five direct `bl` callers: three unconditional
//! (`0x0809e51c`, `0x080cc998`, `0x0818e4c0`) and two `blne`
//! (`0x0805886c`, `0x0818f3a0`). The function reads the cached hardware mode
//! through retail helper `0x082bc614`. Mode one delegates to retail helper
//! `0x082e5a20`. Every other mode takes semaphore one, drives GPIO pin `0x61`
//! low only for mode zero (high for every other u32 value), releases the
//! semaphore, and returns the GPIO-write result.
//!
//! # Deliberate deviation
//!
//! The two unported helpers remain fixed-address literal veneers on-device and
//! host callback seams. The semaphore and GPIO calls use their existing Rust
//! ports rather than their retail shims; their observable ordering is retained.

use crate::drivers::gpio_pin_write::gpio_pin_write;
use crate::kernel::task_lock::{kernel_sem1_signal, kernel_sem1_wait};

pub type FeedbackModeProfile = unsafe extern "C" fn() -> u32;
pub type FeedbackModeApply = unsafe extern "C" fn(mode: u32) -> u32;

#[cfg(not(target_arch = "arm"))]
pub unsafe extern "C" fn missing_feedback_mode_profile() -> u32 {
    1
}
#[cfg(not(target_arch = "arm"))]
pub unsafe extern "C" fn missing_feedback_mode_apply(_mode: u32) -> u32 {
    0
}

/// Host replacements for retail helpers `0x082bc614` and `0x082e5a20`.
#[cfg(not(target_arch = "arm"))]
pub static mut FEEDBACK_MODE_PROFILE: FeedbackModeProfile = missing_feedback_mode_profile;
#[cfg(not(target_arch = "arm"))]
pub static mut FEEDBACK_MODE_APPLY: FeedbackModeApply = missing_feedback_mode_apply;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn feedback_mode_profile() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(FEEDBACK_MODE_PROFILE))()
}
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn feedback_mode_apply(mode: u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(FEEDBACK_MODE_APPLY))(mode)
}

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn retail_feedback_mode_profile() -> u32;
    fn retail_feedback_mode_apply(mode: u32) -> u32;
}
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn feedback_mode_profile() -> u32 {
    retail_feedback_mode_profile()
}
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn feedback_mode_apply(mode: u32) -> u32 {
    retail_feedback_mode_apply(mode)
}

/// The value supplied to GPIO pin `0x61` in the non-delegating path.
#[inline]
pub const fn feedback_mode_gpio_level(mode: u32) -> i32 {
    (mode == 0) as i32
}

/// feedback_level_mode_set — original `FUN_082bc9ec` @ `0x082bc9ec`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn feedback_level_mode_set(mode: u32) -> u32 {
    if feedback_mode_profile() == 1 {
        return feedback_mode_apply(mode);
    }

    kernel_sem1_wait();
    let result = gpio_pin_write(0x61, feedback_mode_gpio_level(mode));
    kernel_sem1_signal();
    result
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
retail_feedback_mode_profile:
    ldr     pc, [pc, #-4]
    .word   0x082bc614
retail_feedback_mode_apply:
    ldr     pc, [pc, #-4]
    .word   0x082e5a20
"#
);

#[cfg(test)]
mod tests {
    use super::feedback_mode_gpio_level;

    #[test]
    fn nondelegating_path_only_drives_low_for_zero() {
        assert_eq!(feedback_mode_gpio_level(0), 1);
        assert_eq!(feedback_mode_gpio_level(1), 0);
        assert_eq!(feedback_mode_gpio_level(2), 0);
        assert_eq!(feedback_mode_gpio_level(u32::MAX), 0);
    }
}
