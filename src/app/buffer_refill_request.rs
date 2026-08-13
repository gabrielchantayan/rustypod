//! `stream_buffer_refill_level_advance` — original: `FUN_08004484` @
//! `0x08004484` (32 bytes, followed by two literal words).
//!
//! # Algorithm
//!
//! The stream-buffer consumer at `0x08006b64` calls this when its readable
//! distance exceeds half its configured capacity. The function reads the
//! global refill-request level at `0x2200ad14`, preserves the special level
//! `3`, and otherwise advances it by one with ordinary 32-bit wrapping
//! arithmetic. It stores that result to the request-controller's `+0x10`
//! field (`0x2200aebc`) and tail-enters the shared controller at `0x080029ac`.
//! That controller applies the request to the active buffer state.
//!
//! On ARM the port retains the retail global addresses and the tail transfer;
//! the linker-safe veneer replaces the stock PC-relative branch. Host builds
//! model the two observable edges with a request-level cell and controller
//! callback seam, because neither target RAM address is host-mapped.

/// Request-controller level that is held rather than advanced.
pub const REFILL_LEVEL_HOLD: u32 = 3;

/// Host/target seam for the shared controller tail-called at `0x080029ac`.
pub type RefillController = unsafe extern "C" fn() -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_refill_controller() -> u32 {
    0
}

/// Host-only replacement for target RAM word `0x2200ad14`.
#[cfg(not(target_arch = "arm"))]
pub static mut STREAM_BUFFER_REFILL_LEVEL: u32 = 0;

/// Host-only callback for the shared transition-controller tail call.
#[cfg(not(target_arch = "arm"))]
pub static mut REFILL_CONTROLLER: RefillController = missing_refill_controller;

/// stream_buffer_refill_level_advance — original: `FUN_08004484` @
/// `0x08004484` (32 bytes).
///
/// Advances the global stream-buffer refill request, except that level 3 is
/// retained, then enters the shared buffer transition controller. The return
/// value is exactly the controller's result.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_refill_level_advance() -> u32 {
    let level = core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_REFILL_LEVEL));
    let requested_level = if level == REFILL_LEVEL_HOLD {
        REFILL_LEVEL_HOLD
    } else {
        level.wrapping_add(1)
    };
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!(STREAM_BUFFER_REFILL_LEVEL),
        requested_level,
    );
    core::ptr::read_volatile(core::ptr::addr_of!(REFILL_CONTROLLER))()
}

// The stock body uses two PC-relative literals and a direct tail branch to
// 0x080029ac. A literal veneer keeps that tail call relocation-safe once this
// function lives in the Rust payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl stream_buffer_refill_level_advance
    .type stream_buffer_refill_level_advance, %function
stream_buffer_refill_level_advance:
    ldr     r0, 1f
    ldr     r1, 2f
    ldr     r0, [r0]
    cmp     r0, #3
    addne   r0, r0, #1
    moveq   r0, #3
    str     r0, [r1, #0x10]
    b       retail_stream_buffer_transition_controller
1:  .word   0x2200ad14
2:  .word   0x2200aebc
    .size stream_buffer_refill_level_advance, . - stream_buffer_refill_level_advance

retail_stream_buffer_transition_controller:
    ldr     pc, [pc, #-4]
    .word   0x080029ac
    .size retail_stream_buffer_transition_controller, . - retail_stream_buffer_transition_controller
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static REFILL_LOCK: Mutex<()> = Mutex::new(());
    static mut CONTROLLER_CALLS: u32 = 0;
    static mut CONTROLLER_RESULT: u32 = 0;

    unsafe extern "C" fn recording_controller() -> u32 {
        CONTROLLER_CALLS += 1;
        CONTROLLER_RESULT
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                STREAM_BUFFER_REFILL_LEVEL = 0;
                REFILL_CONTROLLER = missing_refill_controller;
                CONTROLLER_CALLS = 0;
                CONTROLLER_RESULT = 0;
            }
        }
    }

    fn arrange(level: u32, result: u32) -> MutexGuard<'static, ()> {
        let guard = REFILL_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            STREAM_BUFFER_REFILL_LEVEL = level;
            CONTROLLER_CALLS = 0;
            CONTROLLER_RESULT = result;
            REFILL_CONTROLLER = recording_controller;
        }
        guard
    }

    #[test]
    fn advances_non_hold_levels_then_returns_the_controller_result() {
        let _guard = arrange(2, 0xfeed_beef);
        let _reset = Reset;
        assert_eq!(unsafe { stream_buffer_refill_level_advance() }, 0xfeed_beef);
        unsafe {
            assert_eq!(STREAM_BUFFER_REFILL_LEVEL, 3, "request controller +0x10");
            assert_eq!(CONTROLLER_CALLS, 1, "tail controller runs once");
        }
    }

    #[test]
    fn level_three_is_held_but_still_enters_the_controller() {
        let _guard = arrange(REFILL_LEVEL_HOLD, 9);
        let _reset = Reset;
        assert_eq!(unsafe { stream_buffer_refill_level_advance() }, 9);
        unsafe {
            assert_eq!(STREAM_BUFFER_REFILL_LEVEL, REFILL_LEVEL_HOLD);
            assert_eq!(CONTROLLER_CALLS, 1);
        }
    }

    #[test]
    fn only_exactly_three_is_special_and_other_levels_wrap() {
        let _guard = arrange(u32::MAX, 0);
        let _reset = Reset;
        unsafe { stream_buffer_refill_level_advance() };
        unsafe {
            assert_eq!(STREAM_BUFFER_REFILL_LEVEL, 0, "addne is a wrapping add");
            assert_eq!(CONTROLLER_CALLS, 1);
        }
    }
}
