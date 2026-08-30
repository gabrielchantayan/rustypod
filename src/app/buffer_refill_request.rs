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


use crate::drivers::interrupts::{cpsr_disable_irq_fiq, cpsr_restore_irq_fiq};
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

/// Request-controller flags at target RAM address `0x2200aebc`.
///
/// The IRAM body at `0x22004450` reads and writes its first word while IRQ
/// and FIQ are masked.
#[cfg(target_os = "none")]
const STREAM_BUFFER_REQUEST_FLAGS: *mut u32 = 0x2200_aebc as *mut u32;

/// Host-only replacement for the request-controller flags word.
#[cfg(not(target_os = "none"))]
pub static mut STREAM_BUFFER_REQUEST_FLAGS: u32 = 0;

#[inline(always)]
fn stream_buffer_request_flags_ptr() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        STREAM_BUFFER_REQUEST_FLAGS
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(STREAM_BUFFER_REQUEST_FLAGS)
    }
}

/// stream_buffer_request_flags_update — original: `thunk_EXT_FUN_22004450`
/// @ `0x08037fe8` (Ghidra reports 4 bytes; raw extent is **8** bytes:
/// `ldr pc, [pc, #-4]` / `0x22004450`). The IRAM mirror makes that target
/// osos `0x08004450`, whose raw body is 52 bytes including its literal word.
///
/// Raw decoding of every ARM `B`/`BL` in `work/firmware/osos.dec` found
/// **30 direct `bl` call sites** to this veneer: 28 unconditional, one
/// `blhi` (`0x080f5720`), and one `blls` (`0x080f57dc`); there are no tail
/// `b` callers. The two predicated calls are caller-side bounds gates, not a
/// null guard: this function unconditionally masks IRQ/FIQ before accessing
/// its pointer-free global.
///
/// Disables IRQ/FIQ, clears `mask` in the request-controller flags when
/// `enable` is zero, or sets it for every nonzero `enable`, then restores the
/// prior CPSR I/F state. This is the exact `bic`/`orr` selection and volatile
/// read-modify-write at `0x2200aebc` in the mirrored IRAM body.
///
/// # Deliberate deviations
///
/// The target body reaches the CPSR helpers at `0x08001e70` and
/// `0x08001e84`; this port calls their existing Rust ports. Host builds
/// replace only target RAM with [`STREAM_BUFFER_REQUEST_FLAGS`], while those
/// helpers use their existing deterministic host CPSR seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.stream_buffer_request_flags_update"
)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_request_flags_update(enable: u32, mask: u32) {
    let saved_if_mask = cpsr_disable_irq_fiq();
    let flags = core::ptr::read_volatile(stream_buffer_request_flags_ptr());
    let updated_flags = if enable == 0 {
        flags & !mask
    } else {
        flags | mask
    };
    core::ptr::write_volatile(stream_buffer_request_flags_ptr(), updated_flags);
    cpsr_restore_irq_fiq(saved_if_mask);
}

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
                STREAM_BUFFER_REQUEST_FLAGS = 0;
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

    fn arrange_request_flags(flags: u32) -> MutexGuard<'static, ()> {
        let guard = REFILL_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            STREAM_BUFFER_REQUEST_FLAGS = flags;
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

    #[test]
    fn clears_only_requested_flags_when_enable_is_zero() {
        let _guard = arrange_request_flags(0xa5a5_5a5a);
        let _reset = Reset;

        unsafe { stream_buffer_request_flags_update(0, 0x00f0_0f00) };

        unsafe {
            assert_eq!(
                STREAM_BUFFER_REQUEST_FLAGS,
                0xa505_505a,
                "zero enable selects the ARM bic path"
            );
        }
    }

    #[test]
    fn sets_requested_flags_for_every_nonzero_enable_value() {
        let _guard = arrange_request_flags(0x0000_1001);
        let _reset = Reset;

        unsafe { stream_buffer_request_flags_update(0x8000_0000, 0x0010_0a04) };

        unsafe {
            assert_eq!(
                STREAM_BUFFER_REQUEST_FLAGS,
                0x0010_1a05,
                "any nonzero enable selects the ARM orr path"
            );
        }
    }
}
