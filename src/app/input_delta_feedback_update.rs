//! `input_delta_feedback_update` — original: `FUN_0829329c` at load address
//! `0x0829329c`, 128 bytes (124 bytes of code plus its trailing literal).
//!
//! # Verified behavior
//!
//! Decoding every ARM B/BL-immediate word in `osos.dec` finds six inbound
//! direct call sites, all unconditional plain `bl`: `0x08293374`,
//! `0x08293680`, `0x08293734`, `0x08293b00`, `0x08294b60`, and `0x08294b84`.
//! The function interprets the halfword at `0x089d04a0` as a signed feedback
//! adjustment without sign-extending it: nonnegative adjustments add to the
//! input delta, while negative adjustments subtract their two's-complement
//! magnitude only when the delta reaches it. It maps the resulting unsigned
//! magnitude to levels 1, 4, 5, 6, or 7 at thresholds 100, 200, 500, and
//! 1000, clears the caller state's pending-feedback byte at `+0x61`, then
//! tail-dispatches the level to retailOS `0x080cc978`.
//!
//! The ARM implementation retains the stock instruction sequence and both
//! stock targets through relocation-safe literal veneers. Host builds replace
//! the fixed halfword and unported tail dispatcher with mutable test seams.

/// Prefix of the caller state through its `+0x61` pending-feedback byte.
#[repr(C)]
pub struct InputFeedbackState {
    _before_pending_feedback: [u8; 0x61],
    pub pending_feedback: u8,
}

/// ABI of the unported retail feedback-level dispatcher at `0x080cc978`.
pub type FeedbackLevelDispatch = unsafe extern "C" fn(u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_feedback_level_dispatch(_level: u32) {}

/// Retail halfword read by the ARM implementation from `0x089d049c + 4`.
#[cfg(target_os = "none")]
const INPUT_FEEDBACK_ADJUSTMENT: *const u16 = 0x089d_04a0 as *const u16;

/// Host replacement for the retail feedback-adjustment halfword.
#[cfg(not(target_os = "none"))]
pub static mut INPUT_FEEDBACK_ADJUSTMENT: u16 = 0;

/// Host replacement for the unported retail feedback-level dispatcher.
#[cfg(not(target_arch = "arm"))]
pub static mut FEEDBACK_LEVEL_DISPATCH: FeedbackLevelDispatch = missing_feedback_level_dispatch;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn input_feedback_adjustment_ptr() -> *const u16 {
    #[cfg(target_os = "none")]
    {
        INPUT_FEEDBACK_ADJUSTMENT
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(INPUT_FEEDBACK_ADJUSTMENT)
    }
}

/// input_delta_feedback_update — original: `FUN_0829329c` at load address
/// `0x0829329c`, 128 bytes (124 bytes of code plus a trailing literal).
///
/// Maps `delta` adjusted by the retail feedback halfword into a feedback level,
/// clears `state.pending_feedback`, and tail-dispatches that level. The ARM
/// path is instruction-for-instruction shaped like retailOS; host builds use
/// the documented seams because their fixed address and target are unmapped.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_delta_feedback_update(
    state: *mut InputFeedbackState,
    delta: u32,
) {
    let adjustment = core::ptr::read_volatile(input_feedback_adjustment_ptr()) as u32;
    let magnitude = if adjustment < 0x8000 {
        delta.wrapping_add(adjustment)
    } else {
        let magnitude = 0x1_0000 - adjustment;
        if delta >= magnitude {
            delta - magnitude
        } else {
            0
        }
    };
    let level = if magnitude >= 1000 {
        7
    } else if magnitude >= 500 {
        6
    } else if magnitude >= 200 {
        5
    } else if magnitude >= 100 {
        4
    } else {
        1
    };

    core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).pending_feedback), 0);
    core::ptr::read_volatile(core::ptr::addr_of!(FEEDBACK_LEVEL_DISPATCH))(level);
}

// The literal belongs to the 128-byte original extent; both target calls use
// literal veneers so payload placement cannot change their destinations.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl input_delta_feedback_update
    .type input_delta_feedback_update, %function
input_delta_feedback_update:
    ldr     r3, 1f
    push    {{r4, lr}}
    ldrh    r2, [r3, #4]
    cmp     r2, #0x8000
    ldrh    r2, [r3, #4]
    addcc   r1, r1, r2
    bcc     0f
    rsb     r2, r2, #0x10000
    cmp     r2, r1
    bhi     2f
    ldrh    r2, [r3, #4]
    rsb     r2, r2, #0x10000
    sub     r1, r1, r2
0:
    cmp     r1, #1000
    movcs   r2, #7
    bcs     3f
    cmp     r1, #500
    movcs   r2, #6
    bcs     3f
    cmp     r1, #200
    movcs   r2, #5
    bcs     3f
    cmp     r1, #100
    movcs   r2, #4
    bcs     3f
2:
    mov     r2, #1
3:
    add     r0, r0, #0x60
    bl      retail_clear_input_feedback_pending
    pop     {{r4, lr}}
    mov     r0, r2
    b       retail_feedback_level_dispatch
1:  .word   0x089d049c
    .size input_delta_feedback_update, . - input_delta_feedback_update

retail_clear_input_feedback_pending:
    ldr     pc, [pc, #-4]
    .word   0x08205fd4
    .size retail_clear_input_feedback_pending, . - retail_clear_input_feedback_pending

retail_feedback_level_dispatch:
    ldr     pc, [pc, #-4]
    .word   0x080cc978
    .size retail_feedback_level_dispatch, . - retail_feedback_level_dispatch
"#
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut DISPATCHED_LEVEL: u32 = 0;
    unsafe extern "C" fn record_feedback_level(level: u32) {
        ptr::write_volatile(ptr::addr_of_mut!(DISPATCHED_LEVEL), level);
    }

    unsafe fn dispatch_for(adjustment: u16, delta: u32) -> (u32, InputFeedbackState) {
        ptr::write_volatile(ptr::addr_of_mut!(INPUT_FEEDBACK_ADJUSTMENT), adjustment);
        ptr::write_volatile(
            ptr::addr_of_mut!(FEEDBACK_LEVEL_DISPATCH),
            record_feedback_level,
        );
        let mut state = InputFeedbackState {
            _before_pending_feedback: [0xa5; 0x61],
            pending_feedback: 0x5a,
        };
        input_delta_feedback_update(&mut state, delta);
        (ptr::read_volatile(ptr::addr_of!(DISPATCHED_LEVEL)), state)
    }

    #[test]
    fn positive_adjustment_uses_every_threshold_and_clears_pending_feedback() {
        let _guard = TEST_LOCK.lock();
        for (delta, expected) in [
            (0, 1),
            (99, 1),
            (100, 4),
            (199, 4),
            (200, 5),
            (499, 5),
            (500, 6),
            (999, 6),
            (1000, 7),
        ] {
            let (level, state) = unsafe { dispatch_for(0, delta) };
            assert_eq!(level, expected, "delta={delta}");
            assert_eq!(state.pending_feedback, 0, "delta={delta}");
        }
    }

    #[test]
    fn negative_adjustment_requires_its_full_twos_complement_magnitude() {
        let _guard = TEST_LOCK.lock();
        for (delta, expected) in [(0, 1), (1, 1), (100, 1), (101, 4), (1001, 7)] {
            let (level, state) = unsafe { dispatch_for(0xffff, delta) };
            assert_eq!(level, expected, "delta={delta}");
            assert_eq!(state.pending_feedback, 0, "delta={delta}");
        }
    }

    #[test]
    fn sign_bit_adjustment_does_not_wrap_when_delta_is_too_small() {
        let _guard = TEST_LOCK.lock();
        for (delta, expected) in [(0x7fff, 1), (0x8000, 1), (0x8064, 4)] {
            let (level, _) = unsafe { dispatch_for(0x8000, delta) };
            assert_eq!(level, expected, "delta={delta:#x}");
        }
    }
}
