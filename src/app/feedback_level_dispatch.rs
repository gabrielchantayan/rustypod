//! `feedback_level_dispatch` — original: `FUN_080cc978` at load address
//! `0x080cc978`, 92 bytes (84 bytes of ARM code plus one trailing literal).
//!
//! # Verified behavior
//!
//! Decoding every ARM `B`/`BL`-immediate word in `osos.dec` finds six inbound
//! direct `bl` calls, all unconditional: `0x080609a0`, `0x080609e8`,
//! `0x08086290`, `0x081490e8`, `0x081490f8`, and `0x08205f94`. Three direct
//! tail branches also enter it: unconditional `b` at `0x0808c640` and
//! `0x08293314`, plus `beq` at `0x08205fb8`; there are no predicated `bl`
//! calls. It first invokes retail helper `0x082e5aac` with the requested
//! signed level, stores that level's low byte at `0x089cab58`, and tells
//! retail helper `0x082bc9ec` whether the signed level exceeds three. It then
//! compares the signed cached byte at `0x089cab59` against the signed
//! `level > 4` predicate. Matching classes suppress notification unless the
//! cache is the -1 sentinel. Otherwise it updates that cache byte and tail
//! dispatches event code four through retail thunk `0x0809eab4`.
//!
//! # Deliberate deviation
//!
//! The target implementation retains the three unported helper calls and the
//! event thunk through literal veneers. Host builds use callback seams for the
//! two stateful helpers and the existing event-dispatch host seam; the tiny
//! `0x0807d548` predicate is represented directly as its verified signed
//! comparison.

/// The two runtime level bytes at retail address `0x089cab58`.
#[repr(C)]
pub struct FeedbackLevelState {
    /// Low byte of the most recently requested level.
    pub current_level: i8,
    /// Last level which crossed the notification-class boundary, or -1.
    pub notified_level: i8,
}

/// ABI of retail helper `0x082e5aac`, which receives the requested level.
pub type FeedbackLevelPrepare = unsafe extern "C" fn(level: i32);
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_feedback_level_prepare(_level: i32) {}


/// Host replacement for the two runtime bytes at `0x089cab58`.
#[cfg(not(target_os = "none"))]
pub static mut FEEDBACK_LEVEL_STATE: FeedbackLevelState = FeedbackLevelState {
    current_level: 0,
    notified_level: 0,
};

/// Host replacement for retail helper `0x082e5aac`.
#[cfg(not(target_arch = "arm"))]
pub static mut FEEDBACK_LEVEL_PREPARE: FeedbackLevelPrepare = missing_feedback_level_prepare;

#[cfg(target_os = "none")]
const FEEDBACK_LEVEL_STATE: *mut FeedbackLevelState = 0x089c_ab58 as *mut FeedbackLevelState;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn feedback_level_state_ptr() -> *mut FeedbackLevelState {
    core::ptr::addr_of_mut!(FEEDBACK_LEVEL_STATE)
}

/// Updates the shared feedback-level bytes and emits event code four only when
/// the level crosses the signed `> 4` class boundary or the cache is -1.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn feedback_level_dispatch(level: i32) {
    core::ptr::read_volatile(core::ptr::addr_of!(FEEDBACK_LEVEL_PREPARE))(level);

    let state = feedback_level_state_ptr();
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).current_level), level as i8);
    crate::app::feedback_level_mode_set::feedback_level_mode_set((level > 3) as u32);

    let notified_level = core::ptr::read_volatile(core::ptr::addr_of!((*state).notified_level));
    if (notified_level > 4) == (level > 4) && notified_level != -1 {
        return;
    }

    core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).notified_level), level as i8);
    crate::app::event_code_dispatch::event_code_dispatch_unflagged(4);
}

// The original contains 84 bytes of code followed by the state-address
// literal. The prepare helper, predicate, and event thunk remain literal
// veneers because payload placement cannot change their fixed retailOS destinations.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl feedback_level_dispatch
    .type feedback_level_dispatch, %function
feedback_level_dispatch:
    push    {{r4, r5, r6, lr}}
    mov     r4, r0
    bl      retail_feedback_level_prepare
    ldr     r5, 1f
    cmp     r4, #3
    movgt   r0, #1
    movle   r0, #0
    strb    r4, [r5]
    bl      feedback_level_mode_set
    ldrsb   r0, [r5, #1]
    bl      retail_feedback_level_is_high
    cmp     r4, #4
    movle   r1, #0
    movgt   r1, #1
    cmp     r0, r1
    bne     0f
    ldrsb   r0, [r5, #1]
    cmn     r0, #1
    popne   {{r4, r5, r6, pc}}
0:
    strb    r4, [r5, #1]
    pop     {{r4, r5, r6, lr}}
    mov     r0, #4
    b       retail_feedback_level_event_dispatch
1:  .word   0x089cab58
    .size feedback_level_dispatch, . - feedback_level_dispatch

retail_feedback_level_prepare:
    ldr     pc, [pc, #-4]
    .word   0x082e5aac
    .size retail_feedback_level_prepare, . - retail_feedback_level_prepare


retail_feedback_level_is_high:
    ldr     pc, [pc, #-4]
    .word   0x0807d548
    .size retail_feedback_level_is_high, . - retail_feedback_level_is_high

retail_feedback_level_event_dispatch:
    ldr     pc, [pc, #-4]
    .word   0x0809eab4
    .size retail_feedback_level_event_dispatch, . - retail_feedback_level_event_dispatch
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::event_code_dispatch::{
        missing_event_code_map, EVENT_CODE_DISPATCH, EVENT_CODE_DISPATCH_TEST_LOCK, EVENT_CODE_MAP,
    };
    use crate::app::feedback_level_mode_set::{
        missing_feedback_mode_apply, missing_feedback_mode_profile, FEEDBACK_MODE_APPLY,
        FEEDBACK_MODE_PROFILE,
    };

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut PREPARE_CALLS: u32 = 0;
    static mut PREPARED_LEVEL: i32 = 0;
    static mut MODE_CALLS: u32 = 0;
    static mut MODE_VALUE: u32 = 0;
    static mut EVENT_CALLS: u32 = 0;
    static mut EVENT_CODE: u32 = 0;
    static mut EVENT_FLAG: u32 = 0;

    unsafe extern "C" fn record_prepare(level: i32) {
        PREPARE_CALLS += 1;
        PREPARED_LEVEL = level;
    }

    unsafe extern "C" fn record_mode(is_above_three: u32) -> u32 {
        MODE_CALLS += 1;
        MODE_VALUE = is_above_three;
        0
    }

    unsafe extern "C" fn profile_is_one() -> u32 {
        1
    }

    unsafe extern "C" fn record_event(event_code: u32, flag: u32) {
        EVENT_CALLS += 1;
        EVENT_CODE = event_code;
        EVENT_FLAG = flag;
    }

    unsafe extern "C" fn map_event_code(_event_code: u32, mapped_code: *mut u8) -> u32 {
        core::ptr::write(mapped_code, 4);
        1
    }
    unsafe extern "C" fn missing_event(_event_code: u32, _flag: u32) {}

    unsafe fn install(initial_notified_level: i8) {
        FEEDBACK_LEVEL_STATE = FeedbackLevelState {
            current_level: 0x55,
            notified_level: initial_notified_level,
        };
        FEEDBACK_LEVEL_PREPARE = record_prepare;
        FEEDBACK_MODE_PROFILE = profile_is_one;
        FEEDBACK_MODE_APPLY = record_mode;
        EVENT_CODE_MAP = map_event_code;
        EVENT_CODE_DISPATCH = record_event;
        PREPARE_CALLS = 0;
        PREPARED_LEVEL = 0;
        MODE_CALLS = 0;
        MODE_VALUE = 0;
        EVENT_CALLS = 0;
        EVENT_CODE = 0;
        EVENT_FLAG = 0;
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                FEEDBACK_LEVEL_PREPARE = missing_feedback_level_prepare;
                FEEDBACK_MODE_PROFILE = missing_feedback_mode_profile;
                FEEDBACK_MODE_APPLY = missing_feedback_mode_apply;
                EVENT_CODE_MAP = missing_event_code_map;
                EVENT_CODE_DISPATCH = missing_event;
            }
        }
    }

    #[test]
    fn sentinel_cache_notifies_and_propagates_the_requested_level() {
        let _event_guard = EVENT_CODE_DISPATCH_TEST_LOCK.lock();
        let _guard = TEST_LOCK.lock();
        let _reset = Reset;
        unsafe {
            install(-1);
            feedback_level_dispatch(4);
            assert_eq!(PREPARE_CALLS, 1);
            assert_eq!(PREPARED_LEVEL, 4);
            assert_eq!(MODE_CALLS, 1);
            assert_eq!(MODE_VALUE, 1);
            assert_eq!(FEEDBACK_LEVEL_STATE.current_level, 4);
            assert_eq!(FEEDBACK_LEVEL_STATE.notified_level, 4);
            assert_eq!(EVENT_CALLS, 1);
            assert_eq!(EVENT_CODE, 4);
            assert_eq!(EVENT_FLAG, 0);
        }
    }

    #[test]
    fn matching_notification_classes_preserve_the_cache_and_skip_the_event() {
        let _event_guard = EVENT_CODE_DISPATCH_TEST_LOCK.lock();
        let _guard = TEST_LOCK.lock();
        let _reset = Reset;
        unsafe {
            install(5);
            feedback_level_dispatch(127);

            assert_eq!(PREPARE_CALLS, 1);
            assert_eq!(MODE_VALUE, 1);
            assert_eq!(FEEDBACK_LEVEL_STATE.current_level, 127);
            assert_eq!(FEEDBACK_LEVEL_STATE.notified_level, 5);
            assert_eq!(EVENT_CALLS, 0);

            install(-8);
            feedback_level_dispatch(-20);
            assert_eq!(MODE_VALUE, 0);
            assert_eq!(FEEDBACK_LEVEL_STATE.current_level, -20);
            assert_eq!(FEEDBACK_LEVEL_STATE.notified_level, -8);
            assert_eq!(EVENT_CALLS, 0);
        }
    }

    #[test]
    fn boundary_crossing_uses_signed_level_before_truncating_the_cache_byte() {
        let _event_guard = EVENT_CODE_DISPATCH_TEST_LOCK.lock();
        let _guard = TEST_LOCK.lock();
        let _reset = Reset;
        unsafe {
            install(4);
            feedback_level_dispatch(260);

            assert_eq!(PREPARED_LEVEL, 260);
            assert_eq!(MODE_VALUE, 1);
            assert_eq!(FEEDBACK_LEVEL_STATE.current_level, 4);
            assert_eq!(FEEDBACK_LEVEL_STATE.notified_level, 4);
            assert_eq!(EVENT_CALLS, 1);
            assert_eq!(EVENT_CODE, 4);
            assert_eq!(EVENT_FLAG, 0);
        }
    }
}
