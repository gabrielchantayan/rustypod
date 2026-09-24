//! Posts a transition-specific notification to the framework root.
//!
//! `context_transition_notification` — original: `FUN_08116b6c` @
//! **0x08116b6c** (**76 bytes**, `0x08116b6c..0x08116bb7`; eighteen ARM
//! instruction words plus the `0x0001d4c0` literal at `0x08116bb8`). Raw
//! bytes show the next separately linked function begins with `push
//! {r4,r5,r6,lr}` at `0x08116bbc`; Ghidra's 76-byte extent includes the
//! literal. Binary-wide decoding finds **3 unconditional `bl` callers**
//! (`0x08114aac`, `0x08114ae0`, `0x08115bc4`) and **zero predicated `bl`
//! callers. The body itself has three unconditional direct `bl` instructions,
//! no predicated `bl`, and tail-branches to `framework_root_post_message`.
//!
//! # Algorithm
//!
//! Refresh the class-0x8c00 two-minute timer. If `use_first_code == 0`, run
//! the context transition preparation routine and post `second_code`; otherwise
//! post `first_code`. The final post is the retail tail branch to
//! `FUN_081d2408`.
//!
//! # Deliberate deviations
//!
//! `FUN_0811666c` has no established semantic Rust port. On the target this
//! port calls that exact retail address; host tests inject the preparation
//! action. The already ported tail target is called normally, returning its
//! status even though stock preserves it only incidentally in `r0`.

use crate::app::class_8c00::class_8c00_rearm_timer_post_0x11;
use crate::app::framework_root_message_post::framework_root_post_message;
use crate::app::singletons::singleton_class_8c00;
use crate::app::registry::instance_of_class_6000;

const TIMER_REFRESH_DELAY_MS: u32 = 0x0001_d4c0;
const CONTEXT_TRANSITION_PREPARE_ADDRESS: usize = 0x0811_666c;

type ContextTransitionPrepare = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_transition_prepare(context: *mut u8) {
    let prepare: ContextTransitionPrepare = unsafe { core::mem::transmute(CONTEXT_TRANSITION_PREPARE_ADDRESS) };
    unsafe { prepare(context) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn context_transition_prepare(_: *mut u8) {
    panic!("context_transition_notification requires FUN_0811666c")
}

macro_rules! context_transition_notification_body {
    ($context:expr, $use_first_code:expr, $first_code:expr, $second_code:expr;
     $class_6000:path, $singleton:path, $rearm:path, $prepare:path, $post:path) => {{
        if unsafe { $class_6000() }.is_null() {
            0
        } else {
            unsafe { $rearm($singleton(), TIMER_REFRESH_DELAY_MS) };
            let message_code = if $use_first_code != 0 {
                $first_code
            } else {
                unsafe { $prepare($context) };
                $second_code
            };
            unsafe { $post(message_code) }
        }
    }};
}

/// context_transition_notification — original: `FUN_08116b6c` @ `0x08116b6c`.
/// See the module header for raw extent and call-site evidence.
///
/// # Safety
///
/// `context` must meet `FUN_0811666c`'s unguarded preconditions when
/// `use_first_code == 0`; the class-0x8c00 singleton and framework-root
/// message path must be initialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.context_transition_notification"))]
pub unsafe extern "C" fn context_transition_notification(
    context: *mut u8,
    use_first_code: u32,
    first_code: u32,
    second_code: u32,
) -> u32 {
    context_transition_notification_body!(
        context, use_first_code, first_code, second_code;
        instance_of_class_6000,
        singleton_class_8c00,
        class_8c00_rearm_timer_post_0x11,
        context_transition_prepare,
        framework_root_post_message
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 5] = [0; 5];
    static mut PREPARED_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut REARM_DELAY: u32 = 0;
    static mut POSTED_CODE: u32 = 0;

    unsafe extern "C" fn recording_class_6000() -> *mut u8 {
        CALLS[0] += 1;
        0x0600usize as *mut u8
    }

    unsafe extern "C" fn recording_singleton() -> *mut u8 {
        CALLS[1] += 1;
        0x1000usize as *mut u8
    }

    unsafe extern "C" fn recording_rearm(instance: *mut u8, delay: u32) {
        assert_eq!(instance, 0x1000usize as *mut u8);
        CALLS[2] += 1;
        REARM_DELAY = delay;
    }

    unsafe extern "C" fn recording_prepare(context: *mut u8) {
        CALLS[3] += 1;
        PREPARED_CONTEXT = context;
    }

    unsafe extern "C" fn recording_post(code: u32) -> u32 {
        CALLS[4] += 1;
        POSTED_CODE = code;
        0xa5a5_5a5a
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CALLS = [0; 5];
            PREPARED_CONTEXT = core::ptr::null_mut();
            REARM_DELAY = 0;
            POSTED_CODE = 0;
        }
        guard
    }

    fn invoke(context: *mut u8, use_first_code: u32, first_code: u32, second_code: u32) -> u32 {
        context_transition_notification_body!(
            context, use_first_code, first_code, second_code;
            recording_class_6000, recording_singleton, recording_rearm, recording_prepare, recording_post
        )
    }

    #[test]
    fn false_selects_second_code_after_preparation() {
        let guard = reset();
        let context = 0x2000usize as *mut u8;
        assert_eq!(invoke(context, 0, 0x1111_1111, 0xdead_beef), 0xa5a5_5a5a);
        unsafe {
            assert_eq!(CALLS, [1, 1, 1, 1, 1]);
            assert_eq!(REARM_DELAY, TIMER_REFRESH_DELAY_MS);
            assert_eq!(PREPARED_CONTEXT, context);
            assert_eq!(POSTED_CODE, 0xdead_beef);
        }
        drop(guard);
    }

    #[test]
    fn nonzero_selects_first_code_without_preparation() {
        let guard = reset();
        assert_eq!(invoke(core::ptr::null_mut(), u32::MAX, 0x8000_0000, 0), 0xa5a5_5a5a);
        unsafe {
            assert_eq!(CALLS, [1, 1, 1, 0, 1]);
            assert_eq!(REARM_DELAY, TIMER_REFRESH_DELAY_MS);
            assert_eq!(POSTED_CODE, 0x8000_0000);
        }
        drop(guard);
    }

    #[test]
    fn missing_class_6000_returns_zero_before_side_effects() {
        let guard = reset();
        unsafe extern "C" fn missing_class_6000() -> *mut u8 { core::ptr::null_mut() }
        assert_eq!(
            context_transition_notification_body!(
                core::ptr::null_mut(), 0, 1, 2;
                missing_class_6000, recording_singleton, recording_rearm, recording_prepare, recording_post
            ),
            0
        );
        unsafe { assert_eq!(CALLS, [0; 5]) };
        drop(guard);
    }
}
