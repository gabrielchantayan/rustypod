//! Selection-step animation — `FUN_081ea54c` at 0x081ea54c.
//!
//! Raw extent: 160 bytes, ending at 0x081ea5ec (the next function's push).
//! Verified callers: 2 plain BL, 0 predicated BL. Body: 6 plain BL and one
//! BLX through vtable +0x114. Always invalidate; for nonzero delta, wrap-add
//! the selected index at +0x124, snapshot +0x11c as Q16.16, resolve the new
//! endpoint virtually, arm a 75-ms transition, rebind the animation, register
//! the embedded callback, and notify with 1. No bounds check is performed.
//!
//! Deliberate deviations: typed word indexing preserves the 32-bit layout on
//! hosts. Existing Rust helpers replace direct firmware calls. The existing
//! status-value notifier seam retains the unported 0x0806e488 boundary.
//! Host-replaceable operations permit exercising state transitions without
//! device globals; target endpoint dispatch still reads vtable slot +0x114.

use crate::app::animation::{animation_set_values, Animation};
use crate::app::fixed_value::FixedValue;
use crate::app::global_callback_register::global_callback_register;
use crate::app::timed_transition::{timed_transition_init, TimedTransition};
use crate::drivers::timer::usec_timer_read_seconds;
use crate::ui::invalidate::ui_element_invalidate;

unsafe extern "C" fn selection_endpoint(owner: *mut u32, index: u32) -> u32 {
    let vtable = *owner as usize as *const u32;
    let resolve: unsafe extern "C" fn(*mut u32, u32) -> u32 =
        core::mem::transmute(*vtable.add(0x114 / 4) as usize);
    resolve(owner, index)
}

unsafe extern "C" fn selection_notify(value: u32) {
    let notify = core::ptr::read_volatile(core::ptr::addr_of!(
        crate::app::status_value_set::STATUS_VALUE_SET_OPS.notify));
    notify(value);
}

#[derive(Clone, Copy)]
pub struct SelectionStepOps {
    pub invalidate: unsafe extern "C" fn(*mut u8) -> *mut u8,
    pub endpoint: unsafe extern "C" fn(*mut u32, u32) -> u32,
    pub seconds: unsafe extern "C" fn() -> u32,
    pub transition: unsafe extern "C" fn(*mut TimedTransition, u32, u32, u32, u32, u32) -> *mut TimedTransition,
    pub bind: unsafe extern "C" fn(*mut Animation, *mut FixedValue, *mut FixedValue, *mut FixedValue),
    pub register: unsafe extern "C" fn(u32),
    pub notify: unsafe extern "C" fn(u32),
}

const DEFAULT_SELECTION_STEP_OPS: SelectionStepOps = SelectionStepOps {
    invalidate: ui_element_invalidate,
    endpoint: selection_endpoint,
    seconds: usec_timer_read_seconds,
    transition: timed_transition_init,
    bind: animation_set_values,
    register: global_callback_register,
    notify: selection_notify,
};

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_STEP_OPS: SelectionStepOps = DEFAULT_SELECTION_STEP_OPS;

/// # Safety
/// `owner` covers at least 0x1b4 bytes of live retail view state, including
/// initialized value/animation nodes and a valid vtable endpoint method.
/// Device globals and installed operations must satisfy their helper contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_step_animate(owner: *mut u32, delta: i32) {
    #[cfg(target_os = "none")]
    let ops = DEFAULT_SELECTION_STEP_OPS;
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_STEP_OPS));
    (ops.invalidate)(owner.cast());
    if delta == 0 { return; }
    let index = (*owner.add(0x49)).wrapping_add(delta as u32);
    *owner.add(0x49) = index;
    *owner.add(0x4c) = (*owner.add(0x47)).wrapping_shl(16);
    *owner.add(0x4d) = 0;
    let endpoint = (ops.endpoint)(owner, index);
    *owner.add(0x52) = endpoint.wrapping_shl(16);
    *owner.add(0x53) = 0;
    let seconds = (ops.seconds)();
    (ops.transition)(owner.add(0x60).cast(), seconds, 75, 0, 0, 0);
    (ops.bind)(owner.add(0x57).cast(), owner.add(0x60).cast(),
        owner.add(0x4b).cast(), owner.add(0x51).cast());
    (ops.register)(owner.add(0x29) as usize as u32);
    (ops.notify)(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut INVALIDATIONS: u32 = 0;
    static mut COMPLETIONS: u32 = 0;

    unsafe extern "C" fn invalidate(p: *mut u8) -> *mut u8 {
        INVALIDATIONS += 1;
        p
    }
    unsafe extern "C" fn endpoint(p: *mut u32, index: u32) -> u32 {
        assert_eq!(*p.add(0x49), index);
        assert_eq!(*p.add(0x4c), 0x8001_0000);
        assert_eq!(*p.add(0x4d), 0);
        index.wrapping_mul(3).wrapping_add(0x1234)
    }
    unsafe extern "C" fn seconds() -> u32 { 0xffff_fffe }
    unsafe extern "C" fn transition(p: *mut TimedTransition, _: u32, _: u32,
        _: u32, _: u32, _: u32) -> *mut TimedTransition {
        p
    }
    unsafe extern "C" fn bind(p: *mut Animation, _: *mut FixedValue,
        _: *mut FixedValue, _: *mut FixedValue) {
        let owner = p.cast::<u32>().sub(0x57);
        let index = *owner.add(0x49);
        assert_eq!(*owner.add(0x52), index.wrapping_mul(3).wrapping_add(0x1234) << 16);
        assert_eq!(*owner.add(0x53), 0);
    }
    unsafe extern "C" fn register(_: u32) {}
    unsafe extern "C" fn notify(_: u32) {
        COMPLETIONS += 1;
    }

    #[test]
    fn zero_preserves_state_and_nonzero_wraps_without_clamping() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = core::ptr::read(core::ptr::addr_of!(SELECTION_STEP_OPS));
            SELECTION_STEP_OPS = SelectionStepOps { invalidate, endpoint, seconds,
                transition, bind, register, notify };
            INVALIDATIONS = 0;
            COMPLETIONS = 0;
            for (initial, delta) in [(0, 0), (0, -1), (u32::MAX, 1),
                (0x7fff_ffff, 1), (17, i32::MIN), (17, i32::MAX)] {
                let mut words = [0xa5a5_a5a5; 0x6d];
                words[0x47] = 0xffff_8001;
                words[0x49] = initial;
                let before = words;
                selection_step_animate(words.as_mut_ptr(), delta);
                if delta == 0 {
                    assert_eq!(words, before);
                } else {
                    let mut expected = before;
                    expected[0x49] = initial.wrapping_add(delta as u32);
                    expected[0x4c] = 0x8001_0000;
                    expected[0x4d] = 0;
                    expected[0x52] = expected[0x49].wrapping_mul(3).wrapping_add(0x1234) << 16;
                    expected[0x53] = 0;
                    assert_eq!(words, expected);
                }
            }
            assert_eq!(core::ptr::read(core::ptr::addr_of!(INVALIDATIONS)), 6);
            assert_eq!(core::ptr::read(core::ptr::addr_of!(COMPLETIONS)), 5);
            SELECTION_STEP_OPS = saved;
        }
    }
}
