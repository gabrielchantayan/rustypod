//! Panel scale-mode setter — original: `FUN_08169be0` @ 0x08169be0.
//!
//! Raw `osos.dec` words establish a 120-byte A32 body
//! `0x08169be0..0x08169be58`; `0x08169be5c..0x08169be64` is its literal pool,
//! and the next real function starts at `0x08169be68`. The body has four
//! unconditional `bl` instructions and no predicated calls. Modes 0 and 1
//! update the shared panel scale state and notify the supplied panel object;
//! other modes return -1 without side effects. Mode 1 scales the float at
//! `state+0x18` by 2/3, replaces the unsigned word at `state+0x24` with
//! `(old << 2) / 3`, and changes the scale limit at `state+0x28` from 0.75 to
//! 0.5625.
//!
//! Deliberate deviation: the notification callee at 0x0816a530 has no known
//! identity. Firmware builds call that exact original entry; host builds use a
//! replaceable test callback.

use crate::fp::fp_fmuldiv::__fdiv;
use crate::fp::fp_scalb::__fscalb;

const PANEL_SCALE_STATE_ADDRESS: usize = 0x089c_c9b4;
const MODE_ZERO_SCALE_LIMIT: u32 = 0x3f40_0000;
const MODE_ONE_SCALE_LIMIT: u32 = 0x3f10_0000;
const THREE_F32: u32 = 0x4040_0000;

#[cfg(not(target_os = "none"))]
static mut PANEL_SCALE_STATE: *mut u8 = PANEL_SCALE_STATE_ADDRESS as *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn panel_scale_state() -> *mut u8 {
    PANEL_SCALE_STATE_ADDRESS as *mut u8
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn panel_scale_state() -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(PANEL_SCALE_STATE))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn notify_panel_mode_changed(panel: *mut u8, enabled: u32) {
    let notify: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(0x0816_a530usize);
    notify(panel, enabled);
}

#[cfg(not(target_os = "none"))]
static mut PANEL_MODE_NOTIFICATION: unsafe extern "C" fn(*mut u8, u32) = panel_mode_notification_stub;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn panel_mode_notification_stub(_panel: *mut u8, _enabled: u32) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn notify_panel_mode_changed(panel: *mut u8, enabled: u32) {
    let notify = core::ptr::read_volatile(core::ptr::addr_of!(PANEL_MODE_NOTIFICATION));
    notify(panel, enabled);
}

/// Sets the panel's scale mode. Returns zero for modes 0 and 1, otherwise -1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn panel_set_scale_mode(panel: *mut u8, mode: u32) -> i32 {
    if mode >= 2 {
        return -1;
    }

    let state = panel_scale_state();
    state.add(1).write(mode as u8);
    state.add(0x28).cast::<u32>().write(MODE_ZERO_SCALE_LIMIT);

    if mode == 1 {
        let scale = state.add(0x18).cast::<u32>();
        scale.write(__fdiv(__fscalb(scale.read(), 2), THREE_F32));

        let count = state.add(0x24).cast::<u32>();
        count.write(count.read().wrapping_shl(2) / 3);
        state.add(0x28).cast::<u32>().write(MODE_ONE_SCALE_LIMIT);
    }

    notify_panel_mode_changed(panel, mode);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static NOTIFY_PANEL: AtomicUsize = AtomicUsize::new(0);
    static NOTIFY_ENABLED: AtomicU32 = AtomicU32::new(u32::MAX);

    unsafe extern "C" fn record_notification(panel: *mut u8, enabled: u32) {
        NOTIFY_PANEL.store(panel as usize, Ordering::SeqCst);
        NOTIFY_ENABLED.store(enabled, Ordering::SeqCst);
    }

    struct Restore {
        state: *mut u8,
        notification: unsafe extern "C" fn(*mut u8, u32),
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                PANEL_SCALE_STATE = self.state;
                PANEL_MODE_NOTIFICATION = self.notification;
            }
        }
    }

    fn install(state: *mut u8) -> Restore {
        let lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        NOTIFY_PANEL.store(0, Ordering::SeqCst);
        NOTIFY_ENABLED.store(u32::MAX, Ordering::SeqCst);
        unsafe {
            let old_state = PANEL_SCALE_STATE;
            let old_notification = PANEL_MODE_NOTIFICATION;
            PANEL_SCALE_STATE = state;
            PANEL_MODE_NOTIFICATION = record_notification;
            Restore { state: old_state, notification: old_notification, _lock: lock }
        }
    }

    #[test]
    fn mode_zero_sets_the_default_limit_and_notifies() {
        let mut state = [0xa5u8; 0x2c];
        let _restore = install(state.as_mut_ptr());
        let mut panel = [0u8; 0x1e8];

        assert_eq!(unsafe { panel_set_scale_mode(panel.as_mut_ptr(), 0) }, 0);
        assert_eq!(state[1], 0);
        assert_eq!(unsafe { state.as_ptr().add(0x28).cast::<u32>().read_unaligned() }, MODE_ZERO_SCALE_LIMIT);
        assert_eq!(NOTIFY_PANEL.load(Ordering::SeqCst), panel.as_mut_ptr() as usize);
        assert_eq!(NOTIFY_ENABLED.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mode_one_scales_both_state_values() {
        let mut state = [0u8; 0x2c];
        unsafe {
            state.as_mut_ptr().add(0x18).cast::<u32>().write_unaligned(1.5f32.to_bits());
            state.as_mut_ptr().add(0x24).cast::<u32>().write_unaligned(11);
        }
        let _restore = install(state.as_mut_ptr());
        let mut panel = [0u8; 0x1e8];

        assert_eq!(unsafe { panel_set_scale_mode(panel.as_mut_ptr(), 1) }, 0);
        assert_eq!(state[1], 1);
        assert_eq!(unsafe { state.as_ptr().add(0x18).cast::<u32>().read_unaligned() }, 2.0f32.to_bits());
        assert_eq!(unsafe { state.as_ptr().add(0x24).cast::<u32>().read_unaligned() }, 14);
        assert_eq!(unsafe { state.as_ptr().add(0x28).cast::<u32>().read_unaligned() }, MODE_ONE_SCALE_LIMIT);
        assert_eq!(NOTIFY_ENABLED.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn invalid_modes_leave_state_and_notification_untouched() {
        let mut state = [0x5au8; 0x2c];
        let before = state;
        let _restore = install(state.as_mut_ptr());

        assert_eq!(unsafe { panel_set_scale_mode(core::ptr::null_mut(), 2) }, -1);
        assert_eq!(state, before);
        assert_eq!(NOTIFY_ENABLED.load(Ordering::SeqCst), u32::MAX);
    }
}
