//! `set_clamped_mode_position` — original: `FUN_081cc5b8` @ `0x081cc5b8`
//! (**96 bytes**, `0x081cc5b8..0x081cc618`).
//!
//! Raw ARM loads signed lower and upper limits from `state+0x8bc` and
//! `state+0x8c0`, respectively, clamps the requested position to that range,
//! and compares it with the active backend position returned by
//! `mode_selected_position(state + 0x1c)`. A different backend position is
//! installed through the unported mode-selected setter at `0x0822ba50` with
//! mode argument 1. Independently, a changed cached position at `state+0x8b8`
//! is stored and passed to the unported notification continuation at
//! `0x081cccac`.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds 10 direct `bl` call
//! sites: nine unconditional (`0x0819dbb4`, `0x0819dcac`, `0x081cba70`,
//! `0x081cbc3c`, `0x081cc944`, `0x081cca64`, `0x081cca78`, `0x081cce74`, and
//! `0x081ccfec`) and one `blne` (`0x081cbfdc`). Two additional unconditional
//! tail branches enter at `0x081cbbf0` and `0x081cd5b4`; no aligned DATA word
//! targets this entry. The next separately linked function starts at
//! `0x081cc618`.
//!
//! Deliberate deviations: the two unported continuations are fixed-address
//! calls on ARM and replaceable host seams for behavior tests.

use super::mode_selected_position::mode_selected_position;

const BACKEND_OFFSET: usize = 0x1c;
const CACHED_POSITION_OFFSET: usize = 0x8b8;
const LOWER_POSITION_OFFSET: usize = 0x8bc;
const UPPER_POSITION_OFFSET: usize = 0x8c0;

pub type ModePositionSetter = unsafe extern "C" fn(*mut u8, u32, u32);
pub type PositionChanged = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_mode_position_setter(_state: *mut u8, _mode: u32, _position: u32) {}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_position_changed(_state: *mut u8) {}

/// Host replacement for the unported mode-selected setter at `0x0822ba50`.
#[cfg(not(target_arch = "arm"))]
pub static mut MODE_POSITION_SETTER: ModePositionSetter = missing_mode_position_setter;

/// Host replacement for the unported position-change continuation at `0x081cccac`.
#[cfg(not(target_arch = "arm"))]
pub static mut MODE_POSITION_CHANGED: PositionChanged = missing_position_changed;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn set_backend_position(state: *mut u8, position: u32) {
    let setter: ModePositionSetter = core::mem::transmute(0x0822_ba50usize);
    setter(state, 1, position)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn set_backend_position(state: *mut u8, position: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(MODE_POSITION_SETTER))(state, 1, position)
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn position_changed(state: *mut u8) {
    let notify: PositionChanged = core::mem::transmute(0x081c_ccacusize);
    notify(state)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn position_changed(state: *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(MODE_POSITION_CHANGED))(state)
}

/// Clamps and installs a mode-selected position, notifying only for cache changes.
///
/// # Safety
///
/// `state` must be non-NULL and four-byte aligned, with readable and writable
/// words at `+0x8b8`, `+0x8bc`, and `+0x8c0`; it must also contain the embedded
/// backend at `+0x1c` required by [`mode_selected_position`]. The retail ARM
/// sequence has no NULL, bounds, or alignment guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn set_clamped_mode_position(state: *mut u8, requested_position: u32) {
    let upper = state.add(UPPER_POSITION_OFFSET).cast::<i32>().read();
    let requested = requested_position as i32;
    let position = if upper < requested {
        upper
    } else {
        let lower = state.add(LOWER_POSITION_OFFSET).cast::<i32>().read();
        if requested < lower { lower } else { requested }
    } as u32;

    let backend = state.add(BACKEND_OFFSET);
    if mode_selected_position(backend) != position {
        set_backend_position(backend, position);
    }

    if state.add(CACHED_POSITION_OFFSET).cast::<u32>().read() != position {
        state.add(CACHED_POSITION_OFFSET).cast::<u32>().write(position);
        position_changed(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    const STATE_BYTES: usize = UPPER_POSITION_OFFSET + core::mem::size_of::<u32>();
    const MODE_POSITION_OFFSET: usize = BACKEND_OFFSET + 0x2ec;
    const DEFAULT_POSITION_OFFSET: usize = BACKEND_OFFSET + 0x5e4;
    const MODE_FLAGS_OFFSET: usize = BACKEND_OFFSET + 0x5f8;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SETTER_STATE: *mut u8 = core::ptr::null_mut();
    static mut SETTER_MODE: u32 = 0;
    static mut SETTER_POSITION: u32 = 0;
    static mut SETTER_CALLS: u32 = 0;
    static mut NOTIFIED_STATE: *mut u8 = core::ptr::null_mut();
    static mut NOTIFICATION_CALLS: u32 = 0;

    #[repr(align(4))]
    struct State([u8; STATE_BYTES]);

    unsafe extern "C" fn record_setter(state: *mut u8, mode: u32, position: u32) {
        SETTER_STATE = state;
        SETTER_MODE = mode;
        SETTER_POSITION = position;
        SETTER_CALLS += 1;
    }

    unsafe extern "C" fn record_notification(state: *mut u8) {
        NOTIFIED_STATE = state;
        NOTIFICATION_CALLS += 1;
    }

    unsafe fn write_word(state: &mut State, offset: usize, value: u32) {
        state.0.as_mut_ptr().add(offset).cast::<u32>().write(value);
    }

    unsafe fn reset_seams() {
        MODE_POSITION_SETTER = record_setter;
        MODE_POSITION_CHANGED = record_notification;
        SETTER_STATE = core::ptr::null_mut();
        SETTER_MODE = 0;
        SETTER_POSITION = 0;
        SETTER_CALLS = 0;
        NOTIFIED_STATE = core::ptr::null_mut();
        NOTIFICATION_CALLS = 0;
    }

    #[test]
    fn clamps_signed_bounds_and_updates_both_observable_paths() {
        let _guard = TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            reset_seams();
            write_word(&mut state, LOWER_POSITION_OFFSET, (-10i32) as u32);
            write_word(&mut state, UPPER_POSITION_OFFSET, 10);
            write_word(&mut state, CACHED_POSITION_OFFSET, 0);
            write_word(&mut state, MODE_POSITION_OFFSET, 7);
            write_word(&mut state, DEFAULT_POSITION_OFFSET, 0);
            state.0[MODE_FLAGS_OFFSET] = 1;

            set_clamped_mode_position(state.0.as_mut_ptr(), i32::MIN as u32);

            assert_eq!(state.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), (-10i32) as u32);
            assert_eq!(SETTER_CALLS, 1);
            assert_eq!(SETTER_STATE, state.0.as_mut_ptr().add(BACKEND_OFFSET));
            assert_eq!(SETTER_MODE, 1);
            assert_eq!(SETTER_POSITION, (-10i32) as u32);
            assert_eq!(NOTIFICATION_CALLS, 1);
            assert_eq!(NOTIFIED_STATE, state.0.as_mut_ptr());
        }
    }

    #[test]
    fn skips_backend_setter_when_active_position_already_matches() {
        let _guard = TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            reset_seams();
            write_word(&mut state, LOWER_POSITION_OFFSET, 10);
            write_word(&mut state, UPPER_POSITION_OFFSET, 20);
            write_word(&mut state, CACHED_POSITION_OFFSET, 0);
            write_word(&mut state, DEFAULT_POSITION_OFFSET, 20);
            state.0[MODE_FLAGS_OFFSET] = 0;

            set_clamped_mode_position(state.0.as_mut_ptr(), i32::MAX as u32);

            assert_eq!(SETTER_CALLS, 0);
            assert_eq!(state.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), 20);
            assert_eq!(NOTIFICATION_CALLS, 1);
        }
    }

    #[test]
    fn backend_update_does_not_notify_when_cached_position_is_unchanged() {
        let _guard = TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            reset_seams();
            write_word(&mut state, LOWER_POSITION_OFFSET, 10);
            write_word(&mut state, UPPER_POSITION_OFFSET, 20);
            write_word(&mut state, CACHED_POSITION_OFFSET, 15);
            write_word(&mut state, MODE_POSITION_OFFSET, 10);
            state.0[MODE_FLAGS_OFFSET] = 1;

            set_clamped_mode_position(state.0.as_mut_ptr(), 15);

            assert_eq!(SETTER_CALLS, 1);
            assert_eq!(SETTER_POSITION, 15);
            assert_eq!(NOTIFICATION_CALLS, 0);
        }
    }
}
