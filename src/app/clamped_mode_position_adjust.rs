//! `adjust_clamped_mode_position` — original: `FUN_081cd090` @ `0x081cd090`
//! (**128 bytes**, `0x081cd090..0x081cd110`; the separately linked next entry
//! starts at `0x081cd110`).
//!
//! Raw ARM adds the unsigned delta to `state+0x8b8`, then uses signed compares
//! to clamp that wrapped sum to `state+0x8bc..state+0x8c0`. If the selected
//! backend position at `state+0x1c` differs, it calls
//! `mode_selected_position_set` with mode zero and the wrapped difference
//! between the clamped and active positions. It notifies the unported
//! `mode_position_changed` continuation only when the cached position changed,
//! returning one in that case and zero otherwise.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds five direct inbound
//! BL calls: three unconditional (`0x081cb6bc`, `0x081cb934`, `0x081cbfec`)
//! and two predicated `bleq` (`0x0810cf58`, `0x0810d178`). No direct tail
//! branch enters this function.
//!
//! Deliberate deviation: the unported notification continuation is the shared
//! fixed-address call on ARM and shared replaceable host seam used by
//! `set_clamped_mode_position`.

use super::{
    clamped_mode_position::PositionChanged,
    mode_selected_position::mode_selected_position,
    mode_selected_position_set::mode_selected_position_set,
};

#[cfg(not(target_arch = "arm"))]
use super::clamped_mode_position::MODE_POSITION_CHANGED;

const BACKEND_OFFSET: usize = 0x1c;
const CACHED_POSITION_OFFSET: usize = 0x8b8;
const LOWER_POSITION_OFFSET: usize = 0x8bc;
const UPPER_POSITION_OFFSET: usize = 0x8c0;

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

/// Adjusts the cached position by a signed delta, clamps it, and updates the backend.
///
/// # Safety
///
/// `state` must be non-NULL and four-byte aligned, with readable and writable
/// words at `+0x8b8`, `+0x8bc`, and `+0x8c0`; it must also contain the embedded
/// backend at `+0x1c` required by [`mode_selected_position`]. The retail ARM
/// sequence has no NULL, bounds, or alignment guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn adjust_clamped_mode_position(state: *mut u8, delta: u32) -> u32 {
    let cached = state.add(CACHED_POSITION_OFFSET).cast::<u32>();
    let previous = cached.read();
    let sum = previous.wrapping_add(delta);
    cached.write(sum);

    let lower = state.add(LOWER_POSITION_OFFSET).cast::<i32>().read();
    let upper = state.add(UPPER_POSITION_OFFSET).cast::<i32>().read();
    let position = if (sum as i32) < lower {
        lower as u32
    } else if upper < sum as i32 {
        upper as u32
    } else {
        sum
    };
    cached.write(position);

    let backend = state.add(BACKEND_OFFSET);
    let active = mode_selected_position(backend);
    if active != position {
        let _ = mode_selected_position_set(backend, 0, position.wrapping_sub(active));
    }

    if position != previous {
        position_changed(state);
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{
        clamped_mode_position::MODE_POSITION_CHANGED_TEST_LOCK,
        mode_selected_position_set::{
            MODE_SELECTED_POSITION_SET_CLEAR, MODE_SELECTED_POSITION_SET_SET,
            MODE_SELECTED_POSITION_SET_TEST_LOCK,
        },
    };

    const STATE_BYTES: usize = UPPER_POSITION_OFFSET + core::mem::size_of::<u32>();
    const MODE_POSITION_OFFSET: usize = BACKEND_OFFSET + 0x2ec;
    const DEFAULT_POSITION_OFFSET: usize = BACKEND_OFFSET + 0x5e4;
    const MODE_FLAGS_OFFSET: usize = BACKEND_OFFSET + 0x5f8;

    static mut SETTER_MODE: u32 = 0;
    static mut SETTER_DELTA: u32 = 0;
    static mut SETTER_CALLS: u32 = 0;
    static mut NOTIFICATION_CALLS: u32 = 0;

    #[repr(align(4))]
    struct State([u8; STATE_BYTES]);

    unsafe extern "C" fn record_setter(_state: *mut u8, mode: u32, delta: u32) -> u32 {
        SETTER_MODE = mode;
        SETTER_DELTA = delta;
        SETTER_CALLS += 1;
        0
    }

    unsafe extern "C" fn record_notification(_state: *mut u8) {
        NOTIFICATION_CALLS += 1;
    }

    unsafe fn write_word(state: &mut State, offset: usize, value: u32) {
        state.0.as_mut_ptr().add(offset).cast::<u32>().write(value);
    }

    unsafe fn reset_seams() {
        MODE_SELECTED_POSITION_SET_CLEAR = record_setter;
        MODE_SELECTED_POSITION_SET_SET = record_setter;
        MODE_POSITION_CHANGED = record_notification;
        SETTER_MODE = u32::MAX;
        SETTER_DELTA = 0;
        SETTER_CALLS = 0;
        NOTIFICATION_CALLS = 0;
    }

    #[test]
    fn wraps_then_clamps_signed_bounds_and_passes_backend_delta() {
        let _setter_guard = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        let _notification_guard = MODE_POSITION_CHANGED_TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            reset_seams();
            write_word(&mut state, CACHED_POSITION_OFFSET, i32::MAX as u32);
            write_word(&mut state, LOWER_POSITION_OFFSET, -20i32 as u32);
            write_word(&mut state, UPPER_POSITION_OFFSET, 20);
            write_word(&mut state, MODE_POSITION_OFFSET, 7);
            state.0[MODE_FLAGS_OFFSET] = 1;

            assert_eq!(adjust_clamped_mode_position(state.0.as_mut_ptr(), 1), 1);

            assert_eq!(state.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), -20i32 as u32);
            assert_eq!(SETTER_CALLS, 1);
            assert_eq!(SETTER_MODE, 0);
            assert_eq!(SETTER_DELTA, (-27i32) as u32);
            assert_eq!(NOTIFICATION_CALLS, 1);
        }
    }

    #[test]
    fn updates_backend_without_notification_when_cached_position_is_unchanged() {
        let _setter_guard = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        let _notification_guard = MODE_POSITION_CHANGED_TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            reset_seams();
            write_word(&mut state, CACHED_POSITION_OFFSET, 10);
            write_word(&mut state, LOWER_POSITION_OFFSET, 0);
            write_word(&mut state, UPPER_POSITION_OFFSET, 20);
            write_word(&mut state, DEFAULT_POSITION_OFFSET, 15);
            state.0[MODE_FLAGS_OFFSET] = 0;

            assert_eq!(adjust_clamped_mode_position(state.0.as_mut_ptr(), 0), 0);

            assert_eq!(SETTER_CALLS, 1);
            assert_eq!(SETTER_DELTA, (-5i32) as u32);
            assert_eq!(NOTIFICATION_CALLS, 0);
        }
    }

    #[test]
    fn lower_bound_wins_when_bounds_are_reversed() {
        let _setter_guard = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        let _notification_guard = MODE_POSITION_CHANGED_TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            reset_seams();
            write_word(&mut state, CACHED_POSITION_OFFSET, 0);
            write_word(&mut state, LOWER_POSITION_OFFSET, 20);
            write_word(&mut state, UPPER_POSITION_OFFSET, 10);
            write_word(&mut state, MODE_POSITION_OFFSET, 20);
            state.0[MODE_FLAGS_OFFSET] = 1;

            assert_eq!(adjust_clamped_mode_position(state.0.as_mut_ptr(), 15), 1);

            assert_eq!(state.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), 20);
            assert_eq!(SETTER_CALLS, 0);
            assert_eq!(NOTIFICATION_CALLS, 1);
        }
    }
}
