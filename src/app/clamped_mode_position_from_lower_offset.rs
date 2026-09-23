//! `set_clamped_mode_position_from_lower_offset` — original: `FUN_081cbbe8` @
//! `0x081cbbe8` (**12 bytes**, `0x081cbbe8..0x081cbbf4`; the separately linked
//! next entry starts at `0x081cbbf4`).
//!
//! Raw ARM loads the unsigned lower position from `state+0x8bc`, adds the
//! supplied offset with A32 wrapping arithmetic, then tail-branches to
//! [`set_clamped_mode_position`]. The body has no direct `bl` calls.
//! Whole-image A32 decoding finds two unconditional inbound plain `bl` sites
//! (`0x0810ce10`, `0x0810d3ec`) and one predicated `blne` site (`0x081cb720`).
//!
//! Deliberate deviation: the ARM tail branch is represented as a normal Rust
//! call; the callee returns `void`, so this does not alter observable results.

use super::clamped_mode_position::set_clamped_mode_position;

const LOWER_POSITION_OFFSET: usize = 0x8bc;

/// Sets the clamped mode position to the lower bound plus a wrapping offset.
///
/// # Safety
///
/// `state` must be non-NULL and four-byte aligned, with a readable word at
/// `+0x8bc` and every region required by [`set_clamped_mode_position`]. The
/// retail ARM sequence has no NULL, bounds, or alignment guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn set_clamped_mode_position_from_lower_offset(state: *mut u8, offset: u32) {
    let lower = state.add(LOWER_POSITION_OFFSET).cast::<u32>().read();
    set_clamped_mode_position(state, lower.wrapping_add(offset));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{
        clamped_mode_position::{MODE_POSITION_CHANGED, MODE_POSITION_CHANGED_TEST_LOCK},
        mode_selected_position_set::{
            MODE_SELECTED_POSITION_SET_CLEAR, MODE_SELECTED_POSITION_SET_SET,
            MODE_SELECTED_POSITION_SET_TEST_LOCK,
        },
    };

    const STATE_BYTES: usize = LOWER_POSITION_OFFSET + 8;
    const BACKEND_OFFSET: usize = 0x1c;
    const CACHED_POSITION_OFFSET: usize = 0x8b8;
    const UPPER_POSITION_OFFSET: usize = 0x8c0;
    const DEFAULT_POSITION_OFFSET: usize = BACKEND_OFFSET + 0x5e4;
    const MODE_FLAGS_OFFSET: usize = BACKEND_OFFSET + 0x5f8;

    static mut SETTER_POSITION: u32 = 0;

    #[repr(align(4))]
    struct State([u8; STATE_BYTES]);

    unsafe extern "C" fn record_setter(_state: *mut u8, _mode: u32, position: u32) -> u32 {
        SETTER_POSITION = position;
        0
    }

    unsafe extern "C" fn ignore_notification(_state: *mut u8) {}

    unsafe fn write_word(state: &mut State, offset: usize, value: u32) {
        state.0.as_mut_ptr().add(offset).cast::<u32>().write(value);
    }

    #[test]
    fn wraps_lower_offset_before_delegating_to_the_clamped_setter() {
        let _setter_guard = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        let _notification_guard = MODE_POSITION_CHANGED_TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            MODE_SELECTED_POSITION_SET_CLEAR = record_setter;
            MODE_SELECTED_POSITION_SET_SET = record_setter;
            MODE_POSITION_CHANGED = ignore_notification;
            SETTER_POSITION = 0;
            write_word(&mut state, LOWER_POSITION_OFFSET, u32::MAX);
            write_word(&mut state, UPPER_POSITION_OFFSET, 10);
            write_word(&mut state, CACHED_POSITION_OFFSET, 0);
            write_word(&mut state, DEFAULT_POSITION_OFFSET, 0);
            state.0[MODE_FLAGS_OFFSET] = 0;

            set_clamped_mode_position_from_lower_offset(state.0.as_mut_ptr(), 2);

            assert_eq!(SETTER_POSITION, 1);
            assert_eq!(state.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), 1);
        }
    }
}
