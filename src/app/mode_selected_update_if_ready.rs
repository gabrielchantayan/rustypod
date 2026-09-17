//! `mode_selected_update_if_ready` — original: `FUN_0822af50` @ `0x0822af50`
//! (**68 bytes**, `0x0822af50..0x0822af93`; the distinct next function begins
//! with `push {r4,r5,r6,lr}` at `0x0822af94`).
//!
//! Raw ARM has two unconditional direct `bl` instructions in its body
//! (`0x0822af70` and `0x0822af84`), no predicated `bl` instructions, and four
//! direct unconditional plain `bl` callers. It checks mode-flags bit 0 at
//! `state+0x5f8`; only a set bit continues. It then selects the active mode
//! byte through `FUN_0822b684`, and only a zero byte calls `FUN_08214a1c` on
//! the selected substate at `state+0x38`, returning that call's result.
//!
//! Deliberate deviation: `FUN_0822b684` is the already ported
//! [`super::mode_selected_byte::mode_selected_byte`], so this port calls it
//! directly instead of introducing a seam for a verified existing Rust port.
//! `FUN_08214a1c` has no recovered semantic identity and remains a fixed-address
//! target seam; host tests replace it while ARM calls its verified entry.

use super::mode_selected_byte::mode_selected_byte;

const MODE_FLAGS_OFFSET: usize = 0x5f8;
const SELECTED_SUBSTATE_OFFSET: usize = 0x38;
const MODE_SUBSTATE_UPDATE_ADDRESS: usize = 0x0821_4a1c;

type ModeSubstateUpdate = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn mode_substate_update() -> ModeSubstateUpdate {
    core::mem::transmute(MODE_SUBSTATE_UPDATE_ADDRESS)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_mode_substate_update(_substate: *mut u8, _mode: u32) -> u32 {
    0
}

/// Host replacement for the unresolved fixed target at `0x08214a1c`.
#[cfg(not(target_arch = "arm"))]
pub(crate) static mut MODE_SUBSTATE_UPDATE: ModeSubstateUpdate = missing_mode_substate_update;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn mode_substate_update() -> ModeSubstateUpdate {
    MODE_SUBSTATE_UPDATE
}

/// Applies `mode` to the active substate only when the selected mode byte is
/// zero and mode flags select that substate.
///
/// # Safety
/// `state` must be non-NULL and readable at `+0x5f8`, `+0x2f4`, and `+0x5ec`.
/// When the flag is set and the selected byte is zero, `state+0x38` must meet
/// the unresolved target's requirements. The retail ARM code has no guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mode_selected_update_if_ready(state: *mut u8, mode: u32) -> u32 {
    if state.add(MODE_FLAGS_OFFSET).read() & 1 == 0 {
        return 0;
    }
    if mode_selected_byte(state) != 0 {
        return 0;
    }
    mode_substate_update()(state.add(SELECTED_SUBSTATE_OFFSET), mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut UPDATE_CALLS: u32 = 0;
    static mut UPDATE_SUBSTATE: *mut u8 = core::ptr::null_mut();
    static mut UPDATE_MODE: u32 = 0;
    static mut UPDATE_RESULT: u32 = 0;

    unsafe extern "C" fn recording_update(substate: *mut u8, mode: u32) -> u32 {
        UPDATE_CALLS += 1;
        UPDATE_SUBSTATE = substate;
        UPDATE_MODE = mode;
        UPDATE_RESULT
    }

    #[test]
    fn only_updates_for_set_flag_and_zero_selected_byte() {
        let _lock = TEST_LOCK.lock();
        let mut state = [0u8; MODE_FLAGS_OFFSET + 1];
        unsafe {
            MODE_SUBSTATE_UPDATE = recording_update;
            UPDATE_CALLS = 0;
            UPDATE_RESULT = 0x5a;

            assert_eq!(mode_selected_update_if_ready(state.as_mut_ptr(), 7), 0);
            assert_eq!(UPDATE_CALLS, 0);

            state[MODE_FLAGS_OFFSET] = 1;
            state[0x2f4] = 9;
            assert_eq!(mode_selected_update_if_ready(state.as_mut_ptr(), 8), 0);
            assert_eq!(UPDATE_CALLS, 0);

            state[0x2f4] = 0;
            assert_eq!(mode_selected_update_if_ready(state.as_mut_ptr(), 9), 0x5a);
            assert_eq!(UPDATE_CALLS, 1);
            assert_eq!(UPDATE_SUBSTATE, state.as_mut_ptr().add(SELECTED_SUBSTATE_OFFSET));
            assert_eq!(UPDATE_MODE, 9);

            MODE_SUBSTATE_UPDATE = missing_mode_substate_update;
        }
    }
}
