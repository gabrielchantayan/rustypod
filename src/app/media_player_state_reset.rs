//! `media_player_state_reset` — original: `FUN_0822b54c` @ `0x0822b54c`
//! (**148 bytes**, `0x0822b54c..0x0822b5e0`; the next separately linked
//! function starts with `push {r4,r5,r6,lr}` at `0x0822b5e0`).
//!
//! Raw ARM has nine unconditional `bl` instructions and one predicated `blne`
//! in its body. It has four incoming plain `bl` call sites and no predicated
//! incoming calls: `0x0820a65c`, `0x082205a0`, `0x0822aad0`, and `0x0822b670`.
//!
//! The routine releases the optional list cursor when the mode-selected byte is
//! nonzero, resets the active mode subobject, clears the three state words at
//! `+0x2c..+0x34`, and replaces both shared-cell handles at `+0x890` and
//! `+0x894` with empty handles. The `+0x330` and `+0x38` reset callees remain
//! unported: target builds call their verified retailOS addresses; host builds
//! expose recording seams whose default is deliberately a no-op.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

#[cfg(target_os = "none")]
use core::ptr::addr_of_mut;

use crate::app::mode_selected_byte::mode_selected_byte;
use crate::cxx::list_cursor_release::list_cursor_release;
#[cfg(target_os = "none")]
use crate::cxx::shared_cell::{shared_cell_assign, shared_cell_construct, shared_cell_release, SharedCell};

const OWNER_OFFSET: usize = 0x14;
const MODE_FLAGS_OFFSET: usize = 0x5f8;
const DEFAULT_SUBSTATE_OFFSET: usize = 0x330;
const SELECTED_SUBSTATE_OFFSET: usize = 0x38;
const STATE_WORDS_OFFSET: usize = 0x2c;
const PRIMARY_HANDLE_OFFSET: usize = 0x894;
const SECONDARY_HANDLE_OFFSET: usize = 0x890;
const RETAIL_DEFAULT_SUBSTATE_RESET: usize = 0x0820_8578;
const RETAIL_SELECTED_SUBSTATE_RESET: usize = 0x0821_4dbc;

/// ABI of either unported mode-substate reset helper.
pub type MediaPlayerSubstateReset = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn reset_default_substate(state: *mut u8) {
    let reset: MediaPlayerSubstateReset = core::mem::transmute(RETAIL_DEFAULT_SUBSTATE_RESET);
    reset(state.add(DEFAULT_SUBSTATE_OFFSET));
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn reset_selected_substate(state: *mut u8) {
    let reset: MediaPlayerSubstateReset = core::mem::transmute(RETAIL_SELECTED_SUBSTATE_RESET);
    reset(state.add(SELECTED_SUBSTATE_OFFSET));
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_substate_reset(_substate: *mut u8) -> u32 {
    0
}

/// Host seams for the two unported substate reset helpers.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct MediaPlayerStateResetOps {
    pub reset_default_substate: MediaPlayerSubstateReset,
    pub reset_selected_substate: MediaPlayerSubstateReset,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEDIA_PLAYER_STATE_RESET_OPS: MediaPlayerStateResetOps = MediaPlayerStateResetOps {
    reset_default_substate: missing_substate_reset,
    reset_selected_substate: missing_substate_reset,
};

#[cfg(not(target_os = "none"))]
pub static mut MEDIA_PLAYER_STATE_RESET_OPS: MediaPlayerStateResetOps = DEFAULT_MEDIA_PLAYER_STATE_RESET_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn reset_default_substate(state: *mut u8) {
    let reset = core::ptr::read_volatile(addr_of!(MEDIA_PLAYER_STATE_RESET_OPS.reset_default_substate));
    reset(state.add(DEFAULT_SUBSTATE_OFFSET));
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn reset_selected_substate(state: *mut u8) {
    let reset = core::ptr::read_volatile(addr_of!(MEDIA_PLAYER_STATE_RESET_OPS.reset_selected_substate));
    reset(state.add(SELECTED_SUBSTATE_OFFSET));
}

/// Resets the mode-dependent player state and empties its two pending handles.
///
/// # Safety
///
/// `state` must reference a live retailOS player object, including the fields
/// through `+0x894`. Its owner at `+0x14`, when non-NULL and selected by the
/// mode byte, must be valid for [`list_cursor_release`]. The target handle
/// slots must meet the shared-cell operations' preconditions. Host execution
/// models those target-width slots as opaque u32 words. The raw routine has no
/// NULL or bounds guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_state_reset(state: *mut u8) {
    if mode_selected_byte(state) != 0 {
        let owner = state.add(OWNER_OFFSET).cast::<*mut u8>().read();
        if !owner.is_null() {
            list_cursor_release(owner.cast());
        }
    }

    if state.add(MODE_FLAGS_OFFSET).read() & 1 == 0 {
        reset_default_substate(state);
    } else {
        reset_selected_substate(state);
    }

    state.add(STATE_WORDS_OFFSET).cast::<u32>().write(0);
    state.add(STATE_WORDS_OFFSET + 4).cast::<u32>().write(0);
    state.add(STATE_WORDS_OFFSET + 8).cast::<u32>().write(u32::MAX);

    empty_handles(state);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn empty_handles(state: *mut u8) {
    let primary = state.add(PRIMARY_HANDLE_OFFSET).cast::<*mut SharedCell>();
    let secondary = state.add(SECONDARY_HANDLE_OFFSET).cast::<*mut SharedCell>();
    let mut empty_primary = core::ptr::null_mut();
    let mut empty_secondary = core::ptr::null_mut();
    shared_cell_construct(addr_of_mut!(empty_primary), core::ptr::null_mut());
    shared_cell_assign(primary, addr_of_mut!(empty_primary));
    shared_cell_release(addr_of_mut!(empty_primary));
    shared_cell_construct(addr_of_mut!(empty_secondary), core::ptr::null_mut());
    shared_cell_assign(secondary, addr_of_mut!(empty_secondary));
    shared_cell_release(addr_of_mut!(empty_secondary));
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn empty_handles(state: *mut u8) {
    // Target slots are adjacent 32-bit words; host pointers cannot occupy that
    // layout, so host fixtures retain the observed empty-handle result only.
    state.add(PRIMARY_HANDLE_OFFSET).cast::<u32>().write(0);
    state.add(SECONDARY_HANDLE_OFFSET).cast::<u32>().write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(usize, usize); 2] = [(0, 0); 2];

    #[repr(align(4))]
    struct AlignedState([u8; PRIMARY_HANDLE_OFFSET + 4]);

    unsafe extern "C" fn record_default(substate: *mut u8) -> u32 {
        CALLS[0] = (CALLS[0].0 + 1, substate as usize);
        0
    }

    unsafe extern "C" fn record_selected(substate: *mut u8) -> u32 {
        CALLS[1] = (CALLS[1].0 + 1, substate as usize);
        0
    }

    #[test]
    fn resets_words_handles_and_the_flag_selected_substate() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut state = AlignedState([0u8; PRIMARY_HANDLE_OFFSET + 4]);
        unsafe {
            state.0.as_mut_ptr().add(PRIMARY_HANDLE_OFFSET).cast::<u32>().write(0x1122_3344);
            state.0.as_mut_ptr().add(SECONDARY_HANDLE_OFFSET).cast::<u32>().write(0x5566_7788);
            state.0[STATE_WORDS_OFFSET..STATE_WORDS_OFFSET + 12].fill(0xa5);
            MEDIA_PLAYER_STATE_RESET_OPS = MediaPlayerStateResetOps {
                reset_default_substate: record_default,
                reset_selected_substate: record_selected,
            };
            CALLS = [(0, 0); 2];

            media_player_state_reset(state.0.as_mut_ptr());

            assert_eq!(CALLS, [(1, state.0.as_ptr() as usize + DEFAULT_SUBSTATE_OFFSET), (0, 0)]);
            assert_eq!(state.0[STATE_WORDS_OFFSET..STATE_WORDS_OFFSET + 12], [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
            assert_eq!(state.0.as_ptr().add(PRIMARY_HANDLE_OFFSET).cast::<u32>().read(), 0);
            assert_eq!(state.0.as_ptr().add(SECONDARY_HANDLE_OFFSET).cast::<u32>().read(), 0);
            MEDIA_PLAYER_STATE_RESET_OPS = DEFAULT_MEDIA_PLAYER_STATE_RESET_OPS;
        }
    }

    #[test]
    fn selects_the_alternate_substate_from_mode_bit() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut state = AlignedState([0u8; PRIMARY_HANDLE_OFFSET + 4]);
        unsafe {
            state.0[MODE_FLAGS_OFFSET] = 1;
            MEDIA_PLAYER_STATE_RESET_OPS = MediaPlayerStateResetOps {
                reset_default_substate: record_default,
                reset_selected_substate: record_selected,
            };
            CALLS = [(0, 0); 2];

            media_player_state_reset(state.0.as_mut_ptr());

            assert_eq!(CALLS, [(0, 0), (1, state.0.as_ptr() as usize + SELECTED_SUBSTATE_OFFSET)]);
            MEDIA_PLAYER_STATE_RESET_OPS = DEFAULT_MEDIA_PLAYER_STATE_RESET_OPS;
        }
    }
}
