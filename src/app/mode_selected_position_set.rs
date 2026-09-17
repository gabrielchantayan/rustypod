//! `mode_selected_position_set` — original: `FUN_0822ba50` @ `0x0822ba50`
//! (**24 bytes**, `0x0822ba50..0x0822ba68`; the separately linked next entry
//! starts at `0x0822ba68`).
//!
//! Raw ARM reads bit 0 of `state+0x5f8` and tail-dispatches unchanged `(state,
//! mode, position)` arguments: a clear flag selects `0x0820859c` with
//! `state+0x330`, while a set flag selects `0x08214e78` with `state+0x38`.
//! Decoding every ARM B/BL immediate in `osos.dec` finds six direct inbound
//! `bl` sites: three unconditional (`0x081cd0ec`, `0x0822034c`, `0x0822b63c`),
//! one `bleq` (`0x081b6b98`), and two `blne` (`0x081cc5f8`, `0x081cd394`). Two
//! further unconditional tail branches enter at `0x0820a60c` and `0x08220538`.
//!
//! Deliberate deviation: the two selected target bodies are not ported, so host
//! tests use replaceable target seams. ARM calls their verified fixed addresses.

const MODE_FLAGS_OFFSET: usize = 0x5f8;
const CLEAR_STATE_OFFSET: usize = 0x330;
const SET_STATE_OFFSET: usize = 0x38;
const CLEAR_TARGET: usize = 0x0820_859c;
const SET_TARGET: usize = 0x0821_4e78;

pub(crate) type ModeSelectedPositionSetPath = unsafe extern "C" fn(*mut u8, u32, u32) -> u32;

#[cfg(test)]
pub(crate) static MODE_SELECTED_POSITION_SET_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_mode_selected_position_set_path(
    _state: *mut u8,
    _mode: u32,
    _position: u32,
) -> u32 {
    0
}

/// Host replacement for the clear-flag target at `0x0820859c`.
#[cfg(not(target_arch = "arm"))]
pub(crate) static mut MODE_SELECTED_POSITION_SET_CLEAR: ModeSelectedPositionSetPath =
    missing_mode_selected_position_set_path;

/// Host replacement for the set-flag target at `0x08214e78`.
#[cfg(not(target_arch = "arm"))]
pub(crate) static mut MODE_SELECTED_POSITION_SET_SET: ModeSelectedPositionSetPath =
    missing_mode_selected_position_set_path;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn mode_selected_position_set_path(flag_set: bool) -> ModeSelectedPositionSetPath {
    if flag_set {
        core::mem::transmute(SET_TARGET)
    } else {
        core::mem::transmute(CLEAR_TARGET)
    }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn mode_selected_position_set_path(flag_set: bool) -> ModeSelectedPositionSetPath {
    if flag_set {
        core::ptr::read_volatile(core::ptr::addr_of!(MODE_SELECTED_POSITION_SET_SET))
    } else {
        core::ptr::read_volatile(core::ptr::addr_of!(MODE_SELECTED_POSITION_SET_CLEAR))
    }
}

/// Selects the state-specific mode-position setter and forwards its result.
///
/// # Safety
///
/// `state` must be non-NULL and readable at `+0x5f8`. The selected target
/// receives either `state+0x330` or `state+0x38` and has its own requirements.
/// The retail ARM code makes neither check.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mode_selected_position_set(
    state: *mut u8,
    mode: u32,
    position: u32,
) -> u32 {
    let flag_set = state.add(MODE_FLAGS_OFFSET).read() & 1 != 0;
    let selected_state = if flag_set {
        state.add(SET_STATE_OFFSET)
    } else {
        state.add(CLEAR_STATE_OFFSET)
    };
    mode_selected_position_set_path(flag_set)(selected_state, mode, position)
}

// `mode_selected_position_set_veneer` — original: `thunk_FUN_0822ba50` @
// `0x08220538` (**4 bytes**, `0x08220538..0x0822053c`; the separately linked
// next function starts with `push {r4,lr}` at `0x0822053c`).
//
// Raw ARM word `0xea002d44` is an unconditional `b 0x0822ba50`. Independent
// decoding finds four inbound unconditional plain `bl` calls and no
// predicated `bl` calls. The veneer tail-dispatches unchanged `(state, mode,
// position)` arguments and its target's result.
//
// Deliberate deviation: the target build branches to the existing Rust port
// symbol rather than the retail fixed address; the ABI-visible tail branch
// remains a single ARM instruction.
//
// Safety: has the same requirements as `mode_selected_position_set`.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl mode_selected_position_set_veneer
    .type mode_selected_position_set_veneer, %function
mode_selected_position_set_veneer:
    b       mode_selected_position_set
    .size mode_selected_position_set_veneer, . - mode_selected_position_set_veneer
"#
);

#[cfg(not(target_arch = "arm"))]
#[inline(never)]
pub unsafe extern "C" fn mode_selected_position_set_veneer(
    state: *mut u8,
    mode: u32,
    position: u32,
) -> u32 {
    mode_selected_position_set(state, mode, position)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const STATE_BYTES: usize = MODE_FLAGS_OFFSET + 1;
    const CLEAR_RETURN: u32 = 0x20c0_859c;
    const SET_RETURN: u32 = 0x20c1_4e78;

    static mut CLEAR_STATE: *mut u8 = core::ptr::null_mut();
    static mut CLEAR_MODE: u32 = 0;
    static mut CLEAR_POSITION: u32 = 0;
    static mut SET_STATE: *mut u8 = core::ptr::null_mut();
    static mut SET_MODE: u32 = 0;
    static mut SET_POSITION: u32 = 0;

    #[repr(align(4))]
    struct State([u8; STATE_BYTES]);

    struct Reset {
        clear: ModeSelectedPositionSetPath,
        set: ModeSelectedPositionSetPath,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(MODE_SELECTED_POSITION_SET_CLEAR), self.clear);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(MODE_SELECTED_POSITION_SET_SET), self.set);
            }
        }
    }

    unsafe extern "C" fn record_clear(state: *mut u8, mode: u32, position: u32) -> u32 {
        CLEAR_STATE = state;
        CLEAR_MODE = mode;
        CLEAR_POSITION = position;
        CLEAR_RETURN
    }

    unsafe extern "C" fn record_set(state: *mut u8, mode: u32, position: u32) -> u32 {
        SET_STATE = state;
        SET_MODE = mode;
        SET_POSITION = position;
        SET_RETURN
    }

    unsafe fn install() -> Reset {
        let reset = Reset {
            clear: core::ptr::read_volatile(core::ptr::addr_of!(MODE_SELECTED_POSITION_SET_CLEAR)),
            set: core::ptr::read_volatile(core::ptr::addr_of!(MODE_SELECTED_POSITION_SET_SET)),
        };
        core::ptr::write_volatile(core::ptr::addr_of_mut!(MODE_SELECTED_POSITION_SET_CLEAR), record_clear);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(MODE_SELECTED_POSITION_SET_SET), record_set);
        CLEAR_STATE = core::ptr::null_mut();
        CLEAR_MODE = 0;
        CLEAR_POSITION = 0;
        SET_STATE = core::ptr::null_mut();
        SET_MODE = 0;
        SET_POSITION = 0;
        reset
    }

    #[test]
    fn clear_flag_forwards_unchanged_arguments_to_clear_state() {
        let _guard = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            let _reset = install();

            assert_eq!(mode_selected_position_set(state.0.as_mut_ptr(), 0, u32::MAX), CLEAR_RETURN);
            assert_eq!(CLEAR_STATE, state.0.as_mut_ptr().add(CLEAR_STATE_OFFSET));
            assert_eq!(CLEAR_MODE, 0);
            assert_eq!(CLEAR_POSITION, u32::MAX);
            assert!(SET_STATE.is_null());
        }
    }

    #[test]
    fn veneer_forwards_set_flag_arguments_and_result() {
        let _guard = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        state.0[MODE_FLAGS_OFFSET] = 1;
        unsafe {
            let _reset = install();

            assert_eq!(mode_selected_position_set_veneer(state.0.as_mut_ptr(), u32::MAX, 0), SET_RETURN);
            assert_eq!(SET_STATE, state.0.as_mut_ptr().add(SET_STATE_OFFSET));
            assert_eq!(SET_MODE, u32::MAX);
            assert_eq!(SET_POSITION, 0);
            assert!(CLEAR_STATE.is_null());
        }
    }
}
