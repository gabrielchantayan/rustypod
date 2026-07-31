//! Raster-edge profile state transitions from `FUN_080e99d8` @ `0x080e99d8`.
//!
//! **Original:** 332 bytes (`0x14c`), retailOS 2.0.4. Reference C:
//! `ipod-decomp/decomp/c/008/080e99d8_FUN_080e99d8.c`; assembly:
//! `ipod-decomp/decomp/osos.asm` at `0x080e99d8`.
//!
//! This is the state-machine front end for a raster edge profile. It compares
//! the incoming edge ordinate with the preceding one *as signed 32-bit
//! values*, creates an ascending or descending profile when needed, ends and
//! reverses a profile at a direction change, and emits the normalized edge
//! segment. Its `u64` return is the ARM `longlong` register pair: low word is
//! the error flag, high word is the carried ordinate (the input ordinate for
//! ascending profiles, its wrapping negation for descending profiles, or the
//! input abscissa while no profile is active).
//!
//! The profile allocator/finalizer and segment emitter live elsewhere in the
//! firmware (`0x080767a8`, `0x08076228`, and `0x080e9b24`). They are explicit
//! volatile callback seams here rather than additional ports. On ARM their
//! defaults point at those retailOS entry points; host tests replace them.

/// Direction byte stored at state offset `0x68`.
pub const PROFILE_ASCENDING: u8 = 1;
/// Direction byte stored at state offset `0x68`.
pub const PROFILE_DESCENDING: u8 = 2;

/// The portion of the firmware raster state touched by
/// [`raster_profile_append_edge`].
///
/// The fields deliberately retain their retailOS offsets. `active_profile` is
/// a 32-bit firmware address; the function only dereferences it on ARM, where
/// pointers are 32 bits.
#[repr(C)]
pub struct RasterProfileState {
    _before_previous: [u8; 0x48],
    pub previous_x: i32,
    pub previous_y: i32,
    pub lower_limit: i32,
    pub upper_limit: i32,
    _padding_58_59: [u8; 2],
    /// Set by profile creation and consumed by the segment emitter.
    pub profile_pending: u8,
    _padding_5b: u8,
    /// Firmware pointer to the active profile; its signed accumulator is at
    /// `active_profile + 0x14`.
    pub active_profile: u32,
    _padding_60_67: [u8; 8],
    pub direction: u8,
}

/// Calls made by [`raster_profile_append_edge`] into unported raster-profile
/// routines. All routines return nonzero to signal an error.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RasterProfileOps {
    pub end_profile: unsafe extern "C" fn(*mut RasterProfileState) -> u32,
    pub begin_profile: unsafe extern "C" fn(*mut RasterProfileState, i32) -> u32,
    pub emit_segment: unsafe extern "C" fn(
        *mut RasterProfileState,
        i32,
        i32,
        i32,
        i32,
        i32,
        i32,
    ) -> u32,
    /// Host seam for the `active_profile + 0x14` negation. On ARM the port
    /// performs that store directly, exactly as the original does.
    pub reverse_profile_accumulator: unsafe extern "C" fn(*mut RasterProfileState),
}

unsafe extern "C" fn missing_end_profile(_: *mut RasterProfileState) -> u32 {
    1
}

unsafe extern "C" fn missing_begin_profile(_: *mut RasterProfileState, _: i32) -> u32 {
    1
}

unsafe extern "C" fn missing_emit_segment(
    _: *mut RasterProfileState,
    _: i32,
    _: i32,
    _: i32,
    _: i32,
    _: i32,
    _: i32,
) -> u32 {
    1
}

unsafe extern "C" fn missing_reverse_profile_accumulator(_: *mut RasterProfileState) {}

#[cfg(target_arch = "arm")]
unsafe extern "C" fn retail_end_profile(state: *mut RasterProfileState) -> u32 {
    let callback: unsafe extern "C" fn(*mut RasterProfileState) -> u32 =
        core::mem::transmute(0x0807_6228usize);
    callback(state)
}

#[cfg(target_arch = "arm")]
unsafe extern "C" fn retail_begin_profile(
    state: *mut RasterProfileState,
    direction: i32,
) -> u32 {
    let callback: unsafe extern "C" fn(*mut RasterProfileState, i32) -> u32 =
        core::mem::transmute(0x0807_67a8usize);
    callback(state, direction)
}

#[cfg(target_arch = "arm")]
unsafe extern "C" fn retail_emit_segment(
    state: *mut RasterProfileState,
    previous_x: i32,
    previous_y: i32,
    x: i32,
    y: i32,
    lower_limit: i32,
    upper_limit: i32,
) -> u32 {
    let callback: unsafe extern "C" fn(
        *mut RasterProfileState,
        i32,
        i32,
        i32,
        i32,
        i32,
        i32,
    ) -> u32 = core::mem::transmute(0x080e_9b24usize);
    callback(state, previous_x, previous_y, x, y, lower_limit, upper_limit)
}

#[cfg(target_arch = "arm")]
const DEFAULT_RASTER_PROFILE_OPS: RasterProfileOps = RasterProfileOps {
    // These wrappers tail into functions that remain in retailOS.
    end_profile: retail_end_profile,
    begin_profile: retail_begin_profile,
    emit_segment: retail_emit_segment,
    reverse_profile_accumulator: missing_reverse_profile_accumulator,
};

#[cfg(not(target_arch = "arm"))]
const DEFAULT_RASTER_PROFILE_OPS: RasterProfileOps = RasterProfileOps {
    end_profile: missing_end_profile,
    begin_profile: missing_begin_profile,
    emit_segment: missing_emit_segment,
    reverse_profile_accumulator: missing_reverse_profile_accumulator,
};

/// The unported raster-profile operation table. Target integration may replace
/// this once during initialization; host tests install deterministic mocks.
pub static mut RASTER_PROFILE_OPS: RasterProfileOps = DEFAULT_RASTER_PROFILE_OPS;

#[inline(always)]
fn profile_ops() -> RasterProfileOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RASTER_PROFILE_OPS)) }
}

#[inline(always)]
fn return_pair(carried: u32, error: u32) -> u64 {
    ((carried as u64) << 32) | error as u64
}

#[inline(always)]
unsafe fn reverse_active_profile_accumulator(state: *mut RasterProfileState, ops: RasterProfileOps) {
    #[cfg(target_arch = "arm")]
    {
        let accumulator = ((*state).active_profile as usize + 0x14) as *mut i32;
        *accumulator = (*accumulator).wrapping_neg();
    }
    #[cfg(not(target_arch = "arm"))]
    {
        (ops.reverse_profile_accumulator)(state);
    }
}

#[inline(always)]
unsafe fn current_direction(state: *mut RasterProfileState) -> u8 {
    core::ptr::addr_of!((*state).direction).read_volatile()
}

#[inline(always)]
unsafe fn profile_is_pending(state: *mut RasterProfileState) -> u8 {
    core::ptr::addr_of!((*state).profile_pending).read_volatile()
}

/// raster_profile_append_edge — original: `FUN_080e99d8` @ `0x080e99d8`
/// (332 bytes).
///
/// Extends the active raster edge profile to `(x, y)`. A nonzero low return
/// word reports a callback failure and leaves `previous_x`/`previous_y`
/// untouched; successful paths always store those two fields. See the module
/// header for the high return word convention.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn raster_profile_append_edge(
    state: *mut RasterProfileState,
    x: u32,
    y: u32,
) -> u64 {
    let ops = profile_ops();
    let incoming_y = y as i32;
    let mut carried = x;

    match current_direction(state) {
        0 if (*state).previous_y < incoming_y => {
            if (ops.begin_profile)(state, PROFILE_ASCENDING as i32) != 0 {
                return return_pair(carried, 1);
            }
        }
        0 if incoming_y < (*state).previous_y => {
            if (ops.begin_profile)(state, PROFILE_DESCENDING as i32) != 0 {
                return return_pair(carried, 1);
            }
        }
        PROFILE_ASCENDING if incoming_y < (*state).previous_y => {
            if (ops.end_profile)(state) != 0 {
                return return_pair(carried, 1);
            }
            if (ops.begin_profile)(state, PROFILE_DESCENDING as i32) != 0 {
                return return_pair(carried, 1);
            }
        }
        PROFILE_DESCENDING if (*state).previous_y < incoming_y => {
            if (ops.end_profile)(state) != 0 {
                return return_pair(carried, 1);
            }
            if (ops.begin_profile)(state, PROFILE_ASCENDING as i32) != 0 {
                return return_pair(carried, 1);
            }
        }
        _ => {}
    }

    let callback_error = match current_direction(state) {
        PROFILE_ASCENDING => {
            carried = y;
            (ops.emit_segment)(
                state,
                (*state).previous_x,
                (*state).previous_y,
                x as i32,
                incoming_y,
                (*state).lower_limit,
                (*state).upper_limit,
            )
        }
        PROFILE_DESCENDING => {
            let profile_was_pending = profile_is_pending(state);
            carried = y.wrapping_neg();
            let error = (ops.emit_segment)(
                state,
                (*state).previous_x,
                (*state).previous_y.wrapping_neg(),
                x as i32,
                (y as i32).wrapping_neg(),
                (*state).upper_limit.wrapping_neg(),
                (*state).lower_limit.wrapping_neg(),
            );
            if profile_was_pending != 0 && profile_is_pending(state) == 0 {
                reverse_active_profile_accumulator(state, ops);
            }
            error
        }
        _ => 0,
    };

    if callback_error != 0 {
        return return_pair(carried, 1);
    }

    (*state).previous_x = x as i32;
    (*state).previous_y = incoming_y;
    return_pair(carried, 0)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy)]
    struct Trace {
        end_result: u32,
        begin_result: u32,
        emit_result: u32,
        clear_pending_on_emit: bool,
        end_calls: u32,
        begin_calls: u32,
        begin_direction: i32,
        emit_calls: u32,
        emit_args: [i32; 6],
        reverse_calls: u32,
    }

    static mut TRACE: Trace = Trace {
        end_result: 0,
        begin_result: 0,
        emit_result: 0,
        clear_pending_on_emit: false,
        end_calls: 0,
        begin_calls: 0,
        begin_direction: 0,
        emit_calls: 0,
        emit_args: [0; 6],
        reverse_calls: 0,
    };

    unsafe extern "C" fn mock_end(_: *mut RasterProfileState) -> u32 {
        TRACE.end_calls += 1;
        TRACE.end_result
    }

    unsafe extern "C" fn mock_begin(state: *mut RasterProfileState, direction: i32) -> u32 {
        TRACE.begin_calls += 1;
        TRACE.begin_direction = direction;
        if TRACE.begin_result == 0 {
            (*state).direction = direction as u8;
        }
        TRACE.begin_result
    }

    unsafe extern "C" fn mock_emit(
        state: *mut RasterProfileState,
        previous_x: i32,
        previous_y: i32,
        x: i32,
        y: i32,
        lower_limit: i32,
        upper_limit: i32,
    ) -> u32 {
        TRACE.emit_calls += 1;
        TRACE.emit_args = [previous_x, previous_y, x, y, lower_limit, upper_limit];
        if TRACE.clear_pending_on_emit {
            (*state).profile_pending = 0;
        }
        TRACE.emit_result
    }

    unsafe extern "C" fn mock_reverse(_: *mut RasterProfileState) {
        TRACE.reverse_calls += 1;
    }

    struct HookReset;

    impl Drop for HookReset {
        fn drop(&mut self) {
            unsafe { RASTER_PROFILE_OPS = DEFAULT_RASTER_PROFILE_OPS };
        }
    }

    fn fresh() -> (MutexGuard<'static, ()>, HookReset) {
        let lock = TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            TRACE = Trace {
                end_result: 0,
                begin_result: 0,
                emit_result: 0,
                clear_pending_on_emit: false,
                end_calls: 0,
                begin_calls: 0,
                begin_direction: 0,
                emit_calls: 0,
                emit_args: [0; 6],
                reverse_calls: 0,
            };
            RASTER_PROFILE_OPS = RasterProfileOps {
                end_profile: mock_end,
                begin_profile: mock_begin,
                emit_segment: mock_emit,
                reverse_profile_accumulator: mock_reverse,
            };
        }
        (lock, HookReset)
    }

    fn state() -> RasterProfileState {
        RasterProfileState {
            _before_previous: [0; 0x48],
            previous_x: 3,
            previous_y: 10,
            lower_limit: 20,
            upper_limit: 40,
            _padding_58_59: [0; 2],
            profile_pending: 0,
            _padding_5b: 0,
            active_profile: 0,
            _padding_60_67: [0; 8],
            direction: 0,
        }
    }

    #[test]
    fn starts_ascending_profile_with_signed_comparison_and_emits_raw_segment() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        profile.previous_y = -1;

        let pair = unsafe { raster_profile_append_edge(&mut profile, 7, 0) };

        assert_eq!(pair, 0);
        unsafe {
            assert_eq!(TRACE.begin_calls, 1);
            assert_eq!(TRACE.begin_direction, PROFILE_ASCENDING as i32);
            assert_eq!(TRACE.end_calls, 0);
            assert_eq!(TRACE.emit_calls, 1);
            assert_eq!(TRACE.emit_args, [3, -1, 7, 0, 20, 40]);
        }
        assert_eq!((profile.previous_x, profile.previous_y), (7, 0));
    }

    #[test]
    fn descending_reversal_ends_restarts_negates_arguments_and_flips_new_accumulator() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        profile.direction = PROFILE_ASCENDING;
        profile.profile_pending = 1;
        unsafe {
            TRACE.clear_pending_on_emit = true;
        }

        let pair = unsafe { raster_profile_append_edge(&mut profile, 7, 4) };

        assert_eq!(pair, ((u32::MAX - 3) as u64) << 32);
        unsafe {
            assert_eq!(TRACE.end_calls, 1);
            assert_eq!(TRACE.begin_calls, 1);
            assert_eq!(TRACE.begin_direction, PROFILE_DESCENDING as i32);
            assert_eq!(TRACE.emit_args, [3, -10, 7, -4, -40, -20]);
            assert_eq!(TRACE.reverse_calls, 1);
        }
        assert_eq!(profile.profile_pending, 0);
        assert_eq!((profile.previous_x, profile.previous_y), (7, 4));
    }

    #[test]
    fn callback_failure_returns_error_pair_without_advancing_endpoint() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        profile.direction = PROFILE_ASCENDING;
        unsafe { TRACE.emit_result = 9 };

        let pair = unsafe { raster_profile_append_edge(&mut profile, 7, 12) };

        assert_eq!(pair, (12u64 << 32) | 1);
        unsafe { assert_eq!(TRACE.emit_calls, 1) };
        assert_eq!((profile.previous_x, profile.previous_y), (3, 10));
    }

    #[test]
    fn failed_profile_creation_returns_input_x_and_skips_emit() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        unsafe { TRACE.begin_result = 5 };

        let pair = unsafe { raster_profile_append_edge(&mut profile, 7, 12) };

        assert_eq!(pair, (7u64 << 32) | 1);
        unsafe {
            assert_eq!(TRACE.begin_calls, 1);
            assert_eq!(TRACE.emit_calls, 0);
        }
        assert_eq!((profile.previous_x, profile.previous_y), (3, 10));
    }

    #[test]
    fn equal_or_unknown_direction_only_updates_endpoint_and_carries_x() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        profile.direction = 3;

        let pair = unsafe { raster_profile_append_edge(&mut profile, 7, 10) };

        assert_eq!(pair, 7u64 << 32);
        unsafe {
            assert_eq!(TRACE.begin_calls, 0);
            assert_eq!(TRACE.end_calls, 0);
            assert_eq!(TRACE.emit_calls, 0);
        }
        assert_eq!((profile.previous_x, profile.previous_y), (7, 10));
    }

    #[test]
    fn signed_extremes_start_descending_not_ascending() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        profile.previous_y = i32::MAX;

        let pair = unsafe { raster_profile_append_edge(&mut profile, 9, i32::MIN as u32) };

        assert_eq!(pair, 0x8000_0000_0000_0000);
        unsafe {
            assert_eq!(TRACE.begin_direction, PROFILE_DESCENDING as i32);
            assert_eq!(TRACE.emit_args, [3, i32::MIN + 1, 9, i32::MIN, -40, -20]);
        }
    }
}
