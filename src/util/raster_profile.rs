//! Raster-edge profile state transitions from `FUN_080e99d8` @ `0x080e99d8`
//! and scanline emission from `FUN_080e9b24` @ `0x080e9b24`.
//!
//! **Originals:** retailOS 2.0.4. `FUN_080e99d8` is 332 bytes (`0x14c`);
//! `FUN_080e9b24` is 408 bytes (`0x198`). Reference C:
//! `ipod-decomp/decomp/c/008/080e99d8_FUN_080e99d8.c` and
//! `ipod-decomp/decomp/c/008/080e9b24_FUN_080e9b24.c`; assembly:
//! `ipod-decomp/decomp/osos.asm` at the respective load addresses.
//!
//! The state-machine front end compares the incoming edge ordinate with the
//! preceding one *as signed 32-bit values*, creates an ascending or descending
//! profile when needed, ends and reverses a profile at a direction change, and
//! emits the normalized edge segment. The scanline emitter clips an ascending
//! edge to its vertical limits, reuses an exact prior scanline when possible,
//! initializes a pending profile at the first emitted scanline, then uses
//! quotient/remainder DDA to append one x ordinate per scanline.
//!
//! `raster_profile_append_edge`'s `u64` return is the ARM `longlong` register
//! pair: low word is the error flag, high word is the carried ordinate (the
//! input ordinate for ascending profiles, its wrapping negation for
//! descending profiles, or the input abscissa while no profile is active).
//!
//! The profile allocator/finalizer and arithmetic helpers remain retailOS
//! calls (`0x080767a8`, `0x08076228`, `0x0804d1a8`, and `0x08031568`).
//! They, plus host-only stores into the firmware-addressed scanline buffer,
//! are explicit volatile callback seams; target builds call or write the
//! retail layout directly and host tests replace them.

/// Direction byte stored at state offset `0x68`.
pub const PROFILE_ASCENDING: u8 = 1;
/// Direction byte stored at state offset `0x68`.
pub const PROFILE_DESCENDING: u8 = 2;

/// The portion of the firmware raster state touched by the raster-profile
/// transition and scanline-emission ports.
///
/// The fields deliberately retain their retailOS offsets. Pointer fields are
/// 32-bit firmware addresses; the scanline/profile targets are dereferenced
/// only on ARM, where pointers are 32 bits.
#[repr(C)]
pub struct RasterProfileState {
    /// Arithmetic right-shift count used to turn a y ordinate into a scanline.
    pub scanline_shift: u32,
    /// Fixed-point scanline height, also the DDA horizontal numerator scale.
    pub scanline_height: u32,
    _padding_08_27: [u8; 0x20],
    /// One-past-the-end firmware address of the i32 scanline-x buffer.
    pub scanline_end: u32,
    /// Firmware address of the next i32 scanline-x slot.
    pub scanline_cursor: u32,
    /// Raster error/status byte word; emission exhaustion stores `0x62`.
    pub raster_status: u32,
    _padding_34_47: [u8; 0x14],
    pub previous_x: i32,
    pub previous_y: i32,
    pub lower_limit: i32,
    pub upper_limit: i32,
    _padding_58_59: [u8; 2],
    /// Set by profile creation and consumed by the segment emitter.
    pub profile_pending: u8,
    /// Whether the final emitted ordinate lies exactly on a scanline boundary.
    pub reusable_final_scanline: u8,
    /// Firmware pointer to the active profile; its signed accumulator is at
    /// `active_profile + 0x14`.
    pub active_profile: u32,
    _padding_60_67: [u8; 8],
    pub direction: u8,
}

/// Calls made by the raster-profile ports into unported routines, plus host
/// seams for writes through 32-bit firmware addresses. Error-returning
/// routines return nonzero to signal an error.
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
    /// Computes the retailOS signed scaled quotient used when clipping an edge.
    pub scaled_divide: unsafe extern "C" fn(i32, i32, i32, i32, i32) -> i32,
    /// Returns the signed quotient in the low word and remainder in the high
    /// word, matching `FUN_08031568`'s ARM register pair.
    pub quotient_remainder: unsafe extern "C" fn(i32, i32) -> u64,
    /// Host seam for a store through `scanline_cursor`; ARM writes directly.
    pub store_scanline_x: unsafe extern "C" fn(*mut RasterProfileState, u32, i32),
    /// Host seam for the active profile's `+0x14` first-scanline store; ARM
    /// writes directly.
    pub set_profile_first_scanline: unsafe extern "C" fn(*mut RasterProfileState, i32),
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


unsafe extern "C" fn missing_reverse_profile_accumulator(_: *mut RasterProfileState) {}

unsafe extern "C" fn missing_scaled_divide(_: i32, _: i32, _: i32, _: i32, _: i32) -> i32 {
    0
}

unsafe extern "C" fn missing_quotient_remainder(_: i32, _: i32) -> u64 {
    0
}

unsafe extern "C" fn missing_store_scanline_x(_: *mut RasterProfileState, _: u32, _: i32) {}

unsafe extern "C" fn missing_set_profile_first_scanline(_: *mut RasterProfileState, _: i32) {}

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
unsafe extern "C" fn retail_scaled_divide(
    delta_x: i32,
    delta_y: i32,
    edge_height: i32,
    x: i32,
    repeated_x: i32,
) -> i32 {
    let callback: unsafe extern "C" fn(i32, i32, i32, i32, i32) -> i32 =
        core::mem::transmute(0x0804_d1a8usize);
    callback(delta_x, delta_y, edge_height, x, repeated_x)
}

#[cfg(target_arch = "arm")]
unsafe extern "C" fn retail_quotient_remainder(numerator: i32, denominator: i32) -> u64 {
    let callback: unsafe extern "C" fn(i32, i32) -> u64 =
        core::mem::transmute(0x0803_1568usize);
    callback(numerator, denominator)
}

#[cfg(target_arch = "arm")]
const DEFAULT_RASTER_PROFILE_OPS: RasterProfileOps = RasterProfileOps {
    // These wrappers tail into retailOS routines that remain unported.
    end_profile: retail_end_profile,
    begin_profile: retail_begin_profile,
    emit_segment: raster_profile_emit_segment,
    scaled_divide: retail_scaled_divide,
    quotient_remainder: retail_quotient_remainder,
    store_scanline_x: missing_store_scanline_x,
    set_profile_first_scanline: missing_set_profile_first_scanline,
    reverse_profile_accumulator: missing_reverse_profile_accumulator,
};

#[cfg(not(target_arch = "arm"))]
const DEFAULT_RASTER_PROFILE_OPS: RasterProfileOps = RasterProfileOps {
    end_profile: missing_end_profile,
    begin_profile: missing_begin_profile,
    emit_segment: raster_profile_emit_segment,
    scaled_divide: missing_scaled_divide,
    quotient_remainder: missing_quotient_remainder,
    store_scanline_x: missing_store_scanline_x,
    set_profile_first_scanline: missing_set_profile_first_scanline,
    reverse_profile_accumulator: missing_reverse_profile_accumulator,
};

/// The raster-profile operation table. Target integration may replace the
/// remaining retailOS calls; host tests install deterministic mocks.
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

#[inline(always)]
fn scanline_for_y(y: i32, shift: u32) -> i32 {
    let shift = shift & 0xff;
    if shift >= i32::BITS {
        if y < 0 { -1 } else { 0 }
    } else {
        y >> shift
    }
}

#[inline(always)]
unsafe fn store_scanline_x(
    state: *mut RasterProfileState,
    address: u32,
    x: i32,
    ops: RasterProfileOps,
) {
    #[cfg(target_arch = "arm")]
    {
        (address as usize as *mut i32).write(x);
    }
    #[cfg(not(target_arch = "arm"))]
    {
        (ops.store_scanline_x)(state, address, x);
    }
}

#[inline(always)]
unsafe fn set_profile_first_scanline(
    state: *mut RasterProfileState,
    scanline: i32,
    ops: RasterProfileOps,
) {
    #[cfg(target_arch = "arm")]
    {
        (((*state).active_profile as usize + 0x14) as *mut i32).write(scanline);
    }
    #[cfg(not(target_arch = "arm"))]
    {
        (ops.set_profile_first_scanline)(state, scanline);
    }
}

/// raster_profile_emit_segment — original: `FUN_080e9b24` @ `0x080e9b24`
/// (408 bytes).
///
/// Clips a strictly ascending edge to `lower_limit..=upper_limit`, emits its
/// x crossings into the state-owned scanline buffer, and returns one only when
/// the buffer lacks room. The fixed-point DDA deliberately uses retailOS
/// `FUN_08031568` for signed quotient/remainder; clipping deliberately uses
/// retailOS `FUN_0804d1a8`. Both unported helpers are operation-table seams.
/// Reference C: `decomp/c/008/080e9b24_FUN_080e9b24.c`; assembly:
/// `decomp/osos.asm` at `0x080e9b24`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn raster_profile_emit_segment(
    state: *mut RasterProfileState,
    previous_x: i32,
    previous_y: i32,
    x: i32,
    y: i32,
    lower_limit: i32,
    upper_limit: i32,
) -> u32 {
    let delta_y = y.wrapping_sub(previous_y);
    let delta_x = x.wrapping_sub(previous_x);
    if delta_y <= 0 || y < lower_limit || upper_limit < previous_y {
        return 0;
    }

    let ops = profile_ops();
    let shift = (*state).scanline_shift;
    let height = (*state).scanline_height as i32;
    let mut first_x;
    let mut first_scanline;
    let first_remainder;
    if previous_y < lower_limit {
        first_x = previous_x.wrapping_add((ops.scaled_divide)(
            delta_x,
            lower_limit.wrapping_sub(previous_y),
            delta_y,
            x,
            x,
        ));
        first_scanline = scanline_for_y(lower_limit, shift);
        first_remainder = 0;
    } else {
        first_x = previous_x;
        first_scanline = scanline_for_y(previous_y, shift);
        first_remainder = (height.wrapping_sub(1) & previous_y) as u32;
    }

    let (last_scanline, last_remainder) = if upper_limit < y {
        (scanline_for_y(upper_limit, shift), 0)
    } else {
        (
            scanline_for_y(y, shift),
            (height.wrapping_sub(1) & y) as u32,
        )
    };

    if (first_remainder as i32) < 1 {
        if (*state).reusable_final_scanline != 0 {
            (*state).scanline_cursor = (*state).scanline_cursor.wrapping_sub(4);
            (*state).reusable_final_scanline = 0;
        }
    } else {
        if first_scanline == last_scanline {
            return 0;
        }
        first_x = first_x.wrapping_add((ops.quotient_remainder)(
            delta_x.wrapping_mul(height.wrapping_sub(first_remainder as i32)),
            delta_y,
        ) as u32 as i32);
        first_scanline = first_scanline.wrapping_add(1);
    }

    (*state).reusable_final_scanline = u8::from(last_remainder == 0);
    if (*state).profile_pending != 0 {
        set_profile_first_scanline(state, first_scanline, ops);
        (*state).profile_pending = 0;
    }

    let mut remaining = last_scanline.wrapping_sub(first_scanline).wrapping_add(1);
    let mut cursor = (*state).scanline_cursor;
    if (*state).scanline_end <= cursor.wrapping_add((remaining as u32).wrapping_mul(4)) {
        (*state).raster_status = 0x62;
        return 1;
    }

    let packed = if delta_x < 1 {
        (ops.quotient_remainder)(delta_x.wrapping_neg().wrapping_mul(height), delta_y)
    } else {
        (ops.quotient_remainder)(delta_x.wrapping_mul(height), delta_y)
    };
    let remainder = (packed >> 32) as u32 as i32;
    let mut x_step = packed as u32 as i32;
    let x_direction;
    if delta_x < 1 {
        x_step = x_step.wrapping_neg();
        x_direction = -1;
    } else {
        x_direction = 1;
    }

    let mut dda_error = delta_y.wrapping_neg();
    while remaining > 0 {
        dda_error = dda_error.wrapping_add(remainder);
        store_scanline_x(state, cursor, first_x, ops);
        cursor = cursor.wrapping_add(4);
        first_x = first_x.wrapping_add(x_step);
        if dda_error >= 0 {
            first_x = first_x.wrapping_add(x_direction);
            dda_error = dda_error.wrapping_sub(delta_y);
        }
        remaining = remaining.wrapping_sub(1);
    }
    (*state).scanline_cursor = cursor;
    0
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
        scaled_divide_calls: u32,
        scanline_store_calls: u32,
        scanline_addresses: [u32; 8],
        scanline_xs: [i32; 8],
        profile_first_scanline_calls: u32,
        profile_first_scanline: i32,
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
        scaled_divide_calls: 0,
        scanline_store_calls: 0,
        scanline_addresses: [0; 8],
        scanline_xs: [0; 8],
        profile_first_scanline_calls: 0,
        profile_first_scanline: 0,
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

    unsafe extern "C" fn mock_scaled_divide(
        delta_x: i32,
        clipped_height: i32,
        edge_height: i32,
        _: i32,
        _: i32,
    ) -> i32 {
        TRACE.scaled_divide_calls += 1;
        delta_x.wrapping_mul(clipped_height) / edge_height
    }

    unsafe extern "C" fn mock_quotient_remainder(numerator: i32, denominator: i32) -> u64 {
        let quotient = numerator / denominator;
        let remainder = numerator % denominator;
        ((remainder as u32 as u64) << 32) | quotient as u32 as u64
    }

    unsafe extern "C" fn mock_store_scanline_x(_: *mut RasterProfileState, address: u32, x: i32) {
        let index = TRACE.scanline_store_calls as usize;
        TRACE.scanline_addresses[index] = address;
        TRACE.scanline_xs[index] = x;
        TRACE.scanline_store_calls += 1;
    }

    unsafe extern "C" fn mock_set_profile_first_scanline(
        _: *mut RasterProfileState,
        scanline: i32,
    ) {
        TRACE.profile_first_scanline_calls += 1;
        TRACE.profile_first_scanline = scanline;
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
                scaled_divide_calls: 0,
                scanline_store_calls: 0,
                scanline_addresses: [0; 8],
                scanline_xs: [0; 8],
                profile_first_scanline_calls: 0,
                profile_first_scanline: 0,
            };
            RASTER_PROFILE_OPS = RasterProfileOps {
                end_profile: mock_end,
                begin_profile: mock_begin,
                emit_segment: mock_emit,
                scaled_divide: mock_scaled_divide,
                quotient_remainder: mock_quotient_remainder,
                store_scanline_x: mock_store_scanline_x,
                set_profile_first_scanline: mock_set_profile_first_scanline,
                reverse_profile_accumulator: mock_reverse,
            };
        }
        (lock, HookReset)
    }

    fn state() -> RasterProfileState {
        RasterProfileState {
            scanline_shift: 2,
            scanline_height: 4,
            _padding_08_27: [0; 0x20],
            scanline_end: 0x200,
            scanline_cursor: 0x100,
            raster_status: 0,
            _padding_34_47: [0; 0x14],
            previous_x: 3,
            previous_y: 10,
            lower_limit: 20,
            upper_limit: 40,
            _padding_58_59: [0; 2],
            profile_pending: 0,
            reusable_final_scanline: 0,
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

    #[test]
    fn emits_each_scanline_with_quotient_remainder_dda() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        profile.previous_x = 0;
        profile.previous_y = 1;
        profile.lower_limit = 0;
        profile.upper_limit = 20;

        let error = unsafe { raster_profile_emit_segment(&mut profile, 0, 1, 10, 9, 0, 20) };

        assert_eq!(error, 0);
        assert_eq!(profile.scanline_cursor, 0x108);
        assert_eq!(profile.reusable_final_scanline, 0);
        unsafe {
            assert_eq!(TRACE.scaled_divide_calls, 0);
            assert_eq!(TRACE.scanline_store_calls, 2);
            assert_eq!(TRACE.scanline_addresses[..2], [0x100, 0x104]);
            assert_eq!(TRACE.scanline_xs[..2], [3, 8]);
        }
    }

    #[test]
    fn clips_reuses_exact_prior_scanline_and_starts_pending_profile() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        profile.scanline_cursor = 0x104;
        profile.previous_x = 2;
        profile.previous_y = -3;
        profile.reusable_final_scanline = 1;
        profile.profile_pending = 1;

        let error = unsafe { raster_profile_emit_segment(&mut profile, 2, -3, 13, 8, 0, 7) };

        assert_eq!(error, 0);
        assert_eq!(profile.scanline_cursor, 0x108);
        assert_eq!(profile.reusable_final_scanline, 1);
        assert_eq!(profile.profile_pending, 0);
        unsafe {
            assert_eq!(TRACE.scaled_divide_calls, 1);
            assert_eq!(TRACE.profile_first_scanline_calls, 1);
            assert_eq!(TRACE.profile_first_scanline, 0);
            assert_eq!(TRACE.scanline_store_calls, 2);
            assert_eq!(TRACE.scanline_addresses[..2], [0x100, 0x104]);
            assert_eq!(TRACE.scanline_xs[..2], [5, 9]);
        }
    }

    #[test]
    fn reports_exhausted_scanline_buffer_without_storing() {
        let (_lock, _reset) = fresh();
        let mut profile = state();
        profile.previous_x = 0;
        profile.previous_y = 0;
        profile.scanline_end = 0x10c;

        let error = unsafe { raster_profile_emit_segment(&mut profile, 0, 0, 8, 8, 0, 20) };

        assert_eq!(error, 1);
        assert_eq!(profile.raster_status, 0x62);
        assert_eq!(profile.scanline_cursor, 0x100);
        unsafe { assert_eq!(TRACE.scanline_store_calls, 0) };
    }
}
