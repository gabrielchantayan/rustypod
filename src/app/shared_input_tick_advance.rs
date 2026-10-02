//! Shared input tick conversion — `FUN_08292d88` @ `0x08292d88`.
//! True extent: 208 bytes, `0x08292d88..0x08292e58` (188 code bytes and
//! five literal words). Raw image scan: two inbound plain BLs, no predicated
//! inbound BLs; body: nine plain BLs and one BLNE.
//!
//! Lazily constructs the shared accumulator with the cached divisor, mode 0
//! and backoff 350. A changed divisor or unsigned wrapping elapsed time above
//! 1000 resets timing and reinstalls the divisor. Every call stamps a fresh
//! clock sample and steps the input at rate zero; nonzero output sets divisor 1.
//! Deliberate deviations: native pointers and a local dependency context on
//! hosts replace fixed retail addresses. Existing constructor, step, reset,
//! divisor setter, guard and shutdown ports are reused; only this function is
//! newly ported. The clock's historic `usec_timer_read_seconds` name is retained
//! despite its actual /1000 conversion. No algorithmic deviation.

use super::tick_accumulator::TickAccumulator;
#[cfg(target_os = "none")]
use super::tick_accumulator::{tick_accumulator_construct, tick_accumulator_step,
    tick_accumulator_reset_timing_state, tick_accumulator_set_input_divisor};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

#[repr(C)]
pub struct SharedInputState {
    pub reserved: [u32; 2],
    pub guard: u32,
    pub divisor: u32,
    pub last_sample: u32,
}

#[derive(Clone, Copy)]
pub struct Context {
    pub state: *mut SharedInputState,
    pub accumulator: *mut TickAccumulator,
    pub clock: unsafe extern "C" fn() -> u32,
    pub construct: unsafe extern "C" fn(*mut TickAccumulator, u32, u8, u32) -> *mut TickAccumulator,
    pub register: unsafe extern "C" fn(*mut TickAccumulator),
    pub reset: unsafe extern "C" fn(*mut TickAccumulator) -> *mut TickAccumulator,
    pub set_divisor: unsafe extern "C" fn(*mut TickAccumulator, u32),
    pub step: unsafe extern "C" fn(*mut TickAccumulator, u32, u32) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn register(object: *mut TickAccumulator) {
    crate::runtime::shutdown_chain::cxa_atexit(
        object.cast(), core::mem::transmute(0x081b_0638usize), 0x089c_a09c);
}

#[cfg(not(target_os = "none"))]
pub static mut HOST_CONTEXT: Option<Context> = None;

/// Converts an input sample using the global adaptive tick accumulator.
/// Safety: retail globals and dependencies must be live; calls are serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_input_tick_advance(input: u32, divisor: u32) -> u32 {
    #[cfg(target_os = "none")]
    let context = Context {
        state: 0x089c_c928 as *mut SharedInputState,
        accumulator: 0x08ac_6cbc as *mut TickAccumulator,
        clock: crate::drivers::timer::usec_timer_read_seconds,
        construct: tick_accumulator_construct,
        register,
        reset: tick_accumulator_reset_timing_state,
        set_divisor: tick_accumulator_set_input_divisor,
        step: tick_accumulator_step,
    };
    #[cfg(not(target_os = "none"))]
    let context = HOST_CONTEXT.expect("install shared input tick host context");
    advance(context, input, divisor)
}

#[inline(always)]
unsafe fn advance(context: Context, input: u32, divisor: u32) -> u32 {
    let state = context.state;
    let guard = core::ptr::addr_of_mut!((*state).guard);
    if (*guard & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let object = (context.construct)(context.accumulator, (*state).divisor, 0, 350);
        (context.register)(object);
        cxa_guard_release(guard);
    }
    let changed = (*state).divisor != divisor;
    let expired = if changed {
        (*state).divisor = divisor;
        true
    } else {
        (context.clock)().wrapping_sub((*state).last_sample) > 1000
    };
    if expired {
        (context.reset)(context.accumulator);
        (context.set_divisor)(context.accumulator, (*state).divisor);
    }
    (*state).last_sample = (context.clock)();
    let result = (context.step)(context.accumulator, input, 0);
    if result != 0 {
        (context.set_divisor)(context.accumulator, 1);
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut NOW: u32 = 0;
    unsafe extern "C" fn clock() -> u32 { let now = NOW; NOW = NOW.wrapping_add(1); now }
    unsafe extern "C" fn construct(p: *mut TickAccumulator, divisor: u32, _: u8, _: u32) -> *mut TickAccumulator {
        (*p).input_divisor = divisor;
        p
    }
    unsafe extern "C" fn register(_: *mut TickAccumulator) {}
    use super::super::tick_accumulator::{
        tick_accumulator_reset_timing_state as reset,
        tick_accumulator_set_input_divisor as set_divisor,
    };
    unsafe extern "C" fn step(p: *mut TickAccumulator, input: u32, _: u32) -> u32 {
        if (*p).last_tick_ms == 0 { return 0; }
        (*p).remainder = (*p).remainder.wrapping_add(input);
        (*p).remainder / (*p).input_divisor
    }

    #[test]
    fn elapsed_boundary_wrap_divisor_changes_and_output_transition() {
        let _lock = LOCK.lock();
        unsafe {
            for (last, now, requested, expires) in [
                (100, 1100, 16, false), (100, 1101, 16, true),
                (u32::MAX - 499, 500, 16, false),
                (u32::MAX - 499, 501, 16, true),
                (100, 100, 32, true), (100, 99, 16, true),
            ] {
                let mut state = SharedInputState { reserved: [7, 9], guard: 1, divisor: 16, last_sample: last };
                let mut accumulator: TickAccumulator = core::mem::zeroed();
                accumulator.last_tick_ms = 77;
                accumulator.input_divisor = 16;
                accumulator.remainder = 3;
                NOW = now;
                HOST_CONTEXT = Some(Context { state: &mut state, accumulator: &mut accumulator,
                    clock, construct, register, reset, set_divisor, step });
                let result = shared_input_tick_advance(13, requested);
                assert_eq!(result, if expires { 0 } else { 1 });
                assert_eq!(accumulator.input_divisor, if expires { requested } else { 1 });
                assert_eq!(accumulator.remainder, if expires { 0 } else { 16 });
                assert_eq!(state.divisor, requested);
                assert_eq!(state.last_sample, if requested != 16 { now } else { now.wrapping_add(1) });
                assert_eq!(state.reserved, [7, 9]);
            }
            HOST_CONTEXT = None;
        }
    }

    #[test]
    fn guard_whole_word_and_zero_output_preserve_existing_divisor() {
        let _lock = LOCK.lock();
        unsafe {
            for guard in [0, 1, 2] {
                let mut state = SharedInputState { reserved: [0; 2], guard, divisor: 16, last_sample: 100 };
                let mut accumulator: TickAccumulator = core::mem::zeroed();
                accumulator.input_divisor = 31;
                NOW = 100;
                HOST_CONTEXT = Some(Context { state: &mut state, accumulator: &mut accumulator,
                    clock, construct, register, reset, set_divisor, step });
                assert_eq!(shared_input_tick_advance(0, 16), 0);
                assert_eq!(accumulator.input_divisor, if guard == 0 { 16 } else { 31 });
                assert_eq!(state.guard, if guard == 0 { 1 } else { guard });
                assert_eq!(state.last_sample, 101);
            }
            HOST_CONTEXT = None;
        }
    }
}
