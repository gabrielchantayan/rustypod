//! `tick_accumulator_construct` — original: `FUN_081bb450` @ `0x081bb450`
//! (176 bytes of code; the true 192-byte extent is
//! `0x081bb450..0x081bb510`, including four trailing literal-pool words).
//! Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/018/081bb450_FUN_081bb450.c`;
//! raw ARM was decoded from `work/firmware/osos.dec`.
//!
//! **28 `bl` call sites, all unconditional and no predicated calls**, verified
//! by decoding every ARM B/BL word in the decrypted image. The constructor
//! seeds a 0x34-byte tick accumulator from three separately sampled millisecond
//! ticks, clears its scaled-input state, selects its input bounds by the
//! system-mode query, then registers `&this` through the global observer's
//! vtable `+0x1c` callback. Its update sibling at `0x081bb2a0` consumes the
//! tick deadlines, scale factor, remainder, input divisor, bound, and flags.
//!
//! The tick helper `0x081bb384`, mode query `0x080562ec`, and observer getter
//! `0x080b43e8` are not yet ported (confirmed against `names.yaml`). Target
//! builds invoke those retail entry points directly; host tests install the
//! equivalent operation table. The observer's concrete identity is unknown,
//! so this module deliberately names only its recovered registration role.
//!
//! The module also carries the constructor's step sibling
//! [`tick_accumulator_step`] (`0x081bb3a0`), which gates one call of the
//! still-unported update body `0x081bb2a0` on a nonzero `last_tick_ms` and
//! re-stamps the tick on every call.

use core::ptr::addr_of_mut;

/// State initialized by the 0x081bb450 tick-accumulator constructor.
///
/// All words intentionally remain `u32`: this is a 32-bit retailOS object,
/// and its byte flags occupy the two bytes immediately after `mode_enabled`.
#[repr(C)]
pub struct TickAccumulator {
    pub last_tick_ms: u32,
    pub backoff_deadline_ms: u32,
    pub next_update_ms: u32,
    pub scale_factor: u32,
    pub scaled_input: u32,
    pub remainder: u32,
    pub input_divisor: u32,
    pub scale_factor_limit: u32,
    pub update_result: u32,
    pub mode_enabled: u8,
    pub scale_suppressed: u8,
    _padding: [u8; 2],
    pub lower_input_bound: u32,
    pub upper_input_bound: u32,
    pub backoff_interval_ms: u32,
}

/// Retail observer registration ABI: the callback receives a pointer to the
/// local `this` pointer rather than `this` directly.
pub type TickAccumulatorRegisterFn = unsafe extern "C" fn(*mut *mut TickAccumulator);

/// Retail update ABI of the unported sibling at `0x081bb2a0`: it consumes the
/// new input sample and the measured rate, then leaves the output-tick count
/// (the remainder-plus-input quotient) in `r0`.
pub type TickAccumulatorUpdateFn =
    unsafe extern "C" fn(*mut TickAccumulator, u32, u32) -> u32;

/// Dependencies of [`tick_accumulator_construct`] and [`tick_accumulator_step`]
/// that remain in retailOS.
#[derive(Clone, Copy)]
pub struct TickAccumulatorOps {
    pub tick_millis: unsafe extern "C" fn() -> u32,
    pub system_mode_enabled: unsafe extern "C" fn() -> u32,
    pub register: TickAccumulatorRegisterFn,
    pub update: TickAccumulatorUpdateFn,
}

const RETAIL_TICK_MILLIS: usize = 0x081b_b384;
const RETAIL_SYSTEM_MODE_ENABLED: usize = 0x0805_62ec;
const RETAIL_OBSERVER_GETTER: usize = 0x080b_43e8;
const RETAIL_TICK_UPDATE: usize = 0x081b_b2a0;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tick_millis() -> u32 {
    let tick_millis: unsafe extern "C" fn() -> u32 = core::mem::transmute(RETAIL_TICK_MILLIS);
    tick_millis()
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_system_mode_enabled() -> u32 {
    let system_mode_enabled: unsafe extern "C" fn() -> u32 =
        core::mem::transmute(RETAIL_SYSTEM_MODE_ENABLED);
    system_mode_enabled()
}

#[cfg(target_os = "none")]
#[repr(C)]
struct RetailObserver {
    vtable: *const RetailObserverVtable,
}

#[cfg(target_os = "none")]
#[repr(C)]
struct RetailObserverVtable {
    _slots_before_register: [usize; 7],
    register: unsafe extern "C" fn(*mut RetailObserver, *mut *mut TickAccumulator),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_register(accumulator: *mut *mut TickAccumulator) {
    let observer_getter: unsafe extern "C" fn() -> *mut RetailObserver =
        core::mem::transmute(RETAIL_OBSERVER_GETTER);
    let observer = observer_getter();
    ((*(*observer).vtable).register)(observer, accumulator);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_update(
    accumulator: *mut TickAccumulator,
    input: u32,
    measured_rate: u32,
) -> u32 {
    let update: TickAccumulatorUpdateFn = core::mem::transmute(RETAIL_TICK_UPDATE);
    update(accumulator, input, measured_rate)
}

#[cfg(target_os = "none")]
const DEFAULT_TICK_ACCUMULATOR_OPS: TickAccumulatorOps = TickAccumulatorOps {
    tick_millis: retail_tick_millis,
    system_mode_enabled: retail_system_mode_enabled,
    register: retail_register,
    update: retail_update,
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tick_millis() -> u32 {
    panic!("install tick accumulator host operations before constructing one")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_system_mode_enabled() -> u32 {
    panic!("install tick accumulator host operations before constructing one")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_register(_: *mut *mut TickAccumulator) {
    panic!("install tick accumulator host operations before constructing one")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(_: *mut TickAccumulator, _: u32, _: u32) -> u32 {
    panic!("install tick accumulator host operations before stepping one")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_TICK_ACCUMULATOR_OPS: TickAccumulatorOps = TickAccumulatorOps {
    tick_millis: missing_tick_millis,
    system_mode_enabled: missing_system_mode_enabled,
    register: missing_register,
    update: missing_update,
};

/// Host-side dependency seam. Tests replace this table with deterministic
/// clock, mode, and observer-registration fixtures.
#[cfg(not(target_os = "none"))]
pub static mut TICK_ACCUMULATOR_OPS: TickAccumulatorOps = DEFAULT_TICK_ACCUMULATOR_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn ops() -> TickAccumulatorOps {
    DEFAULT_TICK_ACCUMULATOR_OPS
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ops() -> TickAccumulatorOps {
    TICK_ACCUMULATOR_OPS
}

/// tick_accumulator_construct — original: `FUN_081bb450` @ `0x081bb450`
/// (176 code bytes plus 16 literal-pool bytes; 28 unconditional `bl` sites).
///
/// Initializes `accumulator`, registers its address with the global observer,
/// and returns the same address. The caller must provide writable 0x34-byte
/// storage. It intentionally has no NULL guard, matching the ARM stores at
/// `r0 + 0x00..0x30`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tick_accumulator_construct(
    accumulator: *mut TickAccumulator,
    input_divisor: u32,
    mode_enabled: u8,
    backoff_interval_ms: u32,
) -> *mut TickAccumulator {
    let operations = ops();
    (*accumulator).last_tick_ms = (operations.tick_millis)();
    (*accumulator).backoff_deadline_ms = (operations.tick_millis)().wrapping_add(backoff_interval_ms);
    (*accumulator).next_update_ms = (operations.tick_millis)().wrapping_add(400);
    (*accumulator).scale_factor = 1;
    (*accumulator).scaled_input = 0;
    (*accumulator).remainder = 0;
    (*accumulator).input_divisor = input_divisor;
    (*accumulator).scale_factor_limit = 16;
    (*accumulator).update_result = 0;
    (*accumulator).mode_enabled = mode_enabled;
    (*accumulator).scale_suppressed = 0;

    if (operations.system_mode_enabled)() == 0 {
        (*accumulator).lower_input_bound = 10_000;
    } else {
        (*accumulator).lower_input_bound = 17_000;
    }
    if (operations.system_mode_enabled)() == 0 {
        (*accumulator).upper_input_bound = 15_000;
    } else {
        (*accumulator).upper_input_bound = 20_000;
    }
    (*accumulator).backoff_interval_ms = backoff_interval_ms;

    let mut local_accumulator = accumulator;
    (operations.register)(addr_of_mut!(local_accumulator));
    accumulator
}

/// tick_accumulator_step — original: `FUN_081bb3a0` @ `0x081bb3a0`
/// (48 bytes; **23 `bl` call sites, all unconditional and no predicated
/// calls**, verified by decoding every ARM B/BL word in the decrypted image).
///
/// Steps the 0x34-byte accumulator by one sample:
///
/// ```text
/// result = 0
/// if accumulator->last_tick_ms != 0:
///     result = tick_accumulator_update(accumulator, input, measured_rate)  // 0x081bb2a0
/// accumulator->update_result = result        // +0x20
/// accumulator->last_tick_ms  = tick_millis() // +0x00, 0x081bb384
/// return accumulator->update_result
/// ```
///
/// The original forwards its own `r1`/`r2` untouched into the update sibling
/// (the `bl` at `0x081bb3b8` sets only `r0`); callers were verified to load
/// both argument registers before every call (e.g. `0x08113dfc`/`0x08113e00`,
/// `0x0811a278`/`0x0811a280`), so the true signature is three-argument, not
/// the one-argument prototype Ghidra reports. `input` is the raw sample folded
/// into the accumulator's remainder/divisor state by the update; `measured_rate`
/// is the value the update compares against `upper_input_bound` when deciding
/// backoff. Ghidra also types the update sibling `void`, but its `r0` on exit
/// is the `__rt_sdiv` quotient — the output-tick count this function stores
/// and returns.
///
/// A zero `last_tick_ms` (fresh or externally cleared accumulator) skips the
/// update entirely: `update_result` becomes 0 and only the tick is re-stamped.
/// The function deliberately has no NULL guard on `accumulator`, matching the
/// unconditional ARM load at `[r0]`; every one of the 23 call sites is an
/// unconditional `bl`.
///
/// Deviation: the update sibling `0x081bb2a0` and tick helper `0x081bb384`
/// remain in retailOS, so both are reached through the module's operation
/// table (direct retail entry calls on target, host fixtures in tests).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tick_accumulator_step(
    accumulator: *mut TickAccumulator,
    input: u32,
    measured_rate: u32,
) -> u32 {
    let operations = ops();
    let mut result = 0;
    if (*accumulator).last_tick_ms != 0 {
        result = (operations.update)(accumulator, input, measured_rate);
    }
    (*accumulator).update_result = result;
    (*accumulator).last_tick_ms = (operations.tick_millis)();
    (*accumulator).update_result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::size_of;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut TICKS: [u32; 3] = [0; 3];
    static mut TICK_INDEX: usize = 0;
    static mut MODE_ENABLED: u32 = 0;
    static mut REGISTERED: *mut TickAccumulator = core::ptr::null_mut();
    static mut REGISTER_CALLS: u32 = 0;

    unsafe extern "C" fn mock_tick_millis() -> u32 {
        let value = TICKS[TICK_INDEX];
        TICK_INDEX += 1;
        value
    }

    unsafe extern "C" fn mock_system_mode_enabled() -> u32 {
        MODE_ENABLED
    }

    unsafe extern "C" fn mock_register(accumulator: *mut *mut TickAccumulator) {
        REGISTER_CALLS += 1;
        REGISTERED = accumulator.read();
    }

    struct OpsReset(TickAccumulatorOps);

    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe { TICK_ACCUMULATOR_OPS = self.0 };
        }
    }

    unsafe fn install_fixture(ticks: [u32; 3], mode_enabled: u32) -> OpsReset {
        TICKS = ticks;
        TICK_INDEX = 0;
        MODE_ENABLED = mode_enabled;
        REGISTERED = core::ptr::null_mut();
        REGISTER_CALLS = 0;
        let old = TICK_ACCUMULATOR_OPS;
        TICK_ACCUMULATOR_OPS = TickAccumulatorOps {
            tick_millis: mock_tick_millis,
            system_mode_enabled: mock_system_mode_enabled,
            register: mock_register,
            update: missing_update,
        };
        OpsReset(old)
    }

    #[test]
    fn constructs_with_tick_wrap_mode_bounds_and_observer_registration() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(size_of::<TickAccumulator>(), 0x34);

        unsafe {
            let _reset = install_fixture([100, 200, 300], 1);
            let mut enabled: TickAccumulator = core::mem::zeroed();
            let enabled_ptr = tick_accumulator_construct(addr_of_mut!(enabled), 6, 1, 0x15e);
            assert_eq!(enabled_ptr, addr_of!(enabled) as *mut TickAccumulator);
            assert_eq!(enabled.last_tick_ms, 100);
            assert_eq!(enabled.backoff_deadline_ms, 200 + 0x15e);
            assert_eq!(enabled.next_update_ms, 700);
            assert_eq!(enabled.scale_factor, 1);
            assert_eq!(enabled.scaled_input, 0);
            assert_eq!(enabled.remainder, 0);
            assert_eq!(enabled.input_divisor, 6);
            assert_eq!(enabled.scale_factor_limit, 16);
            assert_eq!(enabled.update_result, 0);
            assert_eq!(enabled.mode_enabled, 1);
            assert_eq!(enabled.scale_suppressed, 0);
            assert_eq!(enabled.lower_input_bound, 17_000);
            assert_eq!(enabled.upper_input_bound, 20_000);
            assert_eq!(enabled.backoff_interval_ms, 0x15e);
            assert_eq!(REGISTER_CALLS, 1);
            assert_eq!(REGISTERED, enabled_ptr);
        }

        unsafe {
            let _reset = install_fixture([0xffff_fff0, 0xffff_fff8, 0xffff_ffff], 0);
            let mut disabled: TickAccumulator = core::mem::zeroed();
            let disabled_ptr = tick_accumulator_construct(addr_of_mut!(disabled), 2, 0, 0x20);
            assert_eq!(disabled_ptr, addr_of!(disabled) as *mut TickAccumulator);
            assert_eq!(disabled.backoff_deadline_ms, 0x18);
            assert_eq!(disabled.next_update_ms, 399);
            assert_eq!(disabled.lower_input_bound, 10_000);
            assert_eq!(disabled.upper_input_bound, 15_000);
            assert_eq!(REGISTER_CALLS, 1);
            assert_eq!(REGISTERED, disabled_ptr);
        }
    }

    static mut STEP_TICK: u32 = 0;
    static mut UPDATE_CALLS: u32 = 0;
    static mut UPDATE_TARGET: *mut TickAccumulator = core::ptr::null_mut();
    static mut UPDATE_INPUT: u32 = 0;
    static mut UPDATE_RATE: u32 = 0;
    static mut UPDATE_RESULT: u32 = 0;

    unsafe extern "C" fn step_tick_millis() -> u32 {
        STEP_TICK
    }

    unsafe extern "C" fn mock_update(
        accumulator: *mut TickAccumulator,
        input: u32,
        measured_rate: u32,
    ) -> u32 {
        UPDATE_CALLS += 1;
        UPDATE_TARGET = accumulator;
        UPDATE_INPUT = input;
        UPDATE_RATE = measured_rate;
        UPDATE_RESULT
    }

    unsafe fn install_step_fixture(tick: u32, update_result: u32) -> OpsReset {
        STEP_TICK = tick;
        UPDATE_CALLS = 0;
        UPDATE_TARGET = core::ptr::null_mut();
        UPDATE_INPUT = 0;
        UPDATE_RATE = 0;
        UPDATE_RESULT = update_result;
        let old = TICK_ACCUMULATOR_OPS;
        TICK_ACCUMULATOR_OPS = TickAccumulatorOps {
            tick_millis: step_tick_millis,
            system_mode_enabled: mock_system_mode_enabled,
            register: mock_register,
            update: mock_update,
        };
        OpsReset(old)
    }

    #[test]
    fn step_runs_update_and_restamps_tick_when_seeded() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _reset = install_step_fixture(4_200, 7);
            let mut accumulator: TickAccumulator = core::mem::zeroed();
            accumulator.last_tick_ms = 1;
            accumulator.update_result = 0xdead_beef;

            let result = tick_accumulator_step(addr_of_mut!(accumulator), 0x1234, 0x5678);

            assert_eq!(UPDATE_CALLS, 1);
            assert_eq!(UPDATE_TARGET, addr_of_mut!(accumulator));
            assert_eq!(UPDATE_INPUT, 0x1234);
            assert_eq!(UPDATE_RATE, 0x5678);
            assert_eq!(accumulator.update_result, 7);
            assert_eq!(accumulator.last_tick_ms, 4_200);
            assert_eq!(result, 7);
        }
    }

    #[test]
    fn step_skips_update_and_zeroes_result_when_tick_is_zero() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _reset = install_step_fixture(9_999, 0xaaaa_bbbb);
            let mut accumulator: TickAccumulator = core::mem::zeroed();
            accumulator.last_tick_ms = 0;
            accumulator.update_result = 0xdead_beef;

            let result = tick_accumulator_step(addr_of_mut!(accumulator), 0x1234, 0x5678);

            // The unported update sibling must not run: the original's beq
            // skips the bl and falls through with r0 = 0.
            assert_eq!(UPDATE_CALLS, 0);
            assert_eq!(accumulator.update_result, 0);
            assert_eq!(accumulator.last_tick_ms, 9_999);
            assert_eq!(result, 0);
        }
    }

    #[test]
    fn step_propagates_zero_update_result() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _reset = install_step_fixture(u32::MAX, 0);
            let mut accumulator: TickAccumulator = core::mem::zeroed();
            accumulator.last_tick_ms = u32::MAX;
            accumulator.update_result = 5;

            let result = tick_accumulator_step(addr_of_mut!(accumulator), 0, 0);

            assert_eq!(UPDATE_CALLS, 1);
            assert_eq!(accumulator.update_result, 0);
            assert_eq!(accumulator.last_tick_ms, u32::MAX);
            assert_eq!(result, 0);
        }
    }
}
