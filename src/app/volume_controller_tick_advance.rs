//! `volume_controller_tick_advance` — original: `FUN_081f9770` @ `0x081f9770`
//! (116 bytes of instructions, `0x081f9770..0x081f97e4`; the following six
//! words through `0x081f97fc` are its literal pool). Raw ARM decoding finds
//! **4 plain unconditional `bl` calls and 0 predicated `bl` calls**.
//!
//! The function lazily constructs the 0x34-byte tick accumulator at
//! `0x089cc26c` using `{input_divisor: 12, mode_enabled: 0,
//! backoff_interval_ms: 350}`, registers its raw destructor address with the
//! C++ shutdown chain, and steps it with the caller's input and a zero rate.
//! A nonzero step result tail-branches to the identified but unported
//! `singleton_class_8c00_ready_gate` @ `0x081bb29c` with `r0 = 1`.
//!
//! Deliberate deviation: the ready gate and the literal destructor target
//! (`0x08a78eb0`, not independently identified) remain retail calls on target
//! and operation-table callbacks on hosts. This avoids inventing either
//! callee's identity while retaining the exact observable call ordering.

use core::ffi::c_void;

use super::tick_accumulator::{tick_accumulator_construct, tick_accumulator_step, TickAccumulator};

const RETAIL_ACCUMULATOR: usize = 0x089c_c26c;
const RETAIL_DESTRUCTOR: usize = 0x08a7_8eb0;
const RETAIL_DSO_HANDLE: i32 = 0x081b_0638;
const RETAIL_READY_GATE: usize = 0x081b_b29c;

type TickConstructFn = unsafe extern "C" fn(*mut TickAccumulator, u32, u8, u32) -> *mut TickAccumulator;
type TickStepFn = unsafe extern "C" fn(*mut TickAccumulator, u32, u32) -> u32;
type ShutdownRegisterFn = unsafe extern "C" fn(*mut c_void, usize, i32);
type ReadyGateFn = unsafe extern "C" fn(u32);

#[derive(Clone, Copy)]
pub struct VolumeControllerTickOps {
    pub accumulator: *mut TickAccumulator,
    pub construct: TickConstructFn,
    pub step: TickStepFn,
    pub register_shutdown: ShutdownRegisterFn,
    pub ready_gate: ReadyGateFn,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_register_shutdown(object: *mut c_void, destructor: usize, dso_handle: i32) {
    let destructor = core::mem::transmute(destructor);
    crate::runtime::shutdown_chain::cxa_atexit(object, destructor, dso_handle);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_ready_gate(value: u32) {
    let ready_gate: ReadyGateFn = core::mem::transmute(RETAIL_READY_GATE);
    ready_gate(value);
}

#[cfg(target_os = "none")]
const DEFAULT_VOLUME_CONTROLLER_TICK_OPS: VolumeControllerTickOps = VolumeControllerTickOps {
    accumulator: RETAIL_ACCUMULATOR as *mut TickAccumulator,
    construct: tick_accumulator_construct,
    step: tick_accumulator_step,
    register_shutdown: retail_register_shutdown,
    ready_gate: retail_ready_gate,
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_: *mut TickAccumulator, _: u32, _: u8, _: u32) -> *mut TickAccumulator {
    panic!("install volume-controller tick host operations before advancing it")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_step(_: *mut TickAccumulator, _: u32, _: u32) -> u32 {
    panic!("install volume-controller tick host operations before advancing it")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_register_shutdown(_: *mut c_void, _: usize, _: i32) {
    panic!("install volume-controller tick host operations before advancing it")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ready_gate(_: u32) {
    panic!("install volume-controller tick host operations before advancing it")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_VOLUME_CONTROLLER_TICK_OPS: VolumeControllerTickOps = VolumeControllerTickOps {
    accumulator: core::ptr::null_mut(),
    construct: missing_construct,
    step: missing_step,
    register_shutdown: missing_register_shutdown,
    ready_gate: missing_ready_gate,
};
#[cfg(not(target_os = "none"))]
pub static mut VOLUME_CONTROLLER_TICK_OPS: VolumeControllerTickOps = DEFAULT_VOLUME_CONTROLLER_TICK_OPS;

#[inline(always)]
unsafe fn ops() -> VolumeControllerTickOps {
    #[cfg(target_os = "none")]
    { DEFAULT_VOLUME_CONTROLLER_TICK_OPS }
    #[cfg(not(target_os = "none"))]
    { VOLUME_CONTROLLER_TICK_OPS }
}

/// Steps the volume controller's shared adaptive tick accumulator.
///
/// `context` is deliberately unused: the ARM entry overwrites `r0` with the
/// fixed accumulator address before its first load. There is no NULL guard on
/// the accumulator or its embedded guard word, matching the retail stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_controller_tick_advance(_context: *mut c_void, input: u32) {
    let operations = ops();
    let accumulator = operations.accumulator;
    if ((*accumulator).update_result & 1) == 0 {
        if crate::runtime::cxa_guard::cxa_guard_acquire(core::ptr::addr_of_mut!((*accumulator).update_result)) != 0 {
            let object = (operations.construct)(accumulator, 12, 0, 350);
            (operations.register_shutdown)(object.cast(), RETAIL_DESTRUCTOR, RETAIL_DSO_HANDLE);
            crate::runtime::cxa_guard::cxa_guard_release(core::ptr::addr_of_mut!((*accumulator).update_result));
        }
    }
    if (operations.step)(accumulator, input, 0) != 0 {
        (operations.ready_gate)(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCT_CALLS: u32 = 0;
    static mut CONSTRUCT_ARGS: (u32, u8, u32) = (0, 0, 0);
    static mut SHUTDOWN_ARGS: (*mut c_void, usize, i32) = (core::ptr::null_mut(), 0, 0);
    static mut STEP_ARGS: (*mut TickAccumulator, u32, u32) = (core::ptr::null_mut(), 0, 0);
    static mut STEP_RESULT: u32 = 0;
    static mut READY_VALUE: u32 = 0;

    unsafe extern "C" fn construct(accumulator: *mut TickAccumulator, divisor: u32, mode: u8, backoff: u32) -> *mut TickAccumulator {
        CONSTRUCT_CALLS += 1;
        CONSTRUCT_ARGS = (divisor, mode, backoff);
        accumulator
    }
    unsafe extern "C" fn register_shutdown(object: *mut c_void, destructor: usize, dso: i32) {
        SHUTDOWN_ARGS = (object, destructor, dso);
    }
    unsafe extern "C" fn step(accumulator: *mut TickAccumulator, input: u32, rate: u32) -> u32 {
        STEP_ARGS = (accumulator, input, rate);
        STEP_RESULT
    }
    unsafe extern "C" fn ready_gate(value: u32) { READY_VALUE = value; }

    struct OpsReset(VolumeControllerTickOps);
    impl Drop for OpsReset {
        fn drop(&mut self) { unsafe { VOLUME_CONTROLLER_TICK_OPS = self.0; } }
    }

    unsafe fn install(accumulator: *mut TickAccumulator, result: u32) -> OpsReset {
        CONSTRUCT_CALLS = 0;
        CONSTRUCT_ARGS = (0, 0, 0);
        SHUTDOWN_ARGS = (core::ptr::null_mut(), 0, 0);
        STEP_ARGS = (core::ptr::null_mut(), 0, 0);
        STEP_RESULT = result;
        READY_VALUE = 0;
        let old = VOLUME_CONTROLLER_TICK_OPS;
        VOLUME_CONTROLLER_TICK_OPS = VolumeControllerTickOps { accumulator, construct, step, register_shutdown, ready_gate };
        OpsReset(old)
    }

    #[test]
    fn initializes_then_signals_for_nonzero_tick_result() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let mut accumulator: TickAccumulator = core::mem::zeroed();
            let _reset = install(addr_of_mut!(accumulator), 9);
            volume_controller_tick_advance(core::ptr::null_mut(), 0x1234);
            assert_eq!(CONSTRUCT_CALLS, 1);
            assert_eq!(CONSTRUCT_ARGS, (12, 0, 350));
            assert_eq!(SHUTDOWN_ARGS, (addr_of_mut!(accumulator).cast(), RETAIL_DESTRUCTOR, RETAIL_DSO_HANDLE));
            assert_eq!(STEP_ARGS, (addr_of_mut!(accumulator), 0x1234, 0));
            assert_eq!(READY_VALUE, 1);
        }
    }

    #[test]
    fn seeded_guard_skips_initialization_and_zero_result_skips_gate() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let mut accumulator: TickAccumulator = core::mem::zeroed();
            accumulator.update_result = 1;
            let _reset = install(addr_of_mut!(accumulator), 0);
            volume_controller_tick_advance(0x1usize as *mut c_void, u32::MAX);
            assert_eq!(CONSTRUCT_CALLS, 0);
            assert_eq!(SHUTDOWN_ARGS.1, 0);
            assert_eq!(STEP_ARGS, (addr_of_mut!(accumulator), u32::MAX, 0));
            assert_eq!(READY_VALUE, 0);
        }
    }
}
