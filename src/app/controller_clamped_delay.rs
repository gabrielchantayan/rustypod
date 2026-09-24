//! `controller_clamped_delay` — original: `FUN_08114dc0` @ `0x08114dc0`.
//!
//! The raw body is **72 bytes** (`0x08114dc0..0x08114e07`); the next real
//! function begins at `0x08114e08` with `push {r4, lr}`. Full-image A32
//! decoding finds **three plain, unconditional `bl` callers** at 0x0811252c,
//! 0x08112550, and 0x081f44a0, and no predicated `bl` callers. The body has
//! three unconditional direct `bl` instructions.
//!
//! # Algorithm
//!
//! Read the vtable-gated, state-scaled delay from `controller + 0x38`; read
//! the controller timestamp, convert it from microseconds to milliseconds,
//! and store that elapsed value. When elapsed exceeds the delay, clamp the
//! elapsed output to the delay and store zero remaining time; otherwise store
//! `delay - elapsed` as the remaining time.
//!
//! # Deliberate deviations
//!
//! The timestamp helper at 0x08111488 has no recovered identity, so it remains
//! a target-call seam. The already ported vtable-gated delay helper and ADS
//! unsigned divide are represented by target-call seams too, preserving the
//! observed call order without inventing additional callee semantics.

use core::ptr::{addr_of, read_volatile};

use crate::cxx::vtable_predicate_state_flag::VtablePredicateObject;
#[cfg(target_os = "none")]
use crate::cxx::vtable_predicate_state_scaled_value::vtable_predicate_state_scaled_value;
#[cfg(target_os = "none")]
use crate::runtime::rt_div::__rt_udiv;

const DELAY_OBJECT_OFFSET: usize = 0x38;
const MILLISECONDS_DIVISOR: u32 = 1000;
const RETAIL_TIMESTAMP: usize = 0x0811_1488;

pub type ControllerDelay = unsafe extern "C" fn(*mut VtablePredicateObject) -> u32;
pub type ControllerTimestamp = unsafe extern "C" fn(*mut u8) -> u32;
pub type UnsignedDivide = unsafe extern "C" fn(u32, u32) -> u32;

#[derive(Clone, Copy)]
pub struct ControllerClampedDelayOps {
    pub delay: ControllerDelay,
    pub timestamp: ControllerTimestamp,
    pub divide: UnsignedDivide,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_delay(object: *mut VtablePredicateObject) -> u32 {
    vtable_predicate_state_scaled_value(object)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_timestamp(controller: *mut u8) -> u32 {
    let timestamp: ControllerTimestamp = core::mem::transmute(RETAIL_TIMESTAMP);
    timestamp(controller)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_divide(value: u32, divisor: u32) -> u32 {
    __rt_udiv(value, divisor)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_delay(_: *mut VtablePredicateObject) -> u32 {
    panic!("install controller clamped delay host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_timestamp(_: *mut u8) -> u32 {
    panic!("install controller clamped delay host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_divide(_: u32, _: u32) -> u32 {
    panic!("install controller clamped delay host operations")
}

#[cfg(target_os = "none")]
pub const DEFAULT_CONTROLLER_CLAMPED_DELAY_OPS: ControllerClampedDelayOps = ControllerClampedDelayOps {
    delay: retail_delay,
    timestamp: retail_timestamp,
    divide: retail_divide,
};
#[cfg(not(target_os = "none"))]
pub const DEFAULT_CONTROLLER_CLAMPED_DELAY_OPS: ControllerClampedDelayOps = ControllerClampedDelayOps {
    delay: missing_delay,
    timestamp: missing_timestamp,
    divide: missing_divide,
};

pub static mut CONTROLLER_CLAMPED_DELAY_OPS: ControllerClampedDelayOps = DEFAULT_CONTROLLER_CLAMPED_DELAY_OPS;

#[inline(always)]
fn ops() -> ControllerClampedDelayOps {
    unsafe { read_volatile(addr_of!(CONTROLLER_CLAMPED_DELAY_OPS)) }
}

/// Stores the elapsed milliseconds, clamped to the controller delay, and its remainder.
///
/// # Safety
///
/// `controller` must contain a valid delay object at `+0x38`; both output pointers
/// must be writable. The stock routine performs no NULL, alias, or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_clamped_delay(
    controller: *mut u8,
    elapsed_out: *mut u32,
    remaining_out: *mut u32,
) {
    let operations = ops();
    let delay = (operations.delay)(controller.add(DELAY_OBJECT_OFFSET).cast());
    let elapsed = (operations.divide)((operations.timestamp)(controller), MILLISECONDS_DIVISOR);
    elapsed_out.write(elapsed);
    if elapsed < delay {
        remaining_out.write(delay - elapsed);
    } else {
        elapsed_out.write(delay);
        remaining_out.write(0);
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DELAY: u32 = 0;
    static mut TIMESTAMP: u32 = 0;
    static mut CALLS: [u32; 3] = [0; 3];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn delay(_: *mut VtablePredicateObject) -> u32 {
        CALLS[CALL_COUNT] = 1;
        CALL_COUNT += 1;
        DELAY
    }
    unsafe extern "C" fn timestamp(_: *mut u8) -> u32 {
        CALLS[CALL_COUNT] = 2;
        CALL_COUNT += 1;
        TIMESTAMP
    }
    unsafe extern "C" fn divide(value: u32, divisor: u32) -> u32 {
        CALLS[CALL_COUNT] = 3;
        CALL_COUNT += 1;
        assert_eq!(divisor, MILLISECONDS_DIVISOR);
        value / divisor
    }

    #[test]
    fn stores_elapsed_and_remaining_when_elapsed_is_below_delay() {
        let _guard = TEST_LOCK.lock();
        let saved = unsafe { CONTROLLER_CLAMPED_DELAY_OPS };
        unsafe {
            CONTROLLER_CLAMPED_DELAY_OPS = ControllerClampedDelayOps { delay, timestamp, divide };
            DELAY = 9;
            TIMESTAMP = 8_999;
            CALL_COUNT = 0;
            let mut controller = [0u8; DELAY_OBJECT_OFFSET + 16];
            let mut elapsed = u32::MAX;
            let mut remaining = u32::MAX;
            controller_clamped_delay(controller.as_mut_ptr(), &mut elapsed, &mut remaining);
            assert_eq!((elapsed, remaining), (8, 1));
            assert_eq!(CALLS[..CALL_COUNT], [1, 2, 3]);
            CONTROLLER_CLAMPED_DELAY_OPS = saved;
        }
    }

    #[test]
    fn clamps_elapsed_and_supports_aliased_outputs() {
        let _guard = TEST_LOCK.lock();
        let saved = unsafe { CONTROLLER_CLAMPED_DELAY_OPS };
        unsafe {
            CONTROLLER_CLAMPED_DELAY_OPS = ControllerClampedDelayOps { delay, timestamp, divide };
            DELAY = 9;
            TIMESTAMP = 10_000;
            CALL_COUNT = 0;
            let mut controller = [0u8; DELAY_OBJECT_OFFSET + 16];
            let mut output = u32::MAX;
            controller_clamped_delay(controller.as_mut_ptr(), &mut output, &mut output);
            assert_eq!(output, 0, "remaining store follows the clamped elapsed store");
            assert_eq!(CALLS[..CALL_COUNT], [1, 2, 3]);
            CONTROLLER_CLAMPED_DELAY_OPS = saved;
        }
    }
}
