//! Conditional storage-object reset — `FUN_080f9db0` @ `0x080f9db0`.
//!
//! True extent: 44 bytes, `0x080f9db0..0x080f9ddc` (exclusive); the next
//! function is the branch veneer at `0x080f9ddc`. Whole-image A32 decoding
//! finds two incoming plain BLs and zero predicated BLs. The body has three
//! plain BLs, zero predicated BLs, and a tail B to `system_reset`.
//!
//! Read the object's request byte at +0x45d. Zero returns without side effects;
//! any nonzero value posts gateway tag 4, requests PMU powerdown with zero,
//! waits 10 milliseconds, and requests system reset without returning.
//! PMU and delay status values are deliberately ignored, as in retailOS.
//! Deliberate deviations: a volatile byte read preserves the external state
//! observation; existing Rust ports replace all four verified retail targets.

use core::ptr;
use crate::drivers::pmu_powerdown_if_ready::pmu_powerdown_if_ready;
use crate::drivers::system_reset::system_reset;
use crate::drivers::timer::iram_msec_delay_veneer;
use crate::kernel::gateway_request::gateway_request_empty_tag4;

const RESET_REQUEST_OFFSET: usize = 0x45d;

#[inline(always)]
unsafe fn reset_if_requested(
    object: *const u8,
    gateway: impl FnOnce(),
    powerdown: impl FnOnce(u32) -> u32,
    delay: impl FnOnce(u32) -> u32,
    reset: impl FnOnce(),
) {
    if unsafe { ptr::read_volatile(object.add(RESET_REQUEST_OFFSET)) } == 0 {
        return;
    }
    gateway();
    let _ = powerdown(0);
    let _ = delay(10);
    reset();
}

/// # Safety
/// `object` must be readable through byte +0x45d. The retail gateway, PMU,
/// timer, and reset hardware state must be initialized and accessible.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn storage_reset_if_requested(object: *const u8) {
    unsafe {
        reset_if_requested(
            object,
            || gateway_request_empty_tag4(),
            |value| pmu_powerdown_if_ready(value),
            |milliseconds| iram_msec_delay_veneer(milliseconds),
            || system_reset(),
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn zero_request_ignores_nonzero_neighbors() {
        let mut object = [0xff; RESET_REQUEST_OFFSET + 2];
        object[RESET_REQUEST_OFFSET] = 0;
        unsafe {
            reset_if_requested(object.as_ptr(), || panic!("gateway"),
                |_| panic!("powerdown"), |_| panic!("delay"), || panic!("reset"));
        }
        assert_eq!(object[RESET_REQUEST_OFFSET - 1..], [0xff, 0, 0xff]);
    }

    #[test]
    fn every_nonzero_request_resets_even_when_powerdown_is_unavailable() {
        for request in 1..=u8::MAX {
            let mut object = [0; RESET_REQUEST_OFFSET + 1];
            object[RESET_REQUEST_OFFSET] = request;
            let events = RefCell::new(std::vec::Vec::new());
            unsafe {
                reset_if_requested(object.as_ptr(),
                    || events.borrow_mut().push(("gateway", 4)),
                    |value| { events.borrow_mut().push(("powerdown", value)); 11 },
                    |milliseconds| { events.borrow_mut().push(("delay", milliseconds)); 9 },
                    || events.borrow_mut().push(("reset", 0)));
            }
            assert_eq!(*events.borrow(), [("gateway", 4), ("powerdown", 0),
                ("delay", 10), ("reset", 0)]);
            assert_eq!(object[RESET_REQUEST_OFFSET], request);
        }
    }
}
