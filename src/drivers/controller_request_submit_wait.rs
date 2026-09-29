//! Submit a controller request and wait for completion.
//!
//! Original: `FUN_0836daa8` @ `0x0836daa8`, 128 bytes. Raw `osos.dec`
//! establishes the exact extent `0x0836daa8..0x0836db27`: the following
//! eight bytes are the `0x3c20_0000` controller base and `1500`-tick timeout
//! literals, and the next real function starts at `0x0836db30`. A complete
//! A32 branch decode finds two inbound direct calls: plain `bl` at
//! `0x0836d910` and predicated `blne` at `0x0836da74`. The body has three
//! plain outbound `bl` calls and no predicated calls.
//!
//! The controller identity is unrecovered, so this name records only the
//! verified operation. It clears control bit 21, delays one millisecond,
//! restores that bit, writes `request >> 1 | 0x8000_0000` at word 7, and sets
//! command bit 0 at word 1. It then polls status word 3 bit 3 until it clears
//! or 1500 microseconds elapse.
//!
//! Deliberate deviation: host builds use private controller-register storage
//! instead of the target MMIO base `0x3c20_0000`; timing still goes through
//! the existing Timer E ports.

use crate::drivers::timer::{
    iram_msec_delay_veneer, iram_usec_timer_elapsed_veneer, iram_usec_timer_read_veneer,
};

const CONTROLLER_BASE: usize = 0x3c20_0000;
const CONTROL_ENABLE: u32 = 0x0020_0000;
const COMMAND_START: u32 = 1;
const STATUS_PENDING: u32 = 8;
const REQUEST_WORD: usize = 7;
const TIMEOUT_USEC: u32 = 1_500;

#[cfg(not(target_os = "none"))]
static mut HOST_CONTROLLER_WORDS: [u32; 8] = [0; 8];

#[inline(always)]
unsafe fn controller_words() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        CONTROLLER_BASE as *mut u32
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_CONTROLLER_WORDS).cast()
    }
}

unsafe fn submit_request_and_wait(
    controller: *mut u32,
    request: u32,
    delay_msec: unsafe fn(u32) -> u32,
    read_usec: unsafe fn() -> u32,
    elapsed_usec: unsafe fn(u32, u32) -> bool,
) {
    unsafe {
        controller.write_volatile(controller.read_volatile() & !CONTROL_ENABLE);
        delay_msec(1);
        controller.write_volatile(controller.read_volatile() | CONTROL_ENABLE);
        controller.add(REQUEST_WORD).write_volatile((request >> 1) | 0x8000_0000);
        controller.add(1).write_volatile(controller.add(1).read_volatile() | COMMAND_START);

        let start = read_usec();
        while controller.add(3).read_volatile() & STATUS_PENDING != 0 {
            if elapsed_usec(start, TIMEOUT_USEC) {
                return;
            }
        }
    }
}

unsafe fn delay_msec(milliseconds: u32) -> u32 {
    unsafe { iram_msec_delay_veneer(milliseconds) }
}

unsafe fn read_usec() -> u32 {
    unsafe { iram_usec_timer_read_veneer() }
}

unsafe fn elapsed_usec(start: u32, interval: u32) -> bool {
    unsafe { iram_usec_timer_elapsed_veneer(start, interval) }
}

/// controller_request_submit_wait — `FUN_0836daa8` @ `0x0836daa8` (128
/// bytes; one plain and one predicated inbound direct `bl` call site).
///
/// Submits `request` to the controller after its one-millisecond settle
/// delay, then returns after status bit 3 clears or 1500 microseconds expire.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_request_submit_wait(request: u32) {
    unsafe {
        submit_request_and_wait(
            controller_words(),
            request,
            delay_msec,
            read_usec,
            elapsed_usec,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static CONTROLLER_WORDS_LOCK: Mutex<()> = Mutex::new(());

    fn expected_request(request: u32) -> u32 {
        (request >> 1) | 0x8000_0000
    }

    unsafe fn mock_delay_msec(milliseconds: u32) -> u32 {
        assert_eq!(milliseconds, 1);
        0
    }

    unsafe fn mock_read_usec() -> u32 {
        0x1234_5678
    }

    unsafe fn mock_elapsed_usec(start: u32, interval: u32) -> bool {
        assert_eq!(start, 0x1234_5678);
        assert_eq!(interval, TIMEOUT_USEC);
        true
    }

    #[test]
    fn submits_request_and_preserves_unrelated_control_bits() {
        let _lock = CONTROLLER_WORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let words = ptr::addr_of_mut!(HOST_CONTROLLER_WORDS);
            words.write([0x8040_0001, 0x20, 0, 0, 0, 0, 0, 0]);
            submit_request_and_wait(
                words.cast(),
                0xffff_fffe,
                mock_delay_msec,
                mock_read_usec,
                mock_elapsed_usec,
            );
            let result = words.read();
            assert_eq!(result[0], 0x8060_0001);
            assert_eq!(result[1], 0x21);
            assert_eq!(result[REQUEST_WORD], expected_request(0xffff_fffe));
        }
    }

    #[test]
    fn shifts_odd_request_and_times_out_with_pending_status() {
        let _lock = CONTROLLER_WORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let words = ptr::addr_of_mut!(HOST_CONTROLLER_WORDS);
            words.write([CONTROL_ENABLE, 0, 0, STATUS_PENDING, 0, 0, 0, 0]);
            submit_request_and_wait(words.cast(), 3, mock_delay_msec, mock_read_usec, mock_elapsed_usec);
            let result = words.read();
            assert_eq!(result[0] & CONTROL_ENABLE, CONTROL_ENABLE);
            assert_eq!(result[1] & COMMAND_START, COMMAND_START);
            assert_eq!(result[REQUEST_WORD], expected_request(3));
            assert_eq!(result[3], STATUS_PENDING);
        }
    }
}
