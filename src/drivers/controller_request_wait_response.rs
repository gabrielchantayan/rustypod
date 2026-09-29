//! Submit a controller request and wait for its response.
//!
//! Original: `FUN_0836d8e4` @ `0x0836d8e4`, 144 bytes. Raw `osos.dec`
//! establishes the true extent `0x0836d8e4..0x0836d974`: 35 instruction
//! words through `pop {r4-r10,pc}`, followed by its `0x3c20_0000` literal;
//! `push {r4-r8,lr}` at `0x0836d974` begins the next real function. Complete
//! A32 decoding finds four plain outbound `bl` calls and no predicated calls.
//!
//! Takes and clears the pending-state word, marks controller word 5 as waiting,
//! submits `request`, then polls the 2000-microsecond deadline. While word 5
//! bit 0 is set, it checks controller status word 3 bit 0 and refreshes word 5
//! if no response is ready. If status word 3 bit 0 is set it returns response
//! word 6; it always restores word 5 to 1 and writes the saved pending state to
//! word 4. Deliberate deviation: the host reuses the existing controller MMIO
//! storage seam; the result and polling order are otherwise unchanged.

use crate::drivers::controller_request_submit_wait::{
    controller_request_submit_wait, controller_words,
};
use crate::drivers::timer::{iram_usec_timer_elapsed_veneer, iram_usec_timer_read_veneer};
use crate::kernel::pending_state_take::pending_state_take;

const STATUS_RESPONSE_READY: u32 = 1;
const WAITING: u32 = 1;
const RESPONSE_TIMEOUT_USEC: u32 = 2_000;
const PENDING_STATE_WORD: usize = 4;
const WAITING_WORD: usize = 5;
const RESPONSE_WORD: usize = 6;
const STATUS_WORD: usize = 3;

type SubmitRequest = unsafe fn(u32);
type ReadUsec = unsafe fn() -> u32;
type ElapsedUsec = unsafe fn(u32, u32) -> bool;

unsafe fn submit_and_wait_response(
    controller: *mut u32,
    pending_state: u32,
    request: u32,
    submit_request: SubmitRequest,
    read_usec: ReadUsec,
    elapsed_usec: ElapsedUsec,
) -> u32 {
    unsafe {
        controller.add(WAITING_WORD).write_volatile(WAITING);
        controller.add(WAITING_WORD).write_volatile(WAITING);
        submit_request(request);
        let start = read_usec();
        loop {
            if controller.add(WAITING_WORD).read_volatile() & WAITING != 0 {
                if controller.add(STATUS_WORD).read_volatile() & STATUS_RESPONSE_READY != 0 {
                    break;
                }
                controller.add(WAITING_WORD).write_volatile(WAITING);
            }
            if elapsed_usec(start, RESPONSE_TIMEOUT_USEC) {
                break;
            }
        }

        let response = if controller.add(STATUS_WORD).read_volatile() & STATUS_RESPONSE_READY != 0 {
            controller.add(RESPONSE_WORD).read_volatile()
        } else {
            0
        };
        controller.add(WAITING_WORD).write_volatile(WAITING);
        controller.add(PENDING_STATE_WORD).write_volatile(pending_state);
        response
    }
}

unsafe fn submit_request(request: u32) {
    unsafe { controller_request_submit_wait(request) }
}

unsafe fn read_usec() -> u32 {
    unsafe { iram_usec_timer_read_veneer() }
}

unsafe fn elapsed_usec(start: u32, interval: u32) -> bool {
    unsafe { iram_usec_timer_elapsed_veneer(start, interval) }
}

/// controller_request_wait_response — `FUN_0836d8e4` @ `0x0836d8e4` (144
/// bytes including literal pool; four plain and zero predicated outbound `bl`
/// calls).
///
/// Returns the response word when controller status bit 0 becomes set before
/// the 2000-microsecond deadline; otherwise returns zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_request_wait_response(request: u32) -> u32 {
    unsafe {
        submit_and_wait_response(
            controller_words(),
            pending_state_take(),
            request,
            submit_request,
            read_usec,
            elapsed_usec,
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    unsafe fn submit_response_ready(_request: u32) {}

    unsafe fn read_start() -> u32 {
        0x1234_5678
    }

    unsafe fn elapsed_never(_start: u32, _interval: u32) -> bool {
        false
    }

    unsafe fn elapsed_immediately(start: u32, interval: u32) -> bool {
        assert_eq!(start, 0x1234_5678);
        assert_eq!(interval, RESPONSE_TIMEOUT_USEC);
        true
    }

    #[test]
    fn returns_ready_response_and_restores_controller_words() {
        let mut controller = [0; 8];
        controller[STATUS_WORD] = STATUS_RESPONSE_READY;
        controller[RESPONSE_WORD] = 0xdead_beef;
        controller[WAITING_WORD] = WAITING;
        unsafe {
            assert_eq!(
                submit_and_wait_response(
                    controller.as_mut_ptr(),
                    0x1122_3344,
                    7,
                    submit_response_ready,
                    read_start,
                    elapsed_never,
                ),
                0xdead_beef
            );
        }
        assert_eq!(controller[WAITING_WORD], WAITING);
        assert_eq!(controller[PENDING_STATE_WORD], 0x1122_3344);
    }

    #[test]
    fn returns_zero_when_deadline_expires_without_response() {
        let mut controller = [0; 8];
        unsafe {
            assert_eq!(
                submit_and_wait_response(
                    controller.as_mut_ptr(),
                    0xa5a5_5a5a,
                    9,
                    submit_response_ready,
                    read_start,
                    elapsed_immediately,
                ),
                0
            );
        }
        assert_eq!(controller[WAITING_WORD], WAITING);
        assert_eq!(controller[PENDING_STATE_WORD], 0xa5a5_5a5a);
    }
}
