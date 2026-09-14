//! `ata_stop_transmission` — original: `FUN_08098ddc` @ `0x08098ddc`.
//!
//! Ghidra reports 120 bytes. Raw `osos.dec` has 120 instruction bytes at
//! `0x08098ddc..0x08098e50`, followed by the two literal-pool words at
//! `0x08098e54` and `0x08098e58`; the separately linked next function starts
//! at `0x08098e5c`. Decoding every immediate ARM branch in the image finds
//! exactly six inbound direct calls, all unconditional `bl` (no predicated
//! calls): `0x080dbc54`, `0x080dbc8c`, `0x0836a44c`, `0x0836a480`,
//! `0x0836aadc`, and `0x0836ab1c`. There are no aligned raw data-word
//! references to the entry.
//!
//! # Algorithm
//!
//! Drive GPIO pin 72 low, wait one microsecond, drive it high, wait one
//! microsecond, return it to function 3, then wait one microsecond. Submit
//! command `0x0009_008c` with zero flags and result pointer, using the timeout
//! word at `0x089d03bc + 0x14`. A failed submission returns zero. A successful
//! submission tail-dispatches the ATA-ready wait using a zero status word and
//! the same timeout; its result becomes this function's result. The only two
//! unported callees are the transaction worker `FUN_08077490` and ready waiter
//! `FUN_080cdf5c`, reached through literal target veneers; host tests use
//! volatile callback seams for those calls. GPIO configuration and the delay
//! veneer are already-ported direct calls. Deliberate deviations: none.

use core::ptr;

use crate::drivers::gpio_cmd::gpio_pin_configure;
use crate::drivers::timer::iram_usec_delay_veneer;

const ATA_STOP_TRANSMISSION_COMMAND: u32 = 0x0009_008c;
const ATA_RESET_GPIO_PIN: u32 = 72;
const ATA_RESET_GPIO_FUNCTION: u32 = 3;
const ATA_CONTEXT_TIMEOUT_WORD: usize = 5;

pub type AtaStopTransmissionSubmit = unsafe extern "C" fn(u32, u32, *mut u32, u32) -> u32;
pub type AtaReadyWait = unsafe extern "C" fn(u32, u32, u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ata_stop_transmission_submit(
    _command: u32,
    _flags: u32,
    _result: *mut u32,
    _timeout: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ata_ready_wait(
    _status: u32,
    _unused: u32,
    _error: u32,
    _timeout: u32,
) -> u32 {
    0
}

/// Host-only seams for the two still-unported ATA calls.
#[cfg(not(target_arch = "arm"))]
#[derive(Clone, Copy)]
pub struct AtaStopTransmissionOps {
    pub submit: AtaStopTransmissionSubmit,
    pub wait_ready: AtaReadyWait,
}

#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_ATA_STOP_TRANSMISSION_OPS: AtaStopTransmissionOps = AtaStopTransmissionOps {
    submit: missing_ata_stop_transmission_submit,
    wait_ready: missing_ata_ready_wait,
};

#[cfg(not(target_arch = "arm"))]
pub static mut ATA_STOP_TRANSMISSION_OPS: AtaStopTransmissionOps =
    DEFAULT_ATA_STOP_TRANSMISSION_OPS;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_ata_stop_transmission_submit(
        command: u32,
        flags: u32,
        result: *mut u32,
        timeout: u32,
    ) -> u32;
    fn retail_ata_ready_wait(status: u32, unused: u32, error: u32, timeout: u32) -> u32;
}

// The original's PC-relative calls cannot reach from the patch payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_ata_stop_transmission_submit
    .type retail_ata_stop_transmission_submit, %function
retail_ata_stop_transmission_submit:
    ldr     pc, [pc, #-4]
    .word   0x08077490
    .size retail_ata_stop_transmission_submit, . - retail_ata_stop_transmission_submit

    .p2align 2
    .globl retail_ata_ready_wait
    .type retail_ata_ready_wait, %function
retail_ata_ready_wait:
    ldr     pc, [pc, #-4]
    .word   0x080cdf5c
    .size retail_ata_ready_wait, . - retail_ata_ready_wait
"#
);

#[inline(always)]
unsafe fn ata_context_timeout() -> u32 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile((0x089d_03bc as *const u32).add(ATA_CONTEXT_TIMEOUT_WORD))
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(
            ptr::addr_of!(crate::drivers::ata_taskfile_register_read::ATA_TASKFILE_REGISTER_READ_CONTEXT)
                .cast::<u32>()
                .add(ATA_CONTEXT_TIMEOUT_WORD),
        )
    }
}

#[inline(always)]
unsafe fn submit_stop_transmission(timeout: u32) -> u32 {
    #[cfg(target_arch = "arm")]
    {
        retail_ata_stop_transmission_submit(ATA_STOP_TRANSMISSION_COMMAND, 0, ptr::null_mut(), timeout)
    }
    #[cfg(not(target_arch = "arm"))]
    {
        let submit = ptr::read_volatile(ptr::addr_of!(ATA_STOP_TRANSMISSION_OPS.submit));
        submit(ATA_STOP_TRANSMISSION_COMMAND, 0, ptr::null_mut(), timeout)
    }
}

#[inline(always)]
unsafe fn wait_for_ata_ready(timeout: u32) -> u32 {
    #[cfg(target_arch = "arm")]
    {
        retail_ata_ready_wait(0, 0, 0, timeout)
    }
    #[cfg(not(target_arch = "arm"))]
    {
        let wait_ready = ptr::read_volatile(ptr::addr_of!(ATA_STOP_TRANSMISSION_OPS.wait_ready));
        wait_ready(0, 0, 0, timeout)
    }
}

/// ata_stop_transmission — original: `FUN_08098ddc` @ `0x08098ddc`
/// (120 instruction bytes plus an 8-byte literal pool).
///
/// Six unconditional direct `bl` call sites, verified from every ARM branch
/// immediate in `osos.dec`. Pulses GPIO 72 low/high, restores function 3, and
/// waits one microsecond after each configuration. It submits command
/// `0x0009_008c` with zero flags/result pointer and the global `+0x14`
/// timeout; a zero submission returns zero, otherwise the ATA-ready wait's
/// result is returned.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_stop_transmission")]
#[inline(never)]
pub unsafe extern "C" fn ata_stop_transmission() -> u32 {
    gpio_pin_configure(ATA_RESET_GPIO_PIN, 1, 0);
    iram_usec_delay_veneer(1);
    gpio_pin_configure(ATA_RESET_GPIO_PIN, 1, 1);
    iram_usec_delay_veneer(1);
    gpio_pin_configure(ATA_RESET_GPIO_PIN, ATA_RESET_GPIO_FUNCTION, 0);
    iram_usec_delay_veneer(1);

    let timeout = ata_context_timeout();
    if submit_stop_transmission(timeout) == 0 {
        0
    } else {
        wait_for_ata_ready(timeout)
    }
}

#[cfg(test)]
pub(crate) static ATA_STOP_TRANSMISSION_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::drivers::ata_taskfile_register_read::{
        ATA_TASKFILE_REGISTER_READ_CONTEXT, ATA_TASKFILE_REGISTER_READ_TEST_LOCK,
    };
    use crate::drivers::gpio_cmd::host_gpiocmd;

    static mut SUBMIT_RESULT: u32 = 0;
    static mut READY_WAIT_RESULT: u32 = 0;
    static mut SUBMIT_CALLS: usize = 0;
    static mut READY_WAIT_CALLS: usize = 0;
    static mut SUBMIT_ARGS: (u32, u32, usize, u32) = (0, 0, 0, 0);
    static mut READY_WAIT_ARGS: (u32, u32, u32, u32) = (0, 0, 0, 0);

    unsafe extern "C" fn record_submit(command: u32, flags: u32, result: *mut u32, timeout: u32) -> u32 {
        SUBMIT_CALLS += 1;
        SUBMIT_ARGS = (command, flags, result as usize, timeout);
        SUBMIT_RESULT
    }

    unsafe extern "C" fn record_ready_wait(status: u32, unused: u32, error: u32, timeout: u32) -> u32 {
        READY_WAIT_CALLS += 1;
        READY_WAIT_ARGS = (status, unused, error, timeout);
        READY_WAIT_RESULT
    }

    unsafe fn configure_fixture(timeout: u32, submit_result: u32, ready_wait_result: u32) {
        SUBMIT_RESULT = submit_result;
        READY_WAIT_RESULT = ready_wait_result;
        SUBMIT_CALLS = 0;
        READY_WAIT_CALLS = 0;
        SUBMIT_ARGS = (0, 0, 0, 0);
        READY_WAIT_ARGS = (0, 0, 0, 0);
        ATA_STOP_TRANSMISSION_OPS = AtaStopTransmissionOps {
            submit: record_submit,
            wait_ready: record_ready_wait,
        };
        ptr::write_volatile(
            ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_CONTEXT).cast::<u32>().add(ATA_CONTEXT_TIMEOUT_WORD),
            timeout,
        );
    }

    #[test]
    fn failed_submission_returns_zero_without_waiting_for_ready() {
        let _ops_guard = ATA_STOP_TRANSMISSION_TEST_LOCK.lock();
        let _context_guard = ATA_TASKFILE_REGISTER_READ_TEST_LOCK.lock();
        let _timer_guard = crate::drivers::timer::configure_usec_timer_for_test(0, 1);
        let gpio_writes = unsafe { host_gpiocmd::WRITE_COUNT };

        unsafe {
            configure_fixture(0x1234_5678, 0, 0xfeed_face);
            assert_eq!(ata_stop_transmission(), 0);
            assert_eq!(SUBMIT_CALLS, 1);
            assert_eq!(SUBMIT_ARGS, (ATA_STOP_TRANSMISSION_COMMAND, 0, 0, 0x1234_5678));
            assert_eq!(READY_WAIT_CALLS, 0);
            assert_eq!(host_gpiocmd::WRITE_COUNT, gpio_writes + 3);
            assert_eq!(host_gpiocmd::LAST_COMMAND, 0x0009_0003);
            ATA_STOP_TRANSMISSION_OPS = DEFAULT_ATA_STOP_TRANSMISSION_OPS;
        }
    }

    #[test]
    fn successful_submission_returns_ready_wait_result_with_zero_status_words() {
        let _ops_guard = ATA_STOP_TRANSMISSION_TEST_LOCK.lock();
        let _context_guard = ATA_TASKFILE_REGISTER_READ_TEST_LOCK.lock();
        let _timer_guard = crate::drivers::timer::configure_usec_timer_for_test(u32::MAX - 1, 1);

        unsafe {
            configure_fixture(0xffff_ffff, 7, 0xa5a5_5a5a);
            assert_eq!(ata_stop_transmission(), 0xa5a5_5a5a);
            assert_eq!(SUBMIT_CALLS, 1);
            assert_eq!(SUBMIT_ARGS, (ATA_STOP_TRANSMISSION_COMMAND, 0, 0, u32::MAX));
            assert_eq!(READY_WAIT_CALLS, 1);
            assert_eq!(READY_WAIT_ARGS, (0, 0, 0, u32::MAX));
            ATA_STOP_TRANSMISSION_OPS = DEFAULT_ATA_STOP_TRANSMISSION_OPS;
        }
    }
}
