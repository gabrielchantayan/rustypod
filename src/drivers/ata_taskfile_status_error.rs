//! ATA task-file status/error decoder — `FUN_080c4950` @ `0x080c4950`.
//!
//! Raw `osos.dec` establishes a **208-byte** extent,
//! `0x080c4950..0x080c4a20`; the following bytes are the first inline
//! diagnostic string, not code. Decoding every ARM B/BL word finds **seven
//! plain `bl` instructions** and zero predicated forms: four to
//! `ata_taskfile_register_read`, two to `iram_usec_delay_veneer`, and one to
//! `debug_printf` (three unique callee addresses).
//!
//! # Algorithm
//!
//! Read ATA task-file register 15, retrying once after 1000 microseconds on
//! submission failure. A clear ready bit returns success immediately. Then
//! read register 9 with the same retry policy, report its low byte, and map
//! error bits in priority order to retailOS status codes: bit 0 -> 0x4c, bit
//! 6 -> 0x4f, bit 1 -> 0x4d, bits 2 or 5 -> 0x4e, otherwise 0x51. Either
//! exhausted read retry reports its respective diagnostic and returns 0x59.
//!
//! # Deliberate deviations
//!
//! Host builds replace diagnostics with a volatile seam so tests can observe
//! their format and argument. Target builds call `debug_printf` directly;
//! retry diagnostics have no conversions, and the status diagnostic receives
//! a one-word argument list equivalent to the ARM register-save area.

#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::drivers::ata_taskfile_register_read::ata_taskfile_register_read;
use crate::drivers::timer::iram_usec_delay_veneer;
#[cfg(target_os = "none")]
use crate::stdio::debug_printf::debug_printf;

const ATA_READY_REGISTER: u32 = 15;
const ATA_ERROR_REGISTER: u32 = 9;
const RETRY_DELAY_USEC: u32 = 1_000;
const READY_READ_FAILURE_FORMAT: *const u8 = 0x080c_4a20 as *const u8;
const ERROR_READ_FAILURE_FORMAT: *const u8 = 0x080c_4a54 as *const u8;
const ERROR_VALUE_FORMAT: *const u8 = 0x080c_4a88 as *const u8;

pub type AtaTaskfileStatusReport = unsafe extern "C" fn(*const u8, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn ignore_ata_taskfile_status_report(_format: *const u8, _value: u32) {}

#[cfg(not(target_os = "none"))]
pub static mut ATA_TASKFILE_STATUS_ERROR_REPORT: AtaTaskfileStatusReport =
    ignore_ata_taskfile_status_report;

#[inline(always)]
unsafe fn report(format: *const u8, value: u32) {
    #[cfg(target_os = "none")]
    {
        let args = [value];
        debug_printf(format, args.as_ptr());
    }
    #[cfg(not(target_os = "none"))]
    {
        let reporter = ptr::read_volatile(ptr::addr_of!(ATA_TASKFILE_STATUS_ERROR_REPORT));
        reporter(format, value);
    }
}

#[inline(always)]
unsafe fn read_register_with_retry(register: u32) -> Option<u32> {
    let mut value = 0u32;
    if ata_taskfile_register_read(register, &mut value) != 0 {
        return Some(value);
    }
    iram_usec_delay_veneer(RETRY_DELAY_USEC);
    if ata_taskfile_register_read(register, &mut value) != 0 {
        Some(value)
    } else {
        None
    }
}

/// ata_taskfile_status_error — original: `FUN_080c4950` @ `0x080c4950`
/// (208 bytes through the first inline diagnostic at `0x080c4a20`).
///
/// Seven unconditional direct `bl` instructions and no predicated calls,
/// verified from raw ARM words. Reads ready then error task-file status with
/// one 1000-us retry per failed read; maps the error word's bits in the exact
/// retail priority order. Host diagnostics are observable through a volatile
/// seam; target diagnostics use the stock format addresses and argument list.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_taskfile_status_error")]
#[inline(never)]
pub unsafe extern "C" fn ata_taskfile_status_error() -> u32 {
    let ready = match read_register_with_retry(ATA_READY_REGISTER) {
        Some(value) => value,
        None => {
            report(READY_READ_FAILURE_FORMAT, 0);
            return 0x59;
        }
    };
    if ready & 1 == 0 {
        return 0;
    }

    let error = match read_register_with_retry(ATA_ERROR_REGISTER) {
        Some(value) => value,
        None => {
            report(ERROR_READ_FAILURE_FORMAT, 0);
            return 0x59;
        }
    };
    report(ERROR_VALUE_FORMAT, error & 0xff);
    if error & 1 != 0 {
        0x4c
    } else if error & 0x40 != 0 {
        0x4f
    } else if error & 2 != 0 {
        0x4d
    } else if error & 0x24 != 0 {
        0x4e
    } else {
        0x51
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_taskfile_register_read::{
        AtaTaskfileRegisterReadOps, ATA_TASKFILE_REGISTER_READ_CONTEXT,
        ATA_TASKFILE_REGISTER_READ_OPS, ATA_TASKFILE_REGISTER_READ_TEST_LOCK,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};

    static mut SUBMIT_RESULTS: [u32; 4] = [0; 4];
    static mut REGISTER_VALUES: [u32; 4] = [0; 4];
    static mut SUBMIT_COUNT: usize = 0;
    static REPORT_FORMAT: AtomicUsize = AtomicUsize::new(0);
    static REPORT_VALUE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn scripted_submit(
        _command: u32,
        _selector: u32,
        result: *mut u32,
        _timeout: u32,
    ) -> u32 {
        let index = SUBMIT_COUNT;
        SUBMIT_COUNT += 1;

        if !result.is_null() {
            result.write(REGISTER_VALUES[index]);
        }
        SUBMIT_RESULTS[index]
    }
    unsafe extern "C" fn ignore_taskfile_read_failure(_format: *const u8) {}

    unsafe extern "C" fn record_report(format: *const u8, value: u32) {
        REPORT_FORMAT.store(format as usize, Ordering::Relaxed);
        REPORT_VALUE.store(value as usize, Ordering::Relaxed);
    }

    struct Reset {
        taskfile_ops: AtaTaskfileRegisterReadOps,
        report: AtaTaskfileStatusReport,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_OPS), self.taskfile_ops);
                ptr::write_volatile(ptr::addr_of_mut!(ATA_TASKFILE_STATUS_ERROR_REPORT), self.report);
                ptr::write_volatile(ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_CONTEXT), [0; 6]);
                SUBMIT_RESULTS = [0; 4];
                REGISTER_VALUES = [0; 4];
                SUBMIT_COUNT = 0;
            }
            REPORT_FORMAT.store(0, Ordering::Relaxed);
            REPORT_VALUE.store(0, Ordering::Relaxed);
        }
    }

    unsafe fn install(submit_results: [u32; 4], register_values: [u32; 4]) -> Reset {
        let taskfile_ops = ptr::read_volatile(ptr::addr_of!(ATA_TASKFILE_REGISTER_READ_OPS));
        let report = ptr::read_volatile(ptr::addr_of!(ATA_TASKFILE_STATUS_ERROR_REPORT));
        ptr::write_volatile(
            ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_OPS),
            AtaTaskfileRegisterReadOps {
                submit: scripted_submit,
                report_failure: ignore_taskfile_read_failure,
            },
        );
        ptr::write_volatile(ptr::addr_of_mut!(ATA_TASKFILE_STATUS_ERROR_REPORT), record_report);
        ptr::write_volatile(ptr::addr_of_mut!(ATA_TASKFILE_REGISTER_READ_CONTEXT), [0; 6]);
        SUBMIT_RESULTS = submit_results;
        REGISTER_VALUES = register_values;
        Reset { taskfile_ops, report }
    }

    #[test]
    fn ready_clear_returns_success_without_reading_error_register() {
        let _lock = ATA_TASKFILE_REGISTER_READ_TEST_LOCK.lock();
        let _reset = unsafe { install([1, 0, 0, 0], [0, 0, 0, 0]) };

        assert_eq!(unsafe { ata_taskfile_status_error() }, 0);
        assert_eq!(unsafe { SUBMIT_COUNT }, 1);
        assert_eq!(REPORT_FORMAT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn error_bits_follow_retail_priority_after_a_ready_retry() {
        let _lock = ATA_TASKFILE_REGISTER_READ_TEST_LOCK.lock();
        let _timer = crate::drivers::timer::configure_usec_timer_for_test(0, RETRY_DELAY_USEC);
        let _reset = unsafe { install([0, 1, 1, 0], [0, 1, 0x67, 0]) };

        assert_eq!(unsafe { ata_taskfile_status_error() }, 0x4c);
        assert_eq!(unsafe { SUBMIT_COUNT }, 3);
        assert_eq!(REPORT_FORMAT.load(Ordering::Relaxed), ERROR_VALUE_FORMAT as usize);
        assert_eq!(REPORT_VALUE.load(Ordering::Relaxed), 0x67);
    }

    #[test]
    fn exhausted_error_read_retry_reports_its_specific_failure() {
        let _lock = ATA_TASKFILE_REGISTER_READ_TEST_LOCK.lock();
        let _timer = crate::drivers::timer::configure_usec_timer_for_test(0, RETRY_DELAY_USEC);
        let _reset = unsafe { install([1, 0, 0, 0], [1, 0, 0, 0]) };

        assert_eq!(unsafe { ata_taskfile_status_error() }, 0x59);
        assert_eq!(unsafe { SUBMIT_COUNT }, 3);
        assert_eq!(REPORT_FORMAT.load(Ordering::Relaxed), ERROR_READ_FAILURE_FORMAT as usize);
    }
}
