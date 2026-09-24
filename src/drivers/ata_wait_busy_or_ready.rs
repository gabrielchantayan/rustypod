//! ATA BUSY/ready status wait — `FUN_080cdf5c` @ `0x080cdf5c`.
//!
//! Raw `osos.dec` establishes a **156-byte** executable extent at
//! `0x080cdf5c..0x080cdff7`; the literal word at `0x080cdff8` and inline
//! diagnostic strings follow it. The next real function starts after those
//! data objects. Decoding its ARM words finds seven plain unconditional `bl`
//! instructions and zero predicated `bl` instructions (the five target
//! addresses include two repeated calls each to task-file reading and tracing).
//!
//! # Algorithm
//!
//! Capture the microsecond timer, then poll ATA status register 15. A failed
//! read returns zero. On error bit zero, read error register 9, report its low
//! byte, and continue unless that read failed. If the elapsed interval reaches
//! the controller context's `+0x18` word, report the timeout and return zero.
//! Otherwise sleep 50 ticks and retry while status has BUSY (`0x80`) or DRQ
//! (`0x08`) set; a settled status returns one. Deliberate deviation: host builds
//! use replaceable call seams for the fixed-address/runtime services.

use core::ptr;

const ATA_STATUS_REGISTER: u32 = 15;
const ATA_ERROR_REGISTER: u32 = 9;
const ATA_BUSY_OR_DRQ: u32 = 0x88;
const ATA_ERROR: u32 = 1;
const POLL_SLEEP_TICKS: u32 = 50;
const CONTEXT_WAIT_INTERVAL_WORD: usize = 6;
const ATA_ERROR_READ_FAILURE_FORMAT: *const u8 = 0x080c_dffc as *const u8;
const ATA_ERROR_FORMAT: *const u8 = 0x080c_e030 as *const u8;
const ATA_TIMEOUT_FORMAT: *const u8 = 0x080c_e060 as *const u8;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct AtaWaitBusyOrReadyOps {
    pub read_register: unsafe extern "C" fn(u32, *mut u32) -> u32,
    pub timer_read: unsafe extern "C" fn() -> u32,
    pub timer_elapsed: unsafe extern "C" fn(u32, u32) -> bool,
    pub sleep: unsafe extern "C" fn(u32),
    pub report: unsafe extern "C" fn(*const u8, u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read_register(_register: u32, _result: *mut u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn zero_timer_read() -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn never_elapsed(_start: u32, _interval: u32) -> bool { false }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn ignore_sleep(_ticks: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn ignore_report(_format: *const u8, _arg: u32) {}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_ATA_WAIT_BUSY_OR_READY_OPS: AtaWaitBusyOrReadyOps = AtaWaitBusyOrReadyOps {
    read_register: missing_read_register,
    timer_read: zero_timer_read,
    timer_elapsed: never_elapsed,
    sleep: ignore_sleep,
    report: ignore_report,
};

#[cfg(not(target_os = "none"))]
pub static mut ATA_WAIT_BUSY_OR_READY_OPS: AtaWaitBusyOrReadyOps = DEFAULT_ATA_WAIT_BUSY_OR_READY_OPS;

/// Host model of target-width words at `0x089d03bc`; this port reads `+0x18`.
#[cfg(not(target_os = "none"))]
pub static mut ATA_WAIT_BUSY_OR_READY_CONTEXT: [u32; 7] = [0; 7];

#[inline(always)]
unsafe fn interval() -> u32 {
    #[cfg(target_os = "none")]
    { ptr::read_volatile((0x089d_03bc as *const u32).add(CONTEXT_WAIT_INTERVAL_WORD)) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(ATA_WAIT_BUSY_OR_READY_CONTEXT).cast::<u32>().add(CONTEXT_WAIT_INTERVAL_WORD)) }
}

#[inline(always)]
unsafe fn read_register(register: u32, result: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    { crate::drivers::ata_taskfile_register_read::ata_taskfile_register_read(register, result) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(ATA_WAIT_BUSY_OR_READY_OPS.read_register))(register, result) }
}

#[inline(always)]
unsafe fn timer_read() -> u32 {
    #[cfg(target_os = "none")]
    { crate::drivers::timer::iram_usec_timer_read_veneer() }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(ATA_WAIT_BUSY_OR_READY_OPS.timer_read))() }
}

#[inline(always)]
unsafe fn timer_elapsed(start: u32, wait_interval: u32) -> bool {
    #[cfg(target_os = "none")]
    { crate::drivers::timer::iram_usec_timer_elapsed_veneer(start, wait_interval) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(ATA_WAIT_BUSY_OR_READY_OPS.timer_elapsed))(start, wait_interval) }
}

#[inline(always)]
unsafe fn sleep() {
    #[cfg(target_os = "none")]
    { crate::kernel::task::task_sleep(POLL_SLEEP_TICKS); }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(ATA_WAIT_BUSY_OR_READY_OPS.sleep))(POLL_SLEEP_TICKS) }
}

#[inline(always)]
unsafe fn report(format: *const u8, arg: u32) {
    #[cfg(target_os = "none")]
    { crate::stdio::debug_printf::debug_printf(format, &arg); }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(ATA_WAIT_BUSY_OR_READY_OPS.report))(format, arg) }
}

/// `ata_wait_busy_or_ready` — original: `FUN_080cdf5c` @ `0x080cdf5c`
/// (156 executable bytes; seven plain and zero predicated outbound `bl`).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_wait_busy_or_ready")]
#[inline(never)]
pub unsafe extern "C" fn ata_wait_busy_or_ready() -> u32 {
    let start = unsafe { timer_read() };
    loop {
        let mut status = 0;
        if unsafe { read_register(ATA_STATUS_REGISTER, &mut status) } == 0 {
            return 0;
        }
        if status & ATA_ERROR != 0 {
            let mut error = 0;
            if unsafe { read_register(ATA_ERROR_REGISTER, &mut error) } == 0 {
                unsafe { report(ATA_ERROR_READ_FAILURE_FORMAT, 0) };
                return 0;
            }
            unsafe { report(ATA_ERROR_FORMAT, error & 0xff) };
        }
        if unsafe { timer_elapsed(start, interval()) } {
            unsafe { report(ATA_TIMEOUT_FORMAT, 0) };
            return 0;
        }
        unsafe { sleep() };
        if status & ATA_BUSY_OR_DRQ == 0 {
            return 1;
        }
    }
}

#[cfg(test)]
pub(crate) static ATA_WAIT_BUSY_OR_READY_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    static mut STATUS: [u32; 3] = [0; 3];
    static mut READS: usize = 0;
    static mut SLEEPS: u32 = 0;
    static mut REPORT: (*const u8, u32) = (ptr::null(), 0);
    static mut ELAPSED: bool = false;

    unsafe extern "C" fn read(register: u32, result: *mut u32) -> u32 {
        let index = unsafe { READS };
        unsafe { READS += 1; *result = STATUS[index]; }
        assert!(register == ATA_STATUS_REGISTER || register == ATA_ERROR_REGISTER);
        1
    }
    unsafe extern "C" fn elapsed(_start: u32, _interval: u32) -> bool { unsafe { ELAPSED } }
    unsafe extern "C" fn sleep(ticks: u32) { assert_eq!(ticks, POLL_SLEEP_TICKS); unsafe { SLEEPS += 1; } }
    unsafe extern "C" fn report(format: *const u8, arg: u32) { unsafe { REPORT = (format, arg); } }

    fn install() -> AtaWaitBusyOrReadyOps {
        unsafe {
            let old = ATA_WAIT_BUSY_OR_READY_OPS;
            ATA_WAIT_BUSY_OR_READY_OPS = AtaWaitBusyOrReadyOps { read_register: read, timer_read: zero_timer_read, timer_elapsed: elapsed, sleep, report };
            ATA_WAIT_BUSY_OR_READY_CONTEXT[CONTEXT_WAIT_INTERVAL_WORD] = 123;
            STATUS = [0, 0, 0]; READS = 0; SLEEPS = 0; REPORT = (ptr::null(), 0); ELAPSED = false;
            old
        }
    }

    #[test]
    fn settled_status_succeeds_after_one_sleep() {
        let _lock = ATA_WAIT_BUSY_OR_READY_TEST_LOCK.lock();
        let old = install();
        unsafe { assert_eq!(ata_wait_busy_or_ready(), 1); assert_eq!(SLEEPS, 1); ATA_WAIT_BUSY_OR_READY_OPS = old; }
    }

    #[test]
    fn error_status_reports_low_error_byte_then_retries() {
        let _lock = ATA_WAIT_BUSY_OR_READY_TEST_LOCK.lock();
        let old = install();
        unsafe { STATUS = [ATA_ERROR | ATA_BUSY_OR_DRQ, 0x12_34, 0]; assert_eq!(ata_wait_busy_or_ready(), 1); assert_eq!(REPORT, (ATA_ERROR_FORMAT, 0x34)); assert_eq!(READS, 3); ATA_WAIT_BUSY_OR_READY_OPS = old; }
    }

    #[test]
    fn elapsed_busy_status_reports_timeout_without_sleeping() {
        let _lock = ATA_WAIT_BUSY_OR_READY_TEST_LOCK.lock();
        let old = install();
        unsafe { STATUS = [ATA_BUSY_OR_DRQ, 0, 0]; ELAPSED = true; assert_eq!(ata_wait_busy_or_ready(), 0); assert_eq!(REPORT, (ATA_TIMEOUT_FORMAT, 0)); assert_eq!(SLEEPS, 0); ATA_WAIT_BUSY_OR_READY_OPS = old; }
    }
}
