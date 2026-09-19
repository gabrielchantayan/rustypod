//! `ata_fast_io_write` — original: `FUN_080d7360` @ `0x080d7360`.
//!
//! Raw `osos.dec` extent is **72 bytes**, `0x080d7360..0x080d73a7`; the
//! next separately linked function starts at `0x080d73d0` after the command's
//! two literal words and its failure string. Decoding the 18 instruction words
//! finds **2 plain `bl` calls** (`0x080d7388`, `0x080d739c`) and **0 predicated
//! `bl` calls**. The four inbound calls are all plain: `0x08074f10`,
//! `0x080a9708`, `0x080a9720`, and `0x080a96fc`.
//!
//! # Algorithm
//!
//! Build the FAST_IO write command from the runtime ATA configuration: its
//! `+0x0c` word occupies command bits 16..31, `operation` bits 8.., and
//! `argument` the low bits; set bit 15, then submit `0x000400a7` with no status
//! output and the configuration's `+0x14` deadline. Return one on submission
//! success. On failure emit the stock diagnostic and return zero.
//!
//! Deliberate deviation: the runtime configuration at `0x089d03bc` is stale
//! image data until initialization, so host builds model it with a target-width
//! six-word static and route the two unported calls through testable seams.

use core::ptr;

pub const ATA_FAST_IO_WRITE_COMMAND: u32 = 0x0004_00a7;
pub const ATA_FAST_IO_WRITE_BIT: u32 = 0x0000_8000;
const ATA_FAST_IO_CONFIG_ADDRESS: *const u32 = 0x089d_03bc as *const u32;
const FAST_IO_WRITE_FAILED: *const u8 = 0x080d_73b0 as *const u8;

pub type AtaFastIoSubmit = unsafe extern "C" fn(u32, u32, *mut u32, u32) -> u32;
pub type AtaFastIoReport = unsafe extern "C" fn(*const u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_submit(_command: u32, _flags: u32, _status: *mut u32, _deadline: u32) -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_report(_message: *const u8) {}

#[cfg(not(target_arch = "arm"))]
pub static mut ATA_FAST_IO_CONFIG: [u32; 6] = [0; 6];
#[cfg(not(target_arch = "arm"))]
pub static mut ATA_FAST_IO_SUBMIT: AtaFastIoSubmit = missing_submit;
#[cfg(not(target_arch = "arm"))]
pub static mut ATA_FAST_IO_REPORT: AtaFastIoReport = missing_report;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_ata_fast_io_submit(command: u32, flags: u32, status: *mut u32, deadline: u32) -> u32;
    fn retail_ata_fast_io_report(message: *const u8);
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn retail_ata_fast_io_submit(command: u32, flags: u32, status: *mut u32, deadline: u32) -> u32 {
    ptr::read_volatile(ptr::addr_of!(ATA_FAST_IO_SUBMIT))(command, flags, status, deadline)
}
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn retail_ata_fast_io_report(message: *const u8) {
    ptr::read_volatile(ptr::addr_of!(ATA_FAST_IO_REPORT))(message)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_ata_fast_io_submit
retail_ata_fast_io_submit:
    ldr pc, [pc, #-4]
    .word 0x08077490
    .globl retail_ata_fast_io_report
retail_ata_fast_io_report:
    ldr pc, [pc, #-4]
    .word 0x082bd4a8
"#);

#[inline(always)]
unsafe fn config_word(index: usize) -> u32 {
    #[cfg(target_arch = "arm")]
    { ATA_FAST_IO_CONFIG_ADDRESS.add(index).read_volatile() }
    #[cfg(not(target_arch = "arm"))]
    { ptr::addr_of!(ATA_FAST_IO_CONFIG).cast::<u32>().add(index).read_volatile() }
}

/// Submits a FAST_IO write command through the ATA command engine.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_fast_io_write")]
#[inline(never)]
pub unsafe extern "C" fn ata_fast_io_write(operation: u32, argument: u32) -> u32 {
    let flags = (config_word(3) << 16) | (operation << 8) | argument | ATA_FAST_IO_WRITE_BIT;
    if retail_ata_fast_io_submit(ATA_FAST_IO_WRITE_COMMAND, flags, ptr::null_mut(), config_word(5)) != 0 {
        1
    } else {
        retail_ata_fast_io_report(FAST_IO_WRITE_FAILED);
        0
    }
}

#[cfg(test)]
pub(crate) static ATA_FAST_IO_WRITE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;

    static mut SEEN: (u32, u32, usize, u32) = (0, 0, 1, 0);
    static mut REPORTS: u32 = 0;
    unsafe extern "C" fn submit(command: u32, flags: u32, status: *mut u32, deadline: u32) -> u32 {
        SEEN = (command, flags, status as usize, deadline);
        1
    }
    unsafe extern "C" fn fail_submit(command: u32, flags: u32, status: *mut u32, deadline: u32) -> u32 {
        SEEN = (command, flags, status as usize, deadline);
        0
    }
    unsafe extern "C" fn report(message: *const u8) {
        assert_eq!(message, FAST_IO_WRITE_FAILED);
        REPORTS += 1;
    }

    #[test]
    fn submits_packed_fast_io_write() {
        let _lock = ATA_FAST_IO_WRITE_TEST_LOCK.lock();
        unsafe {
            ATA_FAST_IO_CONFIG = [0, 0, 0, 0x1234, 0, 0xfeed_beef];
            ATA_FAST_IO_SUBMIT = submit;
            ATA_FAST_IO_REPORT = report;
            REPORTS = 0;
            assert_eq!(ata_fast_io_write(6, 4), 1);
            assert_eq!(SEEN, (ATA_FAST_IO_WRITE_COMMAND, 0x1234_8604, 0, 0xfeed_beef));
            assert_eq!(REPORTS, 0);
        }
    }

    #[test]
    fn reports_submission_failure() {
        let _lock = ATA_FAST_IO_WRITE_TEST_LOCK.lock();
        unsafe {
            ATA_FAST_IO_CONFIG = [0, 0, 0, 0, 0, 7];
            ATA_FAST_IO_SUBMIT = fail_submit;
            ATA_FAST_IO_REPORT = report;
            REPORTS = 0;
            assert_eq!(ata_fast_io_write(0, 0), 0);
            assert_eq!(SEEN, (ATA_FAST_IO_WRITE_COMMAND, ATA_FAST_IO_WRITE_BIT, 0, 7));
            assert_eq!(REPORTS, 1);
        }
    }
}
