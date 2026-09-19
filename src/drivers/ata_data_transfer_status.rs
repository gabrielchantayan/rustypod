//! `ata_data_transfer_status_ok` — original: `FUN_08087a64` @ `0x08087a64`.
//!
//! Raw `osos.dec` confirms a **120-byte** instruction body,
//! `0x08087a64..0x08087ad8`; `0x08087adc` begins its first inline diagnostic
//! string, not another instruction. Decoding its words finds **1 plain `bl`**
//! (`0x08087a6c`) and **3 predicated `bl` calls** (`0x08087a88`,
//! `0x08087a98`, `0x08087ad0`).
//!
//! # Algorithm
//!
//! Read the ATA transfer-status word. Return one unless a write-response CRC
//! error (bit 22), read-data CRC error (bit 23), write-data CRC error
//! (bits 19..21 = 5), card CRC error (bits 19..21 = 7), or any high-byte
//! end-bit error is present. Emit every applicable stock diagnostic in the
//! original order before returning zero.
//!
//! # Deliberate deviation
//!
//! The four inline formats have no conversions, while ARM leaves `r1`
//! unspecified at each variadic `debug_printf` call. Rust passes a null
//! argument-list pointer instead; the formatter cannot observe a difference
//! for these conversion-free strings.

use core::ptr;

use crate::heap::state::global_indirect_status_get;
use crate::stdio::debug_printf::debug_printf;

const WRITE_RESPONSE_CRC_ERROR: u32 = 0x0040_0000;
const READ_DATA_CRC_ERROR: u32 = 0x0080_0000;
const DATA_CRC_ERROR_MASK: u32 = 0x0038_0000;
const WRITE_DATA_CRC_ERROR: u32 = 0x0028_0000;
const CARD_CRC_ERROR: u32 = 0x0038_0000;
const END_BIT_ERROR_MASK: u32 = 0xff00_0000;

const WRITE_RESPONSE_CRC_ERROR_FORMAT: *const u8 = 0x0808_7adc as *const u8;
const READ_DATA_CRC_ERROR_FORMAT: *const u8 = 0x0808_7b00 as *const u8;
const WRITE_DATA_CRC_ERROR_FORMAT: *const u8 = 0x0808_7b1c as *const u8;
const CARD_CRC_ERROR_FORMAT: *const u8 = 0x0808_7b38 as *const u8;
const READ_DATA_END_BIT_ERROR_FORMAT: *const u8 = 0x0808_7b58 as *const u8;

#[inline(always)]
unsafe fn report(format: *const u8) {
    debug_printf(format, ptr::null());
}

/// Reports ATA data-transfer status failures and returns one only when none occur.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_data_transfer_status_ok")]
#[inline(never)]
pub unsafe extern "C" fn ata_data_transfer_status_ok() -> u32 {
    let status = global_indirect_status_get();
    let mut ok = 1;

    if status & WRITE_RESPONSE_CRC_ERROR != 0 {
        ok = 0;
        report(WRITE_RESPONSE_CRC_ERROR_FORMAT);
    }
    if status & READ_DATA_CRC_ERROR != 0 {
        ok = 0;
        report(READ_DATA_CRC_ERROR_FORMAT);
    }
    match status & DATA_CRC_ERROR_MASK {
        WRITE_DATA_CRC_ERROR => {
            ok = 0;
            report(WRITE_DATA_CRC_ERROR_FORMAT);
        }
        CARD_CRC_ERROR => {
            ok = 0;
            report(CARD_CRC_ERROR_FORMAT);
        }
        _ => {}
    }
    if status & END_BIT_ERROR_MASK != 0 {
        ok = 0;
        report(READ_DATA_END_BIT_ERROR_FORMAT);
    }

    ok
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::state::GLOBAL_INDIRECT_HOLDER;
    use crate::stdio::debug_printf::{DebugVprintfFn, DEBUG_VPRINTF};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut REPORTS: [usize; 4] = [0; 4];
    static mut REPORT_COUNT: usize = 0;

    unsafe extern "C" fn record_report(format: *const u8, args: *const u32) -> i32 {
        assert!(args.is_null(), "conversion-free diagnostic has no argument list");
        REPORTS[REPORT_COUNT] = format as usize;
        REPORT_COUNT += 1;
        0
    }

    unsafe fn install_status(state: &mut [u32; 7]) -> *mut u8 {
        let slot = core::ptr::addr_of_mut!(GLOBAL_INDIRECT_HOLDER)
            .cast::<u8>()
            .add(4)
            .cast::<*mut u8>();
        let old = slot.read_unaligned();
        slot.write_unaligned(state.as_mut_ptr().cast());
        old
    }

    unsafe fn restore_status(old: *mut u8) {
        core::ptr::addr_of_mut!(GLOBAL_INDIRECT_HOLDER)
            .cast::<u8>()
            .add(4)
            .cast::<*mut u8>()
            .write_unaligned(old);
    }

    #[test]
    fn reports_each_simultaneous_error_in_firmware_order() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let old_reporter: DebugVprintfFn = DEBUG_VPRINTF;
            DEBUG_VPRINTF = record_report;
            REPORT_COUNT = 0;
            let mut state = [0, 0, 0, 0, 0, 0, 0x01e8_0000];
            let old_state = install_status(&mut state);

            assert_eq!(ata_data_transfer_status_ok(), 0);
            assert_eq!(REPORT_COUNT, 4);
            assert_eq!(REPORTS[..4], [
                WRITE_RESPONSE_CRC_ERROR_FORMAT as usize,
                READ_DATA_CRC_ERROR_FORMAT as usize,
                WRITE_DATA_CRC_ERROR_FORMAT as usize,
                READ_DATA_END_BIT_ERROR_FORMAT as usize,
            ]);

            restore_status(old_state);
            DEBUG_VPRINTF = old_reporter;
        }
    }

    #[test]
    fn accepts_unreported_low_flags_and_reports_card_crc() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let old_reporter: DebugVprintfFn = DEBUG_VPRINTF;
            DEBUG_VPRINTF = record_report;
            REPORT_COUNT = 0;
            let mut state = [0, 0, 0, 0, 0, 0, 0x0021_0000];
            let old_state = install_status(&mut state);

            assert_eq!(ata_data_transfer_status_ok(), 1);
            assert_eq!(REPORT_COUNT, 0);

            state[6] = CARD_CRC_ERROR;
            assert_eq!(ata_data_transfer_status_ok(), 0);
            assert_eq!(REPORT_COUNT, 1);
            assert_eq!(REPORTS[0], CARD_CRC_ERROR_FORMAT as usize);

            restore_status(old_state);
            DEBUG_VPRINTF = old_reporter;
        }
    }
}
