//! Installs one of the fixed IRAM stubs — original: `FUN_082bd01c` @
//! 0x082bd01c (40 bytes).
//!
//! Raw words establish the body through the `bx lr` at 0x082bd040; the two
//! following words are its literal pool and 0x082bd04c starts the next leaf.
//! Four direct inbound calls are plain `bl` (none predicated); the sole
//! outbound transfer is a predicated tail `bne` to `strncpy` @ 0x080310d4.
//!
//! The function accepts selectors 0..4, takes the corresponding eight-byte
//! record from the nine-byte-stride executable table at 0x083e8b55, and
//! installs it at the IRAM execution slot 0x2203ff00 with `strncpy`. Selectors
//! at least five leave the installed stub unchanged. The Rust helper accepts
//! its fixed addresses as arguments only to make the target behavior testable
//! on the host; the exported entry uses the original constants.

use crate::libc::strncpy::strncpy;

const IRAM_STUB_SLOT: *mut u8 = 0x2203_ff00 as *mut u8;
const STUB_RECORDS: *const u8 = 0x083e_8b55 as *const u8;
const STUB_COUNT: u32 = 5;
const STUB_RECORD_STRIDE: usize = 9;
const STUB_COPY_LEN: usize = 8;

#[inline(always)]
unsafe fn install_iram_stub_at(selector: u32, slot: *mut u8, records: *const u8) -> *mut u8 {
    if selector >= STUB_COUNT {
        return slot;
    }

    strncpy(slot, records.add(selector as usize * STUB_RECORD_STRIDE), STUB_COPY_LEN)
}

/// Installs the selected eight-byte IRAM stub.
///
/// # Safety
/// On target, this writes the fixed executable IRAM slot at `0x2203ff00`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn install_iram_stub(selector: u32) -> *mut u8 {
    install_iram_stub_at(selector, IRAM_STUB_SLOT, STUB_RECORDS)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn copies_each_valid_record_with_its_nine_byte_stride() {
        let records = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xff,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0xfe,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0xfd,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0xfc,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0xfb,
        ];

        for selector in 0..STUB_COUNT {
            let mut slot = [0xa5; STUB_COPY_LEN];
            let result = unsafe { install_iram_stub_at(selector, slot.as_mut_ptr(), records.as_ptr()) };
            assert_eq!(result, slot.as_mut_ptr());
            assert_eq!(&slot, &records[selector as usize * STUB_RECORD_STRIDE..][..STUB_COPY_LEN]);
        }
    }

    #[test]
    fn strncpy_pads_an_embedded_nul() {
        let records = [0x81, 0x00, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0xff];
        let mut slot = [0xa5; STUB_COPY_LEN];

        unsafe { install_iram_stub_at(0, slot.as_mut_ptr(), records.as_ptr()) };

        assert_eq!(slot, [0x81, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn invalid_selectors_leave_the_slot_unchanged() {
        let records = [0; STUB_COUNT as usize * STUB_RECORD_STRIDE];

        for selector in [STUB_COUNT, STUB_COUNT + 1, u32::MAX] {
            let mut slot = [0xa5; STUB_COPY_LEN];
            let result = unsafe { install_iram_stub_at(selector, slot.as_mut_ptr(), records.as_ptr()) };
            assert_eq!(result, slot.as_mut_ptr());
            assert_eq!(slot, [0xa5; STUB_COPY_LEN]);
        }
    }
}
