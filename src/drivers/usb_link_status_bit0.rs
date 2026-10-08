//! USB link-status bit 0 — retail `FUN_081076f0` at 0x081076f0.
//! True extent: [0x081076f0, 0x08107700), 16 bytes; the next function
//! begins with PUSH. Raw aligned A32 decoding verifies two incoming plain
//! BLs (0x0829460c, 0x082946a0), zero predicated BLs, and no outgoing BLs.
//!
//! Read the aligned USB link-status word at 0x38400808 once and return
//! its low bit as 0 or 1. The caller's controller argument is ignored.
//! The hardware meaning of this bit remains unidentified. No target
//! behavioral deviations; host builds reuse the existing USB status-word
//! stand-in instead of accessing MMIO.

use crate::drivers::usb_high_speed_mode::usb_link_status_read;

/// On target, the USB controller's link-status register must be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_link_status_bit0(_controller: u32) -> u32 {
    usb_link_status_read() & 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::usb_high_speed_mode::host_usb_link_status;
    use core::ptr::{addr_of, addr_of_mut};

    #[test]
    fn low_bit_is_normalized_and_all_other_bits_are_ignored() {
        let _guard = host_usb_link_status::LOCK.lock();
        unsafe {
            let saved = addr_of!(host_usb_link_status::WORD).read_volatile();
            for status in [0, 1, 2, 3, 4, 5, 6, 7, 0x8000_0000, 0x8000_0001,
                           0xffff_fffe, u32::MAX] {
                addr_of_mut!(host_usb_link_status::WORD).write_volatile(status);
                for controller in [0, 1, u32::MAX] {
                    assert_eq!(usb_link_status_bit0(controller), status % 2,
                               "status={status:#010x}, controller={controller:#010x}");
                }
                assert_eq!(addr_of!(host_usb_link_status::WORD).read_volatile(), status);
            }
            addr_of_mut!(host_usb_link_status::WORD).write_volatile(saved);
        }
    }
}
