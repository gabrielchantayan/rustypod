//! USB endpoint status-dependent control mask — retail `FUN_080a2268`.
//! Load address 0x080a2268, true extent [0x080a2268, 0x080a2280): 24 bytes,
//! six A32 instructions, no literals. The next routine starts at 0x080a2280.
//! Full-image aligned word decoding finds two plain inbound BLs at
//! 0x08081704 and 0x080a78b0, zero predicated inbound BLs, and no outgoing BLs.
//!
//! Read the USB link-status word at 0x38400808 once. Return 0x20000000 when
//! bit 8 is clear, otherwise 0x10000000; ignore every other bit. Both callers
//! OR this mask into an endpoint control word in the 0x900/0xb00 banks.
//! The hardware meaning of the selected control bits remains unidentified.
//! No target behavioral deviations. Host builds reuse the existing isolated
//! USB status word; the shared read is inlined, not a new firmware callee.

use crate::drivers::usb_high_speed_mode::usb_link_status_read;

/// On target, the USB controller's aligned link-status register must be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_endpoint_status_control_mask() -> u32 {
    let link_status = usb_link_status_read();
    if link_status & 0x100 == 0 { 0x2000_0000 } else { 0x1000_0000 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::usb_high_speed_mode::host_usb_link_status;
    use core::ptr::{addr_of, addr_of_mut};

    #[test]
    fn bit_eight_selects_the_mask_and_other_bits_do_not_affect_it() {
        let _guard = host_usb_link_status::LOCK.lock();
        unsafe {
            let saved = addr_of!(host_usb_link_status::WORD).read_volatile();
            for status in [0, 0x100, 0xff, 0x1ff, 0x200, 0x300,
                           0x8000_0000, 0x8000_0100, 0xffff_feff, u32::MAX] {
                addr_of_mut!(host_usb_link_status::WORD).write_volatile(status);
                let expected = match (status >> 8) & 1 {
                    0 => 1 << 29,
                    _ => 1 << 28,
                };
                assert_eq!(usb_endpoint_status_control_mask(), expected,
                           "status={status:#010x}");
                assert_eq!(addr_of!(host_usb_link_status::WORD).read_volatile(), status);
            }
            addr_of_mut!(host_usb_link_status::WORD).write_volatile(saved);
        }
    }
}
