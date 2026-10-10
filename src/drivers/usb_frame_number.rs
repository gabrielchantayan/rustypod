//! USB frame/microframe counter — retail `FUN_08088aac`.
//! Load address 0x08088aac, true extent [0x08088aac, 0x08088ac0): 20 bytes,
//! five A32 instructions; the next routine starts with CMP and a jump table.
//! Full-image aligned word decoding verifies two plain inbound BLs at
//! 0x08107b9c and 0x08107d50, zero predicated inbound BLs, no outgoing BLs.
//!
//! Read the aligned USB link-status register at 0x38400808 once and return
//! bits 8..21 as a 14-bit counter. The callers save it at transfer start and
//! compute elapsed frames modulo 0x4000, dividing by eight in high-speed mode.
//! No target behavioral deviations. Host builds reuse the shared isolated
//! status word; the volatile read is inlined, not a new firmware callee.

use crate::drivers::usb_high_speed_mode::usb_link_status_read;

/// On target, the USB controller's aligned link-status register must be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_frame_number() -> u32 {
    (usb_link_status_read() >> 8) & 0x3fff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::usb_high_speed_mode::host_usb_link_status;
    use core::ptr::{addr_of, addr_of_mut};

    #[test]
    fn counter_boundaries_wrap_and_unrelated_status_bits_are_ignored() {
        let _guard = host_usb_link_status::LOCK.lock();
        unsafe {
            let saved = addr_of!(host_usb_link_status::WORD).read_volatile();
            for counter in [0, 1, 7, 8, 0x1fff, 0x2000, 0x3ffe, 0x3fff, 0x4000] {
                for unrelated in [0, 0xff, 0xffc0_0000, 0xffc0_00ff] {
                    let status = (counter << 8) | unrelated;
                    addr_of_mut!(host_usb_link_status::WORD).write_volatile(status);
                    // Independent reference: the original pair of ARM shifts.
                    let expected = status.wrapping_shl(10) >> 18;
                    assert_eq!(usb_frame_number(), expected, "status={status:#010x}");
                    assert_eq!(addr_of!(host_usb_link_status::WORD).read_volatile(), status);
                }
            }
            // Every retained bit and both adjacent excluded bits.
            for bit in 0..32 {
                addr_of_mut!(host_usb_link_status::WORD).write_volatile(1 << bit);
                let expected = if (8..22).contains(&bit) { 1 << (bit - 8) } else { 0 };
                assert_eq!(usb_frame_number(), expected, "bit={bit}");
            }
            addr_of_mut!(host_usb_link_status::WORD).write_volatile(saved);
        }
    }
}
