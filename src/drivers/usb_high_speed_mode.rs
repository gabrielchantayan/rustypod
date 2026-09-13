//! `usb_high_speed_mode_active` — original: `FUN_08107f04` @ `0x08107f04`
//! (24 bytes; 7 unconditional `bl` call sites and no predicated forms,
//! binary-scanned from `work/firmware/osos.dec`).
//!
//! Reads the USB link-status word at `0x3840_0808` and returns one exactly
//! when neither status bit 1 nor status bit 2 is set. Its callers use the
//! result to select 0x200-byte instead of 0x40-byte transfer packets, so the
//! clear state is the controller's high-speed mode.
//!
//! The target path performs the original one volatile word read. The host
//! path deliberately substitutes one volatile word, allowing tests to cover
//! every relevant status-bit combination without mapping MMIO.

/// USB controller link-status register read by the retail routine.
const USB_LINK_STATUS: *const u32 = 0x3840_0808 as *const u32;
/// Bits that mean the link is not operating at high speed.
const USB_NOT_HIGH_SPEED_MASK: u32 = 0x6;

/// Applies the retail `tst r0, #6; movne; moveq` result normalization.
#[inline]
pub const fn usb_high_speed_from_status(link_status: u32) -> u32 {
    ((link_status & USB_NOT_HIGH_SPEED_MASK) == 0) as u32
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn usb_link_status_read() -> u32 {
    USB_LINK_STATUS.read_volatile()
}

/// Host-side stand-in for the USB controller's link-status word.
#[cfg(not(target_arch = "arm"))]
pub(crate) mod host_usb_link_status {
    pub static mut WORD: u32 = 0;
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn usb_link_status_read() -> u32 {
    core::ptr::addr_of!(host_usb_link_status::WORD).read_volatile()
}

/// Returns whether the USB controller is in the retailOS high-speed state.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.usb_high_speed_mode_active")]
#[inline(never)]
pub unsafe extern "C" fn usb_high_speed_mode_active() -> u32 {
    usb_high_speed_from_status(usb_link_status_read())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_link_status_bit_combination_matches_the_retail_tst() {
        for status in [0, 1, 2, 4, 6, u32::MAX] {
            let expected = if status & 6 == 0 { 1 } else { 0 };
            assert_eq!(usb_high_speed_from_status(status), expected, "{status:#010x}");
        }
    }

    #[test]
    fn exported_entry_reads_the_host_status_word_volatily() {
        unsafe {
            core::ptr::addr_of_mut!(host_usb_link_status::WORD).write_volatile(1);
            assert_eq!(usb_high_speed_mode_active(), 1);

            core::ptr::addr_of_mut!(host_usb_link_status::WORD).write_volatile(2);
            assert_eq!(usb_high_speed_mode_active(), 0);
        }
    }
}
