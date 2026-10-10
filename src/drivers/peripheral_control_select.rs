//! Peripheral control selection — retailOS `FUN_0808e194` @ 0x0808e194.
//! True extent: 140 bytes [0x0808e194, 0x0808e220): 132 instruction bytes
//! and two register-base literals. The next function is the MOV/B tail
//! wrapper at 0x0808e220, not the PUSH at 0x0808e228.
//! Whole-image aligned A32 decoding finds two inbound plain BLs at
//! 0x08076738 and 0x081b08b8, zero predicated inbound BLs, and zero outbound
//! BLs of either kind. Callers use (selector, value) = (1, 3) and (2, 12).
//! Select control +0x0c in blocks 0x39600000, 0x39660000, or 0x39610000.
//! For selector zero and value one, save bank configuration, clear bit 4
//! at 0x39610010, write control, read/write 0x39660000, and restore saved
//! words in firmware order. Other selectors are ignored. Exact peripheral
//! and control meanings are not established; no callee seams are needed.
//! Deliberate deviations: volatile accesses express MMIO; host builds use
//! isolated word arrays instead of fixed hardware addresses.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_CONTROL: [u32; 4] = [0; 4];
#[cfg(not(target_os = "none"))]
static mut HOST_BANK: [u32; 10] = [0; 10];
#[cfg(not(target_os = "none"))]
static mut HOST_MAILBOX: [u32; 7] = [0; 7];

/// Select a peripheral control word, preserving configuration on the special transition.
///
/// # Safety
/// Hardware must be accessible and calls serialized with all other accesses
/// to these blocks, including the host substitutes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn peripheral_control_select(selector: u32, value: u32) {
    #[cfg(target_os = "none")]
    let (control, bank, mailbox) = (
        0x3960_0000 as *mut u32, 0x3966_0000 as *mut u32,
        0x3961_0000 as *mut u32,
    );
    #[cfg(not(target_os = "none"))]
    let (control, bank, mailbox) = (
        ptr::addr_of_mut!(HOST_CONTROL).cast::<u32>(),
        ptr::addr_of_mut!(HOST_BANK).cast::<u32>(),
        ptr::addr_of_mut!(HOST_MAILBOX).cast::<u32>(),
    );

    match selector {
        0 if value == 1 => {
            let flags = ptr::read_volatile(mailbox.add(4));
            let bank_word9 = ptr::read_volatile(bank.add(9));
            let bank_word8 = ptr::read_volatile(bank.add(8));
            let bank_word4 = ptr::read_volatile(bank.add(4));
            let mailbox_word6 = ptr::read_volatile(mailbox.add(6));
            ptr::write_volatile(mailbox.add(4), flags & !0x10);
            ptr::write_volatile(control.add(3), 1);
            let bank_word0 = ptr::read_volatile(bank);
            ptr::write_volatile(bank, bank_word0);
            ptr::write_volatile(mailbox.add(6), mailbox_word6);
            ptr::write_volatile(bank.add(4), bank_word4);
            ptr::write_volatile(bank.add(8), bank_word8);
            ptr::write_volatile(bank.add(9), bank_word9);
            ptr::write_volatile(mailbox.add(4), flags);
        }
        0 => ptr::write_volatile(control.add(3), value),
        1 => ptr::write_volatile(bank.add(3), value),
        2 => ptr::write_volatile(mailbox.add(3), value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_preserve_neighbors_and_special_transition_restores_configuration() {
        unsafe {
            for selector in [0, 1, 2, 3, 0x8000_0000, u32::MAX] {
                for value in [0, 1, 3, 12, 0x8000_0000, u32::MAX] {
                    for flags in [0, 0x10, 0xffff_ffef, u32::MAX] {
                        let control = [0x1234_5678; 4];
                        let bank = core::array::from_fn(|i| 0x8765_0000 | i as u32);
                        let mut mailbox = core::array::from_fn(|i| 0xabcd_0000 | i as u32);
                        mailbox[4] = flags;
                        HOST_CONTROL = control;
                        HOST_BANK = bank;
                        HOST_MAILBOX = mailbox;
                        let mut expected_control = control;
                        let mut expected_bank = bank;
                        let mut expected_mailbox = mailbox;
                        match selector {
                            0 => expected_control[3] = value,
                            1 => expected_bank[3] = value,
                            2 => expected_mailbox[3] = value,
                            _ => {}
                        }
                        peripheral_control_select(selector, value);
                        assert_eq!(HOST_CONTROL, expected_control);
                        assert_eq!(HOST_BANK, expected_bank);
                        assert_eq!(HOST_MAILBOX, expected_mailbox);
                    }
                }
            }
        }
    }
}
