//! ATA DMA configuration — `FUN_080922c8` @ `0x080922c8`.
//!
//! True extent [0x080922c8, 0x08092364): 156 bytes, comprising 152
//! instruction bytes and the 0x38700000 literal at 0x08092360. Raw ARM
//! decoding finds two incoming plain BLs (0x0836c668 and 0x0836d03c), zero
//! predicated BL callers, no tail callers, and zero outgoing BLs.
//!
//! Mask the buffer address's high bit. Program either the read/write DMA
//! address and byte count, or the alternate address register. Always set
//! total bytes minus one with wrapping arithmetic. Select control flags from
//! the device halfword at +0x24, clear bits 7/8, select write direction, and
//! optionally set bit 12. Preserve separate volatile read/modify/write steps.
//! Deliberate deviation: hosts use a RAM register bank instead of MMIO;
//! firmware uses the original fixed address. No behavioral deviations.

#[cfg(not(target_os = "none"))]
use core::ptr;
use crate::drivers::ata_command_execute::AtaCommandDevice;
#[cfg(not(target_os = "none"))]
pub static mut ATA_DMA_MMIO_WORDS: [u32; 35] = [0; 35];

#[inline(always)]
unsafe fn configure_registers(
    device: *const AtaCommandDevice,
    buffer_address: u32,
    sectors: u32,
    write: u32,
    alternate: u32,
    registers: *mut u32,
) {
    let address = buffer_address & 0x7fff_ffff;
    let bytes = sectors.wrapping_shl(9);
    if alternate != 0 {
        registers.add(0x88 / 4).write_volatile(address);
    } else if write != 0 {
        registers.add(0x48 / 4).write_volatile(bytes);
        registers.add(0x44 / 4).write_volatile(address);
    } else {
        registers.add(0x40 / 4).write_volatile(bytes);
        registers.add(0x3c / 4).write_volatile(address);
    }
    registers.add(0x34 / 4).write_volatile(bytes.wrapping_sub(1));
    let mode = device.cast::<u16>().add(0x24 / 2).read();
    let control = registers.add(0x18 / 4);
    let flags = if mode == 0 { 0x408 } else { 0x60c };
    control.write_volatile(control.read_volatile() | flags);
    control.write_volatile(control.read_volatile() & !0x180);
    let value = control.read_volatile();
    control.write_volatile(if write == 0 { value & !0x10 } else { value | 0x10 });
    if alternate != 0 {
        control.write_volatile(control.read_volatile() | 0x1000);
    }
}

/// Configure a sector DMA transfer without starting or waiting for it.
///
/// # Safety
/// `device` must have a readable aligned halfword at +0x24. Firmware requires
/// access to the ATA controller; callers must serialize controller access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ata_dma_configure(
    device: *const AtaCommandDevice,
    buffer_address: u32,
    sectors: u32,
    write: u32,
    alternate: u32,
) {
    #[cfg(target_os = "none")]
    let registers = 0x3870_0000 as *mut u32;
    #[cfg(not(target_os = "none"))]
    let registers = ptr::addr_of_mut!(ATA_DMA_MMIO_WORDS).cast::<u32>();
    configure_registers(device, buffer_address, sectors, write, alternate, registers);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_updates_match_reference_across_modes_and_wrapping_counts() {
        for mode in [0u16, 1, 0x8000, 0xffff] {
            for write in [0, 1, 0xffff_ffff] {
                for alternate in [0, 1, 0x8000_0000] {
                    for sectors in [0u32, 1, 256, 0x0080_0000, u32::MAX] {
                        for initial in [0u32, u32::MAX, 0xa5a5_1184] {
                            let mut device = [0u16; 40];
                            device[18] = mode;
                            let mut actual = [0xdead_beefu32; 35];
                            actual[6] = initial;
                            let mut expected = actual;
                            let bytes = ((sectors as u64 * 512) & 0xffff_ffff) as u32;
                            if alternate != 0 {
                                expected[34] = 0x7123_4567;
                            } else {
                                let address_index = if write == 0 { 15 } else { 17 };
                                expected[address_index] = 0x7123_4567;
                                expected[address_index + 1] = bytes;
                            }
                            expected[13] = (bytes as u64 + 0xffff_ffff) as u32;
                            expected[6] = (initial | if mode == 0 { 0x408 } else { 0x60c }) & !0x180;
                            if write == 0 { expected[6] &= !0x10; } else { expected[6] |= 0x10; }
                            if alternate != 0 { expected[6] |= 0x1000; }
                            unsafe {
                                configure_registers(device.as_ptr().cast(), 0xf123_4567,
                                    sectors, write, alternate, actual.as_mut_ptr());
                            }
                            assert_eq!(actual, expected);
                            assert_eq!(device[18], mode);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exported_entry_programs_host_controller() {
        let mut device = [0u16; 40];
        device[18] = 0x100;
        unsafe {
            let registers = ptr::addr_of_mut!(ATA_DMA_MMIO_WORDS).cast::<u32>();
            registers.write_bytes(0, 35);
            ata_dma_configure(device.as_ptr().cast(), 0x8800_1000, 2, 1, 0);
            assert_eq!(registers.add(17).read(), 0x0800_1000);
            assert_eq!(registers.add(18).read(), 1024);
            assert_eq!(registers.add(13).read(), 1023);
            assert_eq!(registers.add(6).read(), 0x61c);
            ata_dma_configure(device.as_ptr().cast(), 0x8000_0020, 0, 0, 7);
            assert_eq!(registers.add(34).read(), 0x20);
            assert_eq!(registers.add(13).read(), u32::MAX);
            assert_eq!(registers.add(6).read(), 0x160c);
            assert_eq!(registers.add(17).read(), 0x0800_1000);
        }
    }
}
