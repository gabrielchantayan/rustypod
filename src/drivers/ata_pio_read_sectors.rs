//! PIO sector reads — `FUN_080c4af4` @ `0x080c4af4`.
//!
//! Raw extent [0x080c4af4, 0x080c4b70) is 124 bytes: 120 instruction
//! bytes and the 5000-ms literal at 0x080c4b6c. The next real function is
//! the independently entered halfword reader at 0x080c4b70. Whole-image
//! A32 decoding finds two inbound plain BLs (0x0836c100, 0x0836c698), zero
//! predicated inbound BLs, three outbound plain BLs, zero predicated BLs.
//! Reject NULL with 7, then for each sector select operation state 5, wait
//! up to 5000 ms for status 4, read 256 halfwords, and advance by 512 bytes.
//! Any wait/read failure returns 0x59 immediately; zero sectors returns 0.
//!
//! Deliberate deviations: use the existing Rust state/wait ports, supplying
//! zero for the wait routine's unused r2 and overwritten initial-status r3,
//! as in ata_command_prepare. The unported PIO block reader remains a call
//! to its verified retail entry, not Ghidra's incorrect four-argument body.
//! Host execution of that reader is unsupported; tests inject operations
//! into the same inlined sector loop without replacing production behavior.

use crate::drivers::ata_command_execute::{ata_command_execute, AtaCommandDevice};
use crate::drivers::ata_operation_state_set::ata_operation_state_set;

#[inline(always)]
unsafe fn read_halfwords(device: *mut AtaCommandDevice, destination: *mut u8, count: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let read: unsafe extern "C" fn(*mut AtaCommandDevice, *mut u8, u32) -> u32 =
            core::mem::transmute(0x080a_988cusize);
        read(device, destination, count)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (device, destination, count);
        panic!("retail ATA PIO block reader at 0x080a988c is unavailable on host");
    }
}

#[inline(always)]
unsafe fn read_sectors_with(
    device: *mut AtaCommandDevice,
    mut destination: *mut u8,
    mut sectors: u32,
    mut set_state: impl FnMut(*mut AtaCommandDevice, u32) -> u32,
    mut execute: impl FnMut(*mut AtaCommandDevice, u32, u32, u32) -> u32,
    mut read: impl FnMut(*mut AtaCommandDevice, *mut u8, u32) -> u32,
) -> u32 {
    if device.is_null() { return 7; }
    while sectors != 0 {
        set_state(device, 5);
        if execute(device, 5000, 0, 0) != 4 || read(device, destination, 256) != 0 {
            return 0x59;
        }
        destination = destination.wrapping_add(512);
        sectors -= 1;
    }
    0
}

/// Requires a live ATA device and writable storage for `sectors * 512` bytes
/// when sectors is nonzero. NULL is rejected even when sectors is zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ata_pio_read_sectors(
    device: *mut AtaCommandDevice, destination: *mut u8, sectors: u32,
) -> u32 {
    read_sectors_with(device, destination, sectors,
        |device, state| ata_operation_state_set(device, state),
        |device, timeout, unused, status| ata_command_execute(device, timeout, unused, status),
        |device, destination, count| read_halfwords(device, destination, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn public_empty_paths_do_not_touch_device_or_destination() {
        unsafe {
            assert_eq!(ata_pio_read_sectors(core::ptr::null_mut(), core::ptr::null_mut(), 0), 7);
            assert_eq!(ata_pio_read_sectors(core::ptr::null_mut(), core::ptr::null_mut(), u32::MAX), 7);
            assert_eq!(ata_pio_read_sectors(core::ptr::dangling_mut(), core::ptr::null_mut(), 0), 0);
        }
    }

    #[test]
    fn sector_progress_and_failures_preserve_unread_storage() {
        // Stage 0: state selection; 1: wait; 2: read. State errors are ignored.
        for wait_status in [0, 1, 2, 3, 4, 5, u32::MAX] {
            for read_status in [0, 1, 0x51, u32::MAX] {
                for fail_sector in 0..3 {
                    let mut storage = [0xa5u8; 1538];
                    let base = unsafe { storage.as_mut_ptr().add(1) };
                    let sector = Cell::new(0usize);
                    let stage = Cell::new(0);
                    let result = unsafe { read_sectors_with(core::ptr::dangling_mut(), base, 3,
                        |_, state| {
                            assert_eq!(stage.replace(1), 0);
                            assert_eq!(state, 5);
                            99
                        },
                        |_, timeout, unused, initial| {
                            assert_eq!(stage.replace(2), 1);
                            assert_eq!((timeout, unused, initial), (5000, 0, 0));
                            if sector.get() == fail_sector { wait_status } else { 4 }
                        },
                        |_, destination, count| {
                            assert_eq!(stage.replace(0), 2);
                            assert_eq!(count, 256);
                            let index = sector.get();
                            assert_eq!(destination, base.wrapping_add(index * 512));
                            if index == fail_sector && read_status != 0 { return read_status; }
                            for byte in 0..512 { destination.add(byte).write(index as u8); }
                            sector.set(index + 1);
                            0
                        }) };
                    let failed = wait_status != 4 || read_status != 0;
                    assert_eq!(result, if failed { 0x59 } else { 0 });
                    let completed = if failed { fail_sector } else { 3 };
                    assert_eq!(sector.get(), completed);
                    for index in 0..3 {
                        assert!(storage[1 + index * 512..1 + (index + 1) * 512]
                            .iter().all(|&byte| byte == if index < completed { index as u8 } else { 0xa5 }));
                    }
                    assert_eq!((storage[0], storage[1537]), (0xa5, 0xa5));
                }
            }
        }
    }
}
