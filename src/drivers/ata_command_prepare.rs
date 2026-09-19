//! `ata_command_prepare` — original: `FUN_080b1ae8` @ `0x080b1ae8`.
//!
//! Raw `osos.dec` has **80 instruction bytes** at `0x080b1ae8..0x080b1b37`;
//! its 5000-ms literal at `0x080b1b38` precedes the independently linked next
//! function at `0x080b1b3c`. Decoding every ARM immediate branch finds exactly
//! four inbound direct calls, all unconditional plain `bl` at `0x0836bec8`,
//! `0x0836c088`, `0x0836c530`, and `0x0836cf00`; there are no predicated `bl`
//! forms. The body contains two unconditional direct `bl` calls.
//!
//! # Algorithm
//!
//! If the cached 16-bit ATA mode is not one, execute the command with the
//! fixed 5000-ms timeout and map its timeout result to `0x58`. When the
//! current 16-bit mode differs from the cached mode, wait for PIO write
//! readiness, write its low byte to `status_source + 0x18`, and cache it.
//! Deliberate deviations: the original's unused r2/r3 inputs to the execution
//! call are passed as zero because that callee ignores r2 and overwrites its
//! r3-derived status word before observing it.

use core::ptr;

use crate::drivers::ata_command_execute::{ata_command_execute, AtaCommandDevice, ATA_STATUS_TIMEOUT};
use crate::drivers::ata_pio_write_byte::ata_pio_write_byte;

pub const ATA_COMMAND_PREPARE_TIMEOUT_MS: u32 = 5_000;
pub const ATA_COMMAND_PREPARE_TIMEOUT: u32 = 0x58;
const ATA_COMMAND_MODE_OFFSET: usize = 0x0c;
const ATA_COMMAND_CACHED_MODE_OFFSET: usize = 0x4c;
const ATA_COMMAND_PIO_DATA_OFFSET: usize = 0x18;

/// Prepares an ATA command for its current 16-bit transfer mode.
///
/// `device` must point to an [`AtaCommandDevice`] with a valid target-width
/// `status_source` word; its status source must expose a writable byte at
/// `+0x18` whenever the mode changes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_command_prepare")]
#[inline(never)]
pub unsafe extern "C" fn ata_command_prepare(device: *mut AtaCommandDevice) -> u32 {
    let cached_mode = ptr::read_volatile(device.cast::<u8>().add(ATA_COMMAND_CACHED_MODE_OFFSET).cast::<u16>());
    let mode = ptr::read_volatile(device.cast::<u8>().add(ATA_COMMAND_MODE_OFFSET).cast::<u16>());

    if cached_mode != 1 && ata_command_execute(device, ATA_COMMAND_PREPARE_TIMEOUT_MS, 0, 0) == ATA_STATUS_TIMEOUT {
        return ATA_COMMAND_PREPARE_TIMEOUT;
    }

    if mode != cached_mode {
        let status_source = ptr::read_volatile(ptr::addr_of!((*device).status_source)) as usize as *mut u8;
        ata_pio_write_byte(status_source.add(ATA_COMMAND_PIO_DATA_OFFSET), mode as u8);
        ptr::write_volatile(device.cast::<u8>().add(ATA_COMMAND_CACHED_MODE_OFFSET).cast::<u16>(), mode);
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_command_execute::{AtaStatusRead, ATA_COMMAND_EXECUTE_TEST_LOCK, ATA_STATUS_READ};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::LazyLock;

    static STATUS_SOURCE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ATA_COMMAND_PREPARE, 0x1000).map(|pointer| pointer as usize)
    });
    static STATUS_READS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn complete_status(_source: *mut u8, status_out: *mut u32) -> u32 {
        STATUS_READS.fetch_add(1, Ordering::SeqCst);
        ptr::write_volatile(status_out, 0);
        0
    }

    unsafe fn device(source: usize, mode: u16, cached_mode: u16) -> AtaCommandDevice {
        let mut device = AtaCommandDevice {
            signature: 0,
            _reserved_04_38: [0; 14],
            status_source: source as u32,
            _reserved_40: 0,
            ready: 0,
            operation_count: 0,
        };
        ptr::write_volatile((&mut device as *mut AtaCommandDevice).cast::<u8>().add(ATA_COMMAND_MODE_OFFSET).cast::<u16>(), mode);
        ptr::write_volatile((&mut device as *mut AtaCommandDevice).cast::<u8>().add(ATA_COMMAND_CACHED_MODE_OFFSET).cast::<u16>(), cached_mode);
        device
    }

    #[test]
    fn changed_mode_executes_then_writes_low_byte_and_caches_mode() {
        let _execute_guard = ATA_COMMAND_EXECUTE_TEST_LOCK.lock();
        let Some(source) = *STATUS_SOURCE else {
            assert!(note_missing_u32_fixture("drivers::ata_command_prepare"));
            return;
        };
        unsafe { ATA_STATUS_READ = complete_status as AtaStatusRead; }
        STATUS_READS.store(0, Ordering::SeqCst);
        unsafe { ptr::write_volatile((source as *mut u8).add(ATA_COMMAND_PIO_DATA_OFFSET), 0xa5) };
        let mut command = unsafe { device(source, 0x0102, 0) };

        assert_eq!(unsafe { ata_command_prepare(&mut command) }, 0);
        assert_eq!(STATUS_READS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { ptr::read_volatile((source as *const u8).add(ATA_COMMAND_PIO_DATA_OFFSET)) }, 2);
        assert_eq!(unsafe { ptr::read_volatile((&command as *const AtaCommandDevice).cast::<u8>().add(ATA_COMMAND_CACHED_MODE_OFFSET).cast::<u16>()) }, 0x0102);
    }

    #[test]
    fn cached_mode_one_skips_execution_and_pio_write() {
        let _execute_guard = ATA_COMMAND_EXECUTE_TEST_LOCK.lock();
        let Some(source) = *STATUS_SOURCE else {
            assert!(note_missing_u32_fixture("drivers::ata_command_prepare"));
            return;
        };
        STATUS_READS.store(0, Ordering::SeqCst);
        unsafe { ptr::write_volatile((source as *mut u8).add(ATA_COMMAND_PIO_DATA_OFFSET), 0xa5) };
        let mut command = unsafe { device(source, 1, 1) };

        assert_eq!(unsafe { ata_command_prepare(&mut command) }, 0);
        assert_eq!(STATUS_READS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { ptr::read_volatile((source as *const u8).add(ATA_COMMAND_PIO_DATA_OFFSET)) }, 0xa5);
    }
}
