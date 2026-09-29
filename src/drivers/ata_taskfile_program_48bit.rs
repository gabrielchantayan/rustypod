//! ATA 48-bit task-file programming.
//!
//! Port: [`ata_taskfile_program_48bit`] — original: `FUN_0836c764` @
//! `0x0836c764` (208 bytes, `0x0836c764..0x0836c837`; 204 instruction bytes
//! plus the `"Ide1"` literal at `0x0836c834`). The next real function begins
//! at `0x0836c838`. Decoding every ARM branch immediate in `osos.dec` finds
//! exactly **2 inbound unconditional plain `bl` calls** at `0x0836c5f8` and
//! `0x0836cfc8`, with no predicated calls or direct tail branches. The body
//! makes 12 plain `bl` calls to [`ata_pio_write_byte`].
//!
//! # Algorithm
//!
//! Validate a ready `Ide1` ATA device, then program the high and low halves of
//! a 48-bit task file. Command bytes `+0..+4` fill task-file offsets
//! `+0x4..+0x14`; bytes `+5..+9` overwrite those same registers with their low
//! halves; bytes `+10` and `+11` select the feature and command registers.
//! Returns 7 on validation failure and zero on success. There are no deliberate
//! deviations: the shared PIO primitive preserves readiness polling and
//! volatile byte stores.

use crate::drivers::ata_command_execute::AtaCommandDevice;
use crate::drivers::ata_command_submit_wait::{ATA_DEVICE_NOT_READY, ATA_DEVICE_SIGNATURE};
use crate::drivers::ata_pio_write_byte::ata_pio_write_byte;

const ATA_FEATURE_OFFSET: usize = 0x18;
const ATA_SECTOR_COUNT_OFFSET: usize = 0x04;
const ATA_SECTOR_NUMBER_OFFSET: usize = 0x08;
const ATA_CYLINDER_LOW_OFFSET: usize = 0x0c;
const ATA_CYLINDER_HIGH_OFFSET: usize = 0x10;
const ATA_DRIVE_HEAD_OFFSET: usize = 0x14;
const ATA_COMMAND_OFFSET: usize = 0x1c;

/// Programs the high and low task-file halves for a 48-bit ATA command.
///
/// # Safety
///
/// `device` and `command` must be valid whenever validation succeeds; the
/// target-width `device + 0x3c` word must name writable PIO byte registers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_taskfile_program_48bit")]
#[inline(never)]
pub unsafe extern "C" fn ata_taskfile_program_48bit(
    device: *mut AtaCommandDevice,
    command: *const u8,
) -> u32 {
    if device.is_null() || (*device).signature != ATA_DEVICE_SIGNATURE || (*device).ready == 0 {
        return ATA_DEVICE_NOT_READY;
    }

    let taskfile = (*device).status_source as *mut u8;
    ata_pio_write_byte(taskfile.add(ATA_SECTOR_COUNT_OFFSET), *command.add(0));
    ata_pio_write_byte(taskfile.add(ATA_SECTOR_NUMBER_OFFSET), *command.add(1));
    ata_pio_write_byte(taskfile.add(ATA_CYLINDER_LOW_OFFSET), *command.add(2));
    ata_pio_write_byte(taskfile.add(ATA_CYLINDER_HIGH_OFFSET), *command.add(3));
    ata_pio_write_byte(taskfile.add(ATA_DRIVE_HEAD_OFFSET), *command.add(4));
    ata_pio_write_byte(taskfile.add(ATA_SECTOR_COUNT_OFFSET), *command.add(5));
    ata_pio_write_byte(taskfile.add(ATA_SECTOR_NUMBER_OFFSET), *command.add(6));
    ata_pio_write_byte(taskfile.add(ATA_CYLINDER_LOW_OFFSET), *command.add(7));
    ata_pio_write_byte(taskfile.add(ATA_CYLINDER_HIGH_OFFSET), *command.add(8));
    ata_pio_write_byte(taskfile.add(ATA_DRIVE_HEAD_OFFSET), *command.add(9));
    ata_pio_write_byte(taskfile.add(ATA_FEATURE_OFFSET), *command.add(10));
    ata_pio_write_byte(taskfile.add(ATA_COMMAND_OFFSET), *command.add(11));
    0
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    #[test]
    fn rejects_invalid_or_unready_devices_before_reading_command() {
        let mut device = AtaCommandDevice {
            signature: ATA_DEVICE_SIGNATURE,
            _reserved_04_38: [0; 14],
            status_source: 0,
            _reserved_40: 0,
            ready: 1,
            operation_count: 0,
        };

        assert_eq!(unsafe { ata_taskfile_program_48bit(ptr::null_mut(), ptr::null()) }, ATA_DEVICE_NOT_READY);
        device.signature = 0;
        assert_eq!(unsafe { ata_taskfile_program_48bit(&mut device, ptr::null()) }, ATA_DEVICE_NOT_READY);
        device.signature = ATA_DEVICE_SIGNATURE;
        device.ready = 0;
        assert_eq!(unsafe { ata_taskfile_program_48bit(&mut device, ptr::null()) }, ATA_DEVICE_NOT_READY);
    }

    #[test]
    fn programs_low_halves_after_high_halves_and_feature_command() {
        let Some(taskfile) = crate::testing::try_map_u32_slab(
            crate::testing::hints::ATA_TASKFILE_PROGRAM_48BIT,
            0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("drivers::ata_taskfile_program_48bit"));
            return;
        };
        unsafe { taskfile.write_bytes(0xa5, 0x1000) };
        let command = [0x10, 0x11, 0x12, 0x13, 0x14, 0x20, 0x21, 0x22, 0x23, 0x24, 0x30, 0x31];
        let mut device = AtaCommandDevice {
            signature: ATA_DEVICE_SIGNATURE,
            _reserved_04_38: [0; 14],
            status_source: taskfile as usize as u32,
            _reserved_40: 0,
            ready: 1,
            operation_count: 0,
        };

        assert_eq!(unsafe { ata_taskfile_program_48bit(&mut device, command.as_ptr()) }, 0);
        let taskfile = unsafe { core::slice::from_raw_parts(taskfile, 0x20) };
        assert_eq!(taskfile[ATA_SECTOR_COUNT_OFFSET], 0x20);
        assert_eq!(taskfile[ATA_SECTOR_NUMBER_OFFSET], 0x21);
        assert_eq!(taskfile[ATA_CYLINDER_LOW_OFFSET], 0x22);
        assert_eq!(taskfile[ATA_CYLINDER_HIGH_OFFSET], 0x23);
        assert_eq!(taskfile[ATA_DRIVE_HEAD_OFFSET], 0x24);
        assert_eq!(taskfile[ATA_FEATURE_OFFSET], 0x30);
        assert_eq!(taskfile[ATA_COMMAND_OFFSET], 0x31);
        assert_eq!(taskfile[0], 0xa5);
    }
}
