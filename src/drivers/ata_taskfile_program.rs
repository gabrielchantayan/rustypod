//! ATA task-file programming.
//!
//! Port: [`ata_taskfile_program`] — original: `FUN_0836c6c8` @ `0x0836c6c8`.
//! Raw `osos.dec` has **152 instruction bytes** at
//! `0x0836c6c8..0x0836c75f`; `0x0836c760` is the `"Ide1"` literal and the
//! next function begins at `0x0836c764`. Decoding every ARM branch immediate
//! finds exactly **4 inbound unconditional plain `bl` calls** at
//! `0x0836beec`, `0x0836c0d8`, `0x0836c638`, and `0x0836d008`, with no
//! predicated calls or direct tail branches. The body makes seven plain `bl`
//! calls to [`ata_pio_write_byte`].
//!
//! # Algorithm
//!
//! Validate an `Ide1` ATA device. When `flags` is zero, additionally require
//! its `+0x44` ready word. Write command bytes `+10`, `+5..+9`, and `+11` to
//! task-file offsets `+0x18`, `+0x4..+0x14`, and `+0x1c`, respectively.
//! Returns 7 on validation failure and otherwise zero. There are no deliberate
//! behavioral deviations; the shared PIO primitive supplies the original
//! readiness wait and volatile byte store.

use crate::drivers::ata_command_execute::AtaCommandDevice;
use crate::drivers::ata_command_submit_wait::{ATA_DEVICE_NOT_READY, ATA_DEVICE_SIGNATURE};
use crate::drivers::ata_pio_write_byte::ata_pio_write_byte;

const ATA_TASKFILE_OFFSET: usize = 0x3c;
const ATA_COMMAND_FEATURE_OFFSET: usize = 0x18;
const ATA_COMMAND_SECTOR_COUNT_OFFSET: usize = 0x04;
const ATA_COMMAND_SECTOR_NUMBER_OFFSET: usize = 0x08;
const ATA_COMMAND_CYLINDER_LOW_OFFSET: usize = 0x0c;
const ATA_COMMAND_CYLINDER_HIGH_OFFSET: usize = 0x10;
const ATA_COMMAND_DRIVE_HEAD_OFFSET: usize = 0x14;
const ATA_COMMAND_COMMAND_OFFSET: usize = 0x1c;

/// Programs an ATA command descriptor into the device's task-file registers.
///
/// # Safety
///
/// `device` and `command` must be valid whenever the validation succeeds; the
/// device's target-width `+0x3c` task-file word must name writable PIO bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_taskfile_program")]
#[inline(never)]
pub unsafe extern "C" fn ata_taskfile_program(
    device: *mut AtaCommandDevice,
    command: *const u8,
    flags: u32,
) -> u32 {
    if device.is_null() || (*device).signature != ATA_DEVICE_SIGNATURE || (flags == 0 && (*device).ready == 0) {
        return ATA_DEVICE_NOT_READY;
    }

    let taskfile = (*device).status_source as *mut u8;
    ata_pio_write_byte(taskfile.add(ATA_COMMAND_FEATURE_OFFSET), *command.add(10));
    ata_pio_write_byte(taskfile.add(ATA_COMMAND_SECTOR_COUNT_OFFSET), *command.add(5));
    ata_pio_write_byte(taskfile.add(ATA_COMMAND_SECTOR_NUMBER_OFFSET), *command.add(6));
    ata_pio_write_byte(taskfile.add(ATA_COMMAND_CYLINDER_LOW_OFFSET), *command.add(7));
    ata_pio_write_byte(taskfile.add(ATA_COMMAND_CYLINDER_HIGH_OFFSET), *command.add(8));
    ata_pio_write_byte(taskfile.add(ATA_COMMAND_DRIVE_HEAD_OFFSET), *command.add(9));
    ata_pio_write_byte(taskfile.add(ATA_COMMAND_COMMAND_OFFSET), *command.add(11));
    0
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    #[test]
    fn rejects_invalid_devices_before_reading_command() {
        let mut device = AtaCommandDevice {
            signature: ATA_DEVICE_SIGNATURE,
            _reserved_04_38: [0; 14],
            status_source: 0,
            _reserved_40: 0,
            ready: 1,
            operation_count: 0,
        };

        assert_eq!(unsafe { ata_taskfile_program(ptr::null_mut(), ptr::null(), 0) }, ATA_DEVICE_NOT_READY);
        device.signature = 0;
        assert_eq!(unsafe { ata_taskfile_program(&mut device, ptr::null(), 1) }, ATA_DEVICE_NOT_READY);
        device.signature = ATA_DEVICE_SIGNATURE;
        device.ready = 0;
        assert_eq!(unsafe { ata_taskfile_program(&mut device, ptr::null(), 0) }, ATA_DEVICE_NOT_READY);
    }

    #[test]
    fn flags_bypass_ready_gate_and_program_sparse_command_bytes() {
        let Some(taskfile) = crate::testing::try_map_u32_slab(
            crate::testing::hints::ATA_TASKFILE_PROGRAM,
            0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("drivers::ata_taskfile_program"));
            return;
        };
        unsafe { taskfile.write_bytes(0xa5, 0x1000) };
        let mut command = [0u8; 12];
        command[5..12].copy_from_slice(&[0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]);
        let mut device = AtaCommandDevice {
            signature: ATA_DEVICE_SIGNATURE,
            _reserved_04_38: [0; 14],
            status_source: taskfile as usize as u32,
            _reserved_40: 0,
            ready: 0,
            operation_count: 0,
        };

        assert_eq!(unsafe { ata_taskfile_program(&mut device, command.as_ptr(), 1) }, 0);
        let taskfile = unsafe { core::slice::from_raw_parts(taskfile, 0x20) };
        assert_eq!(taskfile[4], 0x15);
        assert_eq!(taskfile[8..=0x14], [0x16, 0xa5, 0xa5, 0xa5, 0x17, 0xa5, 0xa5, 0xa5, 0x18, 0xa5, 0xa5, 0xa5, 0x19]);
        assert_eq!(taskfile[0x18], 0x1a);
        assert_eq!(taskfile[0x1c], 0x1b);
    }
}
