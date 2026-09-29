//! `ata_set_features` — original: `FUN_0836ccbc` @ `0x0836ccbc`.
//!
//! Raw `osos.dec` establishes a **112-byte** extent at
//! `0x0836ccbc..0x0836cd2b`: 108 instruction bytes ending in `pop
//! {r2,r3,ip,pc}`, followed by the `"Ide1"` literal at `0x0836cd28`.
//! `0x0836cd2c` begins the next real function. The sole caller contains two
//! unconditional plain `bl` instructions at `0x080ce138` and `0x080ce144`;
//! there are no predicated direct call sites. This body makes one unconditional
//! plain `bl`, to `ata_command_submit_wait`, at `0x0836cd20`.
//!
//! # Algorithm
//!
//! Validate the ready `Ide1` ATA device, build an ATA SET FEATURES (`0xef`)
//! command descriptor with sector count 3, caller-supplied sector number, and
//! the device's low feature byte at `+0x0c`, then submit it synchronously.
//! There are no deliberate deviations.

use core::ptr;

use crate::drivers::ata_command_execute::AtaCommandDevice;
use crate::drivers::ata_command_submit_wait::{ata_command_submit_wait, ATA_DEVICE_NOT_READY, ATA_DEVICE_SIGNATURE};

const ATA_COMMAND_SECTOR_COUNT_OFFSET: usize = 5;
const ATA_COMMAND_SECTOR_NUMBER_OFFSET: usize = 6;
const ATA_COMMAND_FEATURE_OFFSET: usize = 10;
const ATA_COMMAND_CODE_OFFSET: usize = 11;
const ATA_SET_FEATURES_SECTOR_COUNT: u8 = 3;
const ATA_SET_FEATURES_COMMAND: u8 = 0xef;
const ATA_DEVICE_FEATURE_OFFSET: usize = 0x0c;
#[inline(always)]
fn ata_set_features_command(feature: u8, sector_number: u8) -> [u8; 12] {
    let mut command = [0u8; 12];
    command[ATA_COMMAND_SECTOR_COUNT_OFFSET] = ATA_SET_FEATURES_SECTOR_COUNT;
    command[ATA_COMMAND_SECTOR_NUMBER_OFFSET] = sector_number;
    command[ATA_COMMAND_FEATURE_OFFSET] = feature;
    command[ATA_COMMAND_CODE_OFFSET] = ATA_SET_FEATURES_COMMAND;
    command
}

/// ata_set_features — original: `FUN_0836ccbc` @ `0x0836ccbc` (112-byte raw
/// extent: 108 instruction bytes and the trailing `"Ide1"` literal).
///
/// Two inbound unconditional plain `bl` call sites are verified at
/// `0x080ce138` and `0x080ce144`; the body makes one plain `bl` to
/// `ata_command_submit_wait`. Rejects an invalid or unready ATA device with 7,
/// otherwise submits SET FEATURES with sector count 3 and the low byte from
/// device `+0x0c` as its feature selector.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_set_features")]
#[inline(never)]
pub unsafe extern "C" fn ata_set_features(device: *mut AtaCommandDevice, sector_number: u8) -> u32 {
    if device.is_null()
        || ptr::read_volatile(ptr::addr_of!((*device).signature)) != ATA_DEVICE_SIGNATURE
        || ptr::read_volatile(ptr::addr_of!((*device).ready)) == 0
    {
        return ATA_DEVICE_NOT_READY;
    }

    let feature = ptr::read_volatile((device as *const u8).add(ATA_DEVICE_FEATURE_OFFSET));
    let mut command = ata_set_features_command(feature, sector_number);
    ata_command_submit_wait(device, command.as_mut_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_uses_low_feature_byte_and_sector_number() {
        let command = ata_set_features_command(0xa5, 0x7c);
        assert_eq!(command, [0, 0, 0, 0, 0, 3, 0x7c, 0, 0, 0, 0xa5, 0xef]);
    }

    #[test]
    fn command_accepts_sector_number_boundaries() {
        for sector_number in [0, 0xff] {
            let command = ata_set_features_command(0x12, sector_number);
            assert_eq!(command[ATA_COMMAND_SECTOR_NUMBER_OFFSET], sector_number);
            assert_eq!(command[ATA_COMMAND_FEATURE_OFFSET], 0x12);
            assert_eq!(command[ATA_COMMAND_CODE_OFFSET], ATA_SET_FEATURES_COMMAND);
        }
    }

    #[test]
    fn rejects_null_invalid_and_unready_devices_before_submission() {
        let mut device = AtaCommandDevice {
            signature: 0,
            _reserved_04_38: [0; 14],
            status_source: 0,
            _reserved_40: 0,
            ready: 1,
            operation_count: 0,
        };
        assert_eq!(unsafe { ata_set_features(ptr::null_mut(), 0) }, ATA_DEVICE_NOT_READY);
        assert_eq!(unsafe { ata_set_features(&mut device, 0) }, ATA_DEVICE_NOT_READY);

        device.signature = ATA_DEVICE_SIGNATURE;
        device.ready = 0;
        assert_eq!(unsafe { ata_set_features(&mut device, 0xff) }, ATA_DEVICE_NOT_READY);
    }
}
