//! ATA command-block builders — the LBA packers of the setter family
//! @ 0x081211bc..0x08121488.
//!
//! The storage layer builds disk commands in a command block whose
//! fields are filled by a family of tiny setters (byte at +0x0c, flags
//! word at +0x10, sector-count byte at +0x15, command byte at +0x1a —
//! the read-flow @ 0x082798bc stores 0xC8 = READ DMA there, transfer
//! byte-count word at +0x30, ...). The two non-trivial members packed
//! here address the medium:
//!
//! - `ata_cmd_set_lba28` — `FUN_0812141c` @ 0x0812141c (84 bytes;
//!   7 call sites, binary-scanned, callers @ 0x082799c8..0x0827a800).
//!   Validates lba < 2^28 and drive <= 1, then stores the legacy
//!   taskfile block: LBA bytes 0..2 at +0x16/+0x17/+0x18 and the
//!   device/head byte at +0x19 = 0x40 (LBA bit) | drive<<4 | lba[24:27].
//!   Returns 0, or 0xffffffff on a range violation.
//! - `ata_cmd_set_lba48` — `FUN_0812134c` @ 0x0812134c (96 bytes;
//!   8 call sites, binary-scanned, callers @ 0x0827a2f4..0x0827b09c).
//!   Stores the 48-bit extended taskfile as three (current | previous
//!   << 8) register pairs — +0x4c = lba[0] | lba[3]<<8, +0x4e = lba[1]
//!   | lba[4]<<8, +0x50 = lba[2] | lba[5]<<8, where the 48-bit LBA is
//!   passed split as `lba_hi` (bits 32..47) and `lba_lo` (bits 0..31) —
//!   plus the sector-count pair at +0x52, the command byte at +0x1a and
//!   the device byte at +0x56 = (0x40 | drive<<4) & 0xff (stored as a
//!   halfword, high byte 0). No validation, no return value.
//!
//! Deviation: the original `ata_cmd_set_lba48` writes its four 16-bit
//! fields with `strh` (needs a 2-byte-aligned block); the port uses
//! `write_unaligned`, identical for every pointer the original
//! supported. Field order of stores is preserved only where observable
//! (it is not — all fields are distinct).

/// ata_cmd_set_lba28 — original: `FUN_0812141c` @ 0x0812141c (84 bytes).
///
/// Stores a 28-bit LBA + drive select into the command block's legacy
/// taskfile bytes (+0x16..+0x19). Fails with 0xffffffff if `lba` has
/// any of bits 28..31 set or `drive` is not 0/1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_lba28(cmd: *mut u8, lba: u32, drive: u32) -> u32 {
    if lba & 0xf000_0000 != 0 || drive > 1 {
        return 0xffff_ffff;
    }
    cmd.add(0x16).write(lba as u8);
    cmd.add(0x17).write((lba >> 8) as u8);
    cmd.add(0x18).write((lba >> 16) as u8);
    cmd.add(0x19).write((0x40 | (drive as u8) << 4) | (lba >> 24) as u8 & 0xf);
    0
}

/// ata_cmd_set_lba48 — original: `FUN_0812134c` @ 0x0812134c (96 bytes).
///
/// Stores a 48-bit LBA (`lba_hi` = bits 32..47, `lba_lo` = bits 0..31),
/// sector count, command byte and device select into the command
/// block's extended taskfile pairs (+0x4c..+0x56, +0x1a). Each 16-bit
/// pair holds (current-register byte | previous-register byte << 8).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_lba48(
    cmd: *mut u8,
    lba_hi: u32,
    lba_lo: u32,
    drive: u32,
    count: u32,
    command: u8,
) {
    let pair = |cur: u32, prev: u32| -> u16 { (cur & 0xff | prev << 8) as u16 };
    (cmd.add(0x4c) as *mut u16).write_unaligned(pair(lba_lo, lba_lo >> 24));
    (cmd.add(0x4e) as *mut u16).write_unaligned(pair(lba_lo >> 8, lba_hi));
    (cmd.add(0x50) as *mut u16).write_unaligned((lba_lo >> 16 & 0xff | lba_hi & 0xff00) as u16);
    (cmd.add(0x52) as *mut u16).write_unaligned(count as u16);
    cmd.add(0x1a).write(command);
    (cmd.add(0x56) as *mut u16).write_unaligned(((0x40 | drive << 4) & 0xff) as u16);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lba28_packs_bytes_and_device_head() {
        let mut cmd = [0u8; 0x60];
        let r = unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0x0abc_def1, 1) };
        assert_eq!(r, 0);
        assert_eq!(cmd[0x16], 0xf1);
        assert_eq!(cmd[0x17], 0xde);
        assert_eq!(cmd[0x18], 0xbc);
        assert_eq!(cmd[0x19], 0x40 | 0x10 | 0x0a, "LBA bit | drive 1 | lba[24:27]");
    }

    #[test]
    fn lba28_rejects_out_of_range_lba_and_drive() {
        let mut cmd = [0xaau8; 0x60];
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0x1000_0000, 0) }, 0xffff_ffff);
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0xffff_ffff, 0) }, 0xffff_ffff);
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0, 2) }, 0xffff_ffff);
        assert_eq!(cmd, [0xaau8; 0x60], "failed call must not touch the block");
    }

    #[test]
    fn lba28_boundary_values_pass() {
        let mut cmd = [0u8; 0x60];
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0x0fff_ffff, 0) }, 0);
        assert_eq!(cmd[0x16..0x1a], [0xff, 0xff, 0xff, 0x4f]);
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0, 0) }, 0);
        assert_eq!(cmd[0x16..0x1a], [0, 0, 0, 0x40]);
    }

    #[test]
    fn lba48_packs_current_previous_register_pairs() {
        let mut cmd = [0u8; 0x60];
        // 48-bit LBA 0x1122_33445566, count 0xBEEF, drive 1, cmd 0x25.
        unsafe { ata_cmd_set_lba48(cmd.as_mut_ptr(), 0x1122, 0x3344_5566, 1, 0xbeef, 0x25) };
        let rd = |o: usize| u16::from_le_bytes([cmd[o], cmd[o + 1]]);
        assert_eq!(rd(0x4c), 0x3366, "lba_low: cur=lba[0] prev=lba[3]");
        assert_eq!(rd(0x4e), 0x2255, "lba_mid: cur=lba[1] prev=lba[4]");
        assert_eq!(rd(0x50), 0x1144, "lba_high: cur=lba[2] prev=lba[5]");
        assert_eq!(rd(0x52), 0xbeef, "sector count pair");
        assert_eq!(cmd[0x1a], 0x25, "command byte");
        assert_eq!(rd(0x56), 0x0050, "device: 0x40 | drive<<4, high byte 0");
    }

    #[test]
    fn lba48_masks_drive_into_one_byte() {
        let mut cmd = [0u8; 0x60];
        unsafe { ata_cmd_set_lba48(cmd.as_mut_ptr(), 0, 0, 0xffff_ffff, 0, 0) };
        let dev = u16::from_le_bytes([cmd[0x56], cmd[0x57]]);
        // (0x40 | 0xfffffff0) & 0xff = 0xf0.
        assert_eq!(dev, 0x00f0);
    }

    #[test]
    fn lba48_zero_everything() {
        let mut cmd = [0xffu8; 0x60];
        unsafe { ata_cmd_set_lba48(cmd.as_mut_ptr(), 0, 0, 0, 0, 0) };
        assert_eq!(&cmd[0x4c..0x54], &[0u8; 8]);
        assert_eq!(cmd[0x1a], 0);
        assert_eq!(u16::from_le_bytes([cmd[0x56], cmd[0x57]]), 0x40);
        // Bytes between the two written regions stay untouched.
        assert_eq!(cmd[0x54], 0xff);
        assert_eq!(cmd[0x55], 0xff);
        assert_eq!(cmd[0x1b], 0xff);
    }
}
