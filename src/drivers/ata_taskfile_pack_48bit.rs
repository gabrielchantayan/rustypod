//! Pack the extended ATA command consumed by `ata_taskfile_program_48bit`.
//!
//! Original: `FUN_0809117c` @ `0x0809117c`, 72 bytes, ending at the
//! separately entered `0x080911c4`. Raw ARM words contain zero outgoing
//! plain or predicated BLs. Two incoming plain BLs occur at `0x0836c5dc`
//! and `0x0836cfac`; there are no incoming predicated BLs.
//!
//! Clear bytes 0, 3, 4 and 5; split the low 16 sector-count bits between
//! bytes 1 and 6 and the 32-bit LBA between bytes 2, 9, 8 and 7. Store the
//! low byte of `device_flags | 0x40` at byte 10. Byte 11 (the opcode) and
//! all surrounding bytes remain untouched. Callers select READ/WRITE EXT
//! opcodes and the existing programmer emits these bytes in two passes.
//! No deliberate deviations, validation, or conversion of a zero count:
//! 65536 sectors naturally encodes as zero, just as in the original.

/// Fill bytes 0..=10 of an extended ATA command, leaving its opcode intact.
///
/// # Safety
/// `command` must point to at least eleven writable bytes. No alignment
/// beyond byte alignment is required.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ata_taskfile_pack_48bit(
    command: *mut u8,
    lba: u32,
    sector_count: u32,
    device_flags: u32,
) {
    *command.add(5) = 0;
    *command = 0;
    *command.add(3) = 0;
    *command.add(4) = 0;
    *command.add(1) = (sector_count >> 8) as u8;
    *command.add(6) = sector_count as u8;
    *command.add(2) = (lba >> 24) as u8;
    *command.add(9) = (lba >> 16) as u8;
    *command.add(8) = (lba >> 8) as u8;
    *command.add(7) = lba as u8;
    *command.add(10) = (device_flags | 0x40) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_distinct_bytes_without_touching_opcode_or_surroundings() {
        for alignment in 0..4 {
            let mut storage = [0xa5; 20];
            let start = 1 + alignment;
            unsafe {
                ata_taskfile_pack_48bit(storage.as_mut_ptr().add(start),
                    0x1234_5678, 0x9abc, 0x10);
            }
            assert_eq!(&storage[start..start + 12],
                &[0, 0x9a, 0x12, 0, 0, 0, 0xbc, 0x78, 0x56, 0x34, 0x50, 0xa5]);
            assert!(storage[..start].iter().all(|&byte| byte == 0xa5));
            assert!(storage[start + 12..].iter().all(|&byte| byte == 0xa5));
        }
    }

    #[test]
    fn count_wraps_at_sixteen_bits_and_flags_keep_all_low_bits() {
        for count in [0, 1, 255, 256, 65535, 65536, 65537, u32::MAX] {
            for flags in [0, 0x10, 0x40, 0x80, 0xff, 0xffff_ff00, u32::MAX] {
                for lba in [0, 0x8000_0000, u32::MAX] {
                    let mut command = [0xa5; 12];
                    unsafe { ata_taskfile_pack_48bit(command.as_mut_ptr(), lba, count, flags); }
                    let count_bytes = (count as u16).to_be_bytes();
                    let lba_bytes = lba.to_be_bytes();
                    assert_eq!(command, [0, count_bytes[0], lba_bytes[0], 0, 0, 0,
                        count_bytes[1], lba_bytes[3], lba_bytes[2], lba_bytes[1],
                        flags as u8 | 0x40, 0xa5]);
                }
            }
        }
    }
}
