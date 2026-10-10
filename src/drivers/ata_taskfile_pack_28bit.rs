//! Pack a non-extended ATA command for the taskfile programmer.
//!
//! Original: `FUN_0809114c` @ `0x0809114c`, 48 bytes, ending at the
//! separately entered `0x0809117c`. Raw words contain zero outgoing plain
//! or predicated BLs; incoming plain BLs are at `0x0836c618` and
//! `0x0836cfe8`, with no incoming predicated BLs.
//!
//! Clear byte 5, store the low sector-count byte at 6, and split the low
//! three LBA bytes into 7..=9. Byte 10 receives the low byte of
//! `(lba >> 24) | device_flags | 0x40`. Preserve bytes 0..=4 and the opcode
//! at 11. Read/write callers limit the count to 256, which encodes as zero.
//! No deliberate deviations: in particular, do not mask the LBA high byte
//! to a nibble or validate flags, counts, or addresses.

/// Fill bytes 5..=10 of a non-extended ATA command.
///
/// # Safety
/// `command` must point to at least eleven writable bytes; byte alignment
/// is sufficient.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ata_taskfile_pack_28bit(
    command: *mut u8,
    lba: u32,
    sector_count: u32,
    device_flags: u32,
) {
    *command.add(5) = 0;
    *command.add(6) = sector_count as u8;
    *command.add(7) = lba as u8;
    *command.add(8) = (lba >> 8) as u8;
    *command.add(9) = (lba >> 16) as u8;
    *command.add(10) = ((lba >> 24) | device_flags | 0x40) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_distinct_bytes_preserving_unused_fields_and_opcode() {
        for alignment in 0..4 {
            let mut storage = [0xa5; 20];
            let start = 1 + alignment;
            unsafe {
                ata_taskfile_pack_28bit(storage.as_mut_ptr().add(start),
                    0x1234_5678, 0x9abc, 0x80);
            }
            assert_eq!(&storage[start..start + 12],
                &[0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0, 0xbc, 0x78, 0x56, 0x34, 0xd2, 0xa5]);
            assert!(storage[..start].iter().all(|&byte| byte == 0xa5));
            assert!(storage[start + 12..].iter().all(|&byte| byte == 0xa5));
        }
    }

    #[test]
    fn count_truncates_and_all_high_lba_bits_participate_in_flags() {
        for count in [0, 1, 255, 256, 257, 65536, u32::MAX] {
            for high_byte in 0..=255u32 {
                for flags in [0, 0x10, 0x40, 0x80, 0xff, 0xffff_ff00, u32::MAX] {
                    let lba = (high_byte << 24) | 0x00ab_cdef;
                    let mut command = [0x5a; 12];
                    unsafe { ata_taskfile_pack_28bit(command.as_mut_ptr(), lba, count, flags); }
                    let bytes = lba.to_le_bytes();
                    assert_eq!(command, [0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0,
                        count as u8, bytes[0], bytes[1], bytes[2],
                        bytes[3] | flags as u8 | 0x40, 0x5a]);
                }
            }
        }
    }
}
