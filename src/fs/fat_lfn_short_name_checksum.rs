//! FAT long-file-name checksum — `FUN_082e0194` @ 0x082e0194 (56 bytes;
//! three inbound plain `bl` call sites, zero predicated `bl` call sites).
//!
//! The function rotates an eight-bit accumulator right by one bit before
//! adding each byte of the 11-byte FAT short name. This is the checksum stored
//! in every associated long-file-name directory entry. The retail loop masks
//! its byte index and accumulator after every iteration; the fixed 11-byte
//! Rust loop has the same observable result. No deliberate deviations.

/// Computes the FAT long-file-name checksum for an 11-byte short directory name.
///
/// Original: `FUN_082e0194` @ 0x082e0194 (56 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fat_lfn_short_name_checksum(short_name: *const u8) -> u32 {
    let mut checksum = 0u8;
    let mut index = 0usize;
    while index < 11 {
        let byte = unsafe { short_name.add(index).read() };
        checksum = checksum.rotate_right(1).wrapping_add(byte);
        index += 1;
    }
    u32::from(checksum)
}

#[cfg(test)]
mod tests {
    use super::fat_lfn_short_name_checksum;

    fn reference(short_name: &[u8; 11]) -> u8 {
        short_name.iter().fold(0u8, |checksum, &byte| {
            ((checksum & 1) << 7).wrapping_add(checksum >> 1).wrapping_add(byte)
        })
    }

    #[test]
    fn matches_standard_fat_lfn_checksum_vector() {
        let short_name = *b"FOO     TXT";
        assert_eq!(unsafe { fat_lfn_short_name_checksum(short_name.as_ptr()) }, 0x65);
    }

    #[test]
    fn includes_spaces_nuls_and_high_bit_bytes() {
        let short_name = [0x80, 0, b' ', 0xff, 0, b'A', b' ', 1, 0xfe, 0, b'Z'];
        assert_eq!(
            unsafe { fat_lfn_short_name_checksum(short_name.as_ptr()) },
            u32::from(reference(&short_name)),
        );
    }

    #[test]
    fn treats_exactly_eleven_bytes_as_the_input() {
        let bytes = [b'A'; 12];
        assert_eq!(
            unsafe { fat_lfn_short_name_checksum(bytes.as_ptr()) },
            u32::from(reference((&bytes[..11]).try_into().unwrap())),
        );
    }
}
