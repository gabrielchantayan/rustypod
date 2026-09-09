//! FAT directory-entry cluster extraction.

/// Filesystem context prefix through the on-target format field at +0x6c.
///
/// The preceding contents are not needed by this helper.  It is represented
/// as target words so `format` retains its retailOS ARM layout on host and
/// device without making up names for fields the body does not inspect.
#[repr(C)]
pub struct FatVolume {
    pub header_words: [u32; 27],
    pub format: u16,
}

/// A 32-byte FAT short directory entry.
#[repr(C)]
pub struct FatDirEntry {
    pub name: [u8; 11],
    pub attributes: u8,
    pub nt_reserved: u8,
    pub creation_time_tenths: u8,
    pub creation_time: u16,
    pub creation_date: u16,
    pub last_access_date: u16,
    pub first_cluster_high: u16,
    pub write_time: u16,
    pub write_date: u16,
    pub first_cluster_low: u16,
    pub file_size: u32,
}

/// FAT directory-entry start-cluster reader — retailOS `FUN_082e1378` at
/// `0x082e1378` (24 bytes; 16 direct `bl` call sites, verified by decoding
/// every ARM B/BL word in `osos.dec`: 16 plain `bl`, no predicated calls or
/// tail branches).
///
/// Reads the low 16-bit first-cluster field from a FAT short directory entry.
/// When the volume format is exactly 8 (the cluster's FAT32 mode), combines
/// the entry's high and low fields into the full 32-bit start cluster. Other
/// formats return only the low field. The raw body has no NULL guard and
/// callers must supply valid pointers. No deliberate deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fat_dirent_start_cluster(
    volume: *const FatVolume,
    entry: *const FatDirEntry,
) -> u32 {
    let low = (*entry).first_cluster_low as u32;
    if (*volume).format == 8 {
        ((*entry).first_cluster_high as u32) << 16 | low
    } else {
        low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(high: u16, low: u16) -> FatDirEntry {
        FatDirEntry {
            name: [0; 11],
            attributes: 0,
            nt_reserved: 0,
            creation_time_tenths: 0,
            creation_time: 0,
            creation_date: 0,
            last_access_date: 0,
            first_cluster_high: high,
            write_time: 0,
            write_date: 0,
            first_cluster_low: low,
            file_size: 0,
        }
    }

    fn volume(format: u16) -> FatVolume {
        FatVolume {
            header_words: [0; 27],
            format,
        }
    }

    #[test]
    fn non_fat32_formats_discard_the_high_cluster_word() {
        let directory_entry = entry(0xbeef, 0x0123);

        for format in [0, 3, 4, 7, 9, u16::MAX] {
            let filesystem = volume(format);
            assert_eq!(
                unsafe { fat_dirent_start_cluster(&filesystem, &directory_entry) },
                0x0123,
                "format {format} must use the low word only"
            );
        }
    }

    #[test]
    fn fat32_format_concatenates_high_and_low_cluster_words() {
        let filesystem = volume(8);
        let directory_entry = entry(0xabcd, 0x1234);

        assert_eq!(
            unsafe { fat_dirent_start_cluster(&filesystem, &directory_entry) },
            0xabcd_1234
        );
    }
}
