//! FAT directory-entry cluster extraction and classification.

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

/// FAT attribute bit marking a directory entry.
const ATTR_DIRECTORY: u8 = 0x10;

/// Lookup-result handle produced by the retailOS path resolver and consumed
/// by the directory predicates and the opendir/readdir family.
///
/// Only the fields this module's bodies inspect are named; the words between
/// the entry pointer and the directory flag keep their retailOS ARM layout
/// as anonymous words rather than invented names.
#[repr(C)]
pub struct FatDirentHandle {
    pub volume: *const FatVolume,
    pub entry: *const FatDirEntry,
    pub uninspected: [u32; 3],
    pub directory_flag: u32,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(FatDirentHandle, entry) == 0x04);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(FatDirentHandle, directory_flag) == 0x14);

/// FAT directory predicate — retailOS `FUN_082e2a48` at `0x082e2a48` (32
/// bytes; byte-verified: the `bx lr` at `0x082e2a64` ends the body and the
/// separately entered sibling `FUN_082e2a68` starts at `0x082e2a68`). 12
/// direct `bl` call sites, verified by decoding every ARM B/BL word in
/// `osos.dec`: 12 plain `bl`, no predicated calls or tail branches.
///
/// Returns 1 when the lookup handle refers to a directory: either the
/// handle's cached directory flag at +0x14 is nonzero, or the FAT short
/// directory entry it points at (+0x04) has the ATTR_DIRECTORY bit (0x10)
/// set in its attribute byte at entry +0x0b. The flag path short-circuits
/// without dereferencing the entry pointer. Callers include the opendir
/// paths `FUN_082e20d0`/`FUN_082e3080` (which require a nonzero result) and
/// the unlink path `FUN_082e47a0` (which rejects on one). Raw body:
///
/// ```text
/// 082e2a48:  ldr    r1, [r0, #20]
/// 082e2a4c:  cmp    r1, #0
/// 082e2a50:  ldreq  r0, [r0, #4]
/// 082e2a54:  ldrbeq r0, [r0, #11]
/// 082e2a58:  tsteq  r0, #16
/// 082e2a5c:  movne  r0, #1
/// 082e2a60:  moveq  r0, #0
/// 082e2a64:  bx     lr
/// ```
///
/// The raw body has no NULL guard and callers must supply valid pointers.
/// No deliberate deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fat_dirent_is_directory(handle: *const FatDirentHandle) -> u32 {
    if (*handle).directory_flag != 0 {
        return 1;
    }
    ((*(*handle).entry).attributes & ATTR_DIRECTORY != 0) as u32
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

    fn handle(entry: *const FatDirEntry, directory_flag: u32) -> FatDirentHandle {
        FatDirentHandle {
            volume: core::ptr::null(),
            entry,
            uninspected: [0; 3],
            directory_flag,
        }
    }

    #[test]
    fn directory_flag_short_circuits_without_touching_the_entry() {
        // A set cached flag answers 1 even with a dangling entry pointer:
        // the flag path never dereferences it.
        let lookup = handle(core::ptr::null(), 1);
        assert_eq!(unsafe { fat_dirent_is_directory(&lookup) }, 1);

        let lookup = handle(core::ptr::null(), u32::MAX);
        assert_eq!(unsafe { fat_dirent_is_directory(&lookup) }, 1);
    }

    #[test]
    fn unset_flag_consults_the_entry_attribute_bit() {
        // ATTR_DIRECTORY (0x10) set, alone or alongside other bits.
        for attributes in [0x10, 0x30, 0x1f] {
            let mut directory_entry = entry(0, 0);
            directory_entry.attributes = attributes;
            let lookup = handle(&directory_entry, 0);
            assert_eq!(
                unsafe { fat_dirent_is_directory(&lookup) },
                1,
                "attributes {attributes:#04x} carry the directory bit"
            );
        }
    }

    #[test]
    fn unset_flag_and_plain_attributes_answer_not_a_directory() {
        // Volume label (0x08), archive (0x20), LFN (0x0f): no 0x10 bit.
        for attributes in [0x00, 0x08, 0x20, 0x0f] {
            let mut directory_entry = entry(0, 0);
            directory_entry.attributes = attributes;
            let lookup = handle(&directory_entry, 0);
            assert_eq!(
                unsafe { fat_dirent_is_directory(&lookup) },
                0,
                "attributes {attributes:#04x} lack the directory bit"
            );
        }
    }

    #[test]
    fn directory_flag_wins_over_plain_attributes() {
        let mut directory_entry = entry(0, 0);
        directory_entry.attributes = 0x20;
        let lookup = handle(&directory_entry, 0xdead_beef);
        assert_eq!(unsafe { fat_dirent_is_directory(&lookup) }, 1);
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
