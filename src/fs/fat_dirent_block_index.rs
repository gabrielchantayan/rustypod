//! FAT directory-entry cache-block lookup.

use super::fat_cluster_to_block::fat_cluster_to_block_index;
use super::fat_dirent::{fat_dirent_is_directory, fat_dirent_start_cluster, FatDirentHandle};

/// Returns the cache-block index associated with a resolved FAT directory entry.
///
/// Original: `FUN_082e1448` at `0x082e1448`, 60 bytes (`0x082e1448..0x082e1484`),
/// with two plain `bl` call sites and no predicated `bl` calls, verified from
/// `osos.dec`. Directories return the lookup handle's word at +0x08 without
/// inspecting either pointer. Other entries obtain their start cluster and map
/// it to a bounded cache-block index through the volume. The final stock `b`
/// to `fat_cluster_to_block_index` is represented as an ordinary Rust call;
/// this is an ABI-preserving deliberate deviation from the tail branch.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fat_dirent_block_index(handle: *const FatDirentHandle) -> u32 {
    if fat_dirent_is_directory(handle) != 0 {
        return (*handle).uninspected[0];
    }

    let volume = (*handle).volume;
    let cluster = fat_dirent_start_cluster(volume, (*handle).entry);
    fat_cluster_to_block_index(volume, cluster)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::fat_dirent::{FatDirEntry, FatVolume};

    const FIRST_DATA_BLOCK_WORD: usize = 29;
    const CLUSTER_SHIFT_WORD: usize = 115;
    const CACHE_BLOCK_LIMIT_WORD: usize = 118;

    fn entry(high: u16, low: u16) -> FatDirEntry {
        FatDirEntry {
            name: [0; 11], attributes: 0, nt_reserved: 0, creation_time_tenths: 0,
            creation_time: 0, creation_date: 0, last_access_date: 0,
            first_cluster_high: high, write_time: 0, write_date: 0,
            first_cluster_low: low, file_size: 0,
        }
    }

    fn volume(format: u16, first_data_block: u32, shift: u16, limit: u32) -> [u32; 119] {
        let mut words = [0; 119];
        words[27] = format as u32;
        words[FIRST_DATA_BLOCK_WORD] = first_data_block;
        words[CLUSTER_SHIFT_WORD] = (shift as u32) << 16;
        words[CACHE_BLOCK_LIMIT_WORD] = limit;
        words
    }

    #[test]
    fn directory_uses_its_cached_block_without_dereferencing_pointers() {
        let handle = FatDirentHandle {
            volume: core::ptr::null(), entry: core::ptr::null(),
            uninspected: [0x1234_5678, 0, 0], directory_flag: u32::MAX,
        };
        assert_eq!(unsafe { fat_dirent_block_index(&handle) }, 0x1234_5678);
    }

    #[test]
    fn regular_fat16_entry_maps_its_low_cluster() {
        let words = volume(0, 100, 3, 200);
        let directory_entry = entry(0xbeef, 3);
        let handle = FatDirentHandle {
            volume: words.as_ptr().cast::<FatVolume>(), entry: &directory_entry,
            uninspected: [0, 0, 0], directory_flag: 0,
        };
        assert_eq!(unsafe { fat_dirent_block_index(&handle) }, 108);
    }

    #[test]
    fn regular_fat32_entry_uses_the_full_cluster_and_preserves_bounds_check() {
        let words = volume(8, 100, 0, 103);
        let directory_entry = entry(0, 5);
        let handle = FatDirentHandle {
            volume: words.as_ptr().cast::<FatVolume>(), entry: &directory_entry,
            uninspected: [0, 0, 0], directory_flag: 0,
        };
        assert_eq!(unsafe { fat_dirent_block_index(&handle) }, 0);
    }
}
