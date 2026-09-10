//! FAT data-cluster to cache-block-index conversion.
//!
//! `fat_cluster_to_block_index` is retailOS `FUN_082e01cc` at `0x082e01cc`.
//! Its code extent is 56 bytes (`0x082e01cc..0x082e0200`); the following
//! word at `0x082e0204` is its literal-pool offset and the next separately
//! entered function begins at `0x082e0208`. Decoding every ARM B/BL word in
//! `osos.dec` finds 11 plain `bl` callers and no predicated `bl` forms, plus
//! two direct tail branches (one unconditional `b`, one `bne`).
//!
//! For a FAT data cluster (cluster >= 2), the function adds
//! `(cluster - 2) << (volume cluster-shift field & 0xff)` to the volume's
//! first-data-block index. It returns that wrapped candidate only when it is
//! strictly below the volume cache-block limit; reserved clusters and a
//! candidate at or above the limit return zero. The raw body has no NULL
//! guard after the cluster >= 2 test. No deliberate deviations.

use super::fat_dirent::FatVolume;

/// Target word index of the FAT volume's first data block (`+0x74`).
const FIRST_DATA_BLOCK_WORD: usize = 29;
/// Target halfword index of the FAT volume's blocks-per-cluster shift (`+0x1ce`).
const CLUSTER_BLOCK_SHIFT_HALFWORD: usize = 231;
/// Target word index of the FAT volume's exclusive cache-block limit (`+0x1d8`).
const CACHE_BLOCK_LIMIT_WORD: usize = 118;

#[inline(always)]
const fn arm_lsl_u32(value: u32, shift: u32) -> u32 {
    if shift < 32 { value << shift } else { 0 }
}

/// Converts a FAT data-cluster number to its bounded cache-block index.
///
/// Original: `FUN_082e01cc` at `0x082e01cc`, 56 bytes, 11 plain `bl` callers
/// (binary-verified; two additional tail branches target the entry).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fat_cluster_to_block_index(volume: *const FatVolume, cluster: u32) -> u32 {
    if cluster < 2 {
        return 0;
    }

    let volume_words = volume.cast::<u32>();
    let cluster_shift = (*volume.cast::<u16>().add(CLUSTER_BLOCK_SHIFT_HALFWORD) as u32) & 0xff;
    let candidate = (*volume_words.add(FIRST_DATA_BLOCK_WORD))
        .wrapping_add(arm_lsl_u32(cluster - 2, cluster_shift));

    if candidate < *volume_words.add(CACHE_BLOCK_LIMIT_WORD) {
        candidate
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER_SHIFT_WORD: usize = 115;

    fn volume(first_data_block: u32, cluster_shift: u16, block_limit: u32) -> [u32; 119] {
        let mut words = [0; 119];
        words[FIRST_DATA_BLOCK_WORD] = first_data_block;
        words[CLUSTER_SHIFT_WORD] = (cluster_shift as u32) << 16;
        words[CACHE_BLOCK_LIMIT_WORD] = block_limit;
        words
    }

    #[test]
    fn reserved_clusters_return_zero_without_dereferencing_volume() {
        for cluster in [0, 1] {
            assert_eq!(
                unsafe { fat_cluster_to_block_index(core::ptr::null(), cluster) },
                0,
                "reserved cluster {cluster}"
            );
        }
    }

    #[test]
    fn maps_data_clusters_with_the_volume_shift() {
        let words = volume(100, 3, 200);
        let volume = words.as_ptr().cast::<FatVolume>();

        assert_eq!(unsafe { fat_cluster_to_block_index(volume, 2) }, 100);
        assert_eq!(unsafe { fat_cluster_to_block_index(volume, 3) }, 108);
        assert_eq!(unsafe { fat_cluster_to_block_index(volume, 14) }, 196);
    }

    #[test]
    fn rejects_the_exclusive_limit_and_above() {
        let words = volume(100, 3, 108);
        let volume = words.as_ptr().cast::<FatVolume>();

        assert_eq!(unsafe { fat_cluster_to_block_index(volume, 2) }, 100);
        assert_eq!(unsafe { fat_cluster_to_block_index(volume, 3) }, 0);
        assert_eq!(unsafe { fat_cluster_to_block_index(volume, 4) }, 0);
    }

    #[test]
    fn wraps_the_addition_and_zeroes_large_arm_shift_counts() {
        let wrapping_words = volume(u32::MAX, 1, 2);
        let wrapping_volume = wrapping_words.as_ptr().cast::<FatVolume>();
        assert_eq!(unsafe { fat_cluster_to_block_index(wrapping_volume, 3) }, 1);

        let large_shift_words = volume(7, 32, 8);
        let large_shift_volume = large_shift_words.as_ptr().cast::<FatVolume>();
        assert_eq!(unsafe { fat_cluster_to_block_index(large_shift_volume, 3) }, 7);
    }
}
