//! FAT cache-block to data-cluster conversion — `FUN_082e4358` @ 0x082e4358
//! (52 bytes; 3 plain `bl` call sites and 1 predicated `bleq` call site).
//!
//! The next separately entered function begins at 0x082e438c, confirming the
//! 52-byte extent. The raw ARM words load the exclusive cache-block limit at
//! +0x1d8 and inclusive first-data-block index at +0x74; an index in that
//! half-open range maps to `((index - first_data_block) >>
//! (cluster_shift_at_+0x1ce & 0xff)) + 2`. Other indices return zero.
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds direct calls at
//! 0x082e2970, 0x082e2a14 (`bleq`), 0x082e2b94, and 0x082e3384; there are no
//! direct tail branches. The `+2` result is the FAT data-cluster numbering
//! convention. Deliberate deviations: shifts of 32..255 explicitly return
//! zero, matching ARM register-LSR semantics while avoiding Rust's
//! oversized-shift panic.

use super::fat_dirent::FatVolume;

/// Target word index of the FAT volume's first data block (`+0x74`).
const FIRST_DATA_BLOCK_WORD: usize = 29;
/// Target halfword index of the FAT volume's blocks-per-cluster shift (`+0x1ce`).
const CLUSTER_BLOCK_SHIFT_HALFWORD: usize = 231;
/// Target word index of the FAT volume's exclusive cache-block limit (`+0x1d8`).
const CACHE_BLOCK_LIMIT_WORD: usize = 118;

/// Converts a bounded cache-block index to its FAT data-cluster number.
///
/// `volume` must point to a readable target-layout FAT volume through +0x1d8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fat_block_to_cluster(volume: *const FatVolume, block: u32) -> u32 {
    let volume_words = volume.cast::<u32>();
    let limit = *volume_words.add(CACHE_BLOCK_LIMIT_WORD);
    let first_block = *volume_words.add(FIRST_DATA_BLOCK_WORD);
    if block < limit && first_block <= block {
        let shift = (*volume.cast::<u16>().add(CLUSTER_BLOCK_SHIFT_HALFWORD) as u32) & 0xff;
        let cluster_offset = if shift < u32::BITS {
            (block - first_block) >> shift
        } else {
            0
        };
        cluster_offset + 2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(first_block: u32, limit: u32, cluster_shift: u16) -> [u32; CACHE_BLOCK_LIMIT_WORD + 1] {
        let mut volume = [0; CACHE_BLOCK_LIMIT_WORD + 1];
        volume[FIRST_DATA_BLOCK_WORD] = first_block;
        volume[CACHE_BLOCK_LIMIT_WORD] = limit;
        unsafe {
            volume.as_mut_ptr().cast::<u16>().add(CLUSTER_BLOCK_SHIFT_HALFWORD).write(cluster_shift);
        }
        volume
    }

    #[test]
    fn maps_only_the_half_open_data_block_range() {
        let volume = volume(0x1000, 0x1800, 9);
        for (block, expected) in [
            (0x0fff, 0),
            (0x1000, 2),
            (0x11ff, 2),
            (0x1200, 3),
            (0x17ff, 5),
            (0x1800, 0),
            (u32::MAX, 0),
        ] {
            assert_eq!(unsafe { fat_block_to_cluster(volume.as_ptr().cast(), block) }, expected, "{block:#010x}");
        }
    }

    #[test]
    fn uses_only_the_low_byte_of_the_shift_halfword() {
        let volume = volume(7, 8, 0x0100);
        assert_eq!(unsafe { fat_block_to_cluster(volume.as_ptr().cast(), 7) }, 2);
    }
}
