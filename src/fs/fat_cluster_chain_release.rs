//! `fat_cluster_chain_release` — retailOS `FUN_082e18f8` at `0x082e18f8`
//! (60 bytes, `0x082e18f8..0x082e1930`; the next separately entered function
//! starts at `0x082e1934`). Decoding every ARM `B`/`BL` word in `osos.dec`
//! finds four direct callers: three plain `bl` at `0x082e0240`, `0x082e4294`,
//! and `0x082e64b0`, plus one predicated `blne` at `0x082e6790`.
//!
//! # Algorithm
//!
//! Starting at `start_cluster`, reads each next cluster before writing the
//! caller-provided replacement value to the current one through the common
//! cache-position writer. It stops after reading the successor of cluster zero
//! or after releasing a cluster whose successor is zero. The raw ABI preserves
//! incoming `r2` and `r3` for every writer call; Ghidra's two-argument
//! prototype is therefore incomplete.
//!
//! # Deliberate deviations
//!
//! `FUN_082e39f4`, the common cache-position writer, remains a resident
//! boundary. This port reuses its existing shared target call and host seam;
//! it does not infer the writer's cache-update behavior.

use super::cache_position_default_value::write_cache_position_value;
use super::fat_dirent::FatVolume;
use super::fat_next_cluster::fat_next_cluster;

/// Releases each cluster in a FAT chain through the common cache-position writer.
///
/// Original: `FUN_082e18f8` at `0x082e18f8`, 60 bytes, with four verified
/// direct `bl` callers (three plain and one `blne`). `replacement_value` and
/// `packed_value` are the raw incoming `r2` and `r3`, preserved for the writer.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fat_cluster_chain_release")]
#[inline(never)]
pub unsafe extern "C" fn fat_cluster_chain_release(
    volume: *mut FatVolume,
    start_cluster: u32,
    replacement_value: u32,
    packed_value: u32,
) {
    let mut cluster = start_cluster;
    loop {
        let next_cluster = fat_next_cluster(volume, cluster);
        if cluster == 0 {
            return;
        }
        write_cache_position_value(volume.cast(), cluster, replacement_value, packed_value);
        cluster = next_cluster;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cache_position_default_value::{
        replace_write_cache_position_value, WriteCachePositionValue,
        CACHE_POSITION_VALUE_WRITE_TEST_LOCK,
    };
    use super::super::cache_position_value::{
        replace_read_cache_position_value, ReadCachePositionValue, CACHE_POSITION_VALUE_TEST_LOCK,
    };

    static mut WRITES: [(u32, u32, u32); 4] = [(0, 0, 0); 4];
    static mut WRITE_COUNT: usize = 0;

    unsafe extern "C" fn chain_reader(_cache: *mut u8, cluster: u32, value: *mut u32) -> u32 {
        *value = match cluster {
            2 => 3,
            3 => 0,
            _ => 0,
        };
        1
    }

    unsafe extern "C" fn recording_writer(
        _cache: *mut u8,
        cluster: u32,
        replacement_value: u32,
        packed_value: u32,
    ) -> u32 {
        WRITES[WRITE_COUNT] = (cluster, replacement_value, packed_value);
        WRITE_COUNT += 1;
        1
    }

    struct ReaderReset(ReadCachePositionValue);
    impl Drop for ReaderReset {
        fn drop(&mut self) {
            unsafe { replace_read_cache_position_value(self.0); }
        }
    }

    struct WriterReset(WriteCachePositionValue);
    impl Drop for WriterReset {
        fn drop(&mut self) {
            unsafe { replace_write_cache_position_value(self.0); }
        }
    }

    #[test]
    fn releases_every_cluster_after_reading_its_successor() {
        let _reader_guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let _writer_guard = CACHE_POSITION_VALUE_WRITE_TEST_LOCK.lock();
        unsafe {
            WRITE_COUNT = 0;
            let _reader_reset = ReaderReset(replace_read_cache_position_value(chain_reader));
            let _writer_reset = WriterReset(replace_write_cache_position_value(recording_writer));
            let mut volume = FatVolume { header_words: [0; 27], format: 3 };
            fat_cluster_chain_release(&mut volume, 2, 0xfeed_beef, 0x0123_4567);
            assert_eq!(WRITE_COUNT, 2);
            assert_eq!(WRITES[..2], [(2, 0xfeed_beef, 0x0123_4567), (3, 0xfeed_beef, 0x0123_4567)]);
        }
    }

    #[test]
    fn zero_start_reads_but_does_not_write() {
        let _reader_guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let _writer_guard = CACHE_POSITION_VALUE_WRITE_TEST_LOCK.lock();
        unsafe {
            WRITE_COUNT = 0;
            let _reader_reset = ReaderReset(replace_read_cache_position_value(chain_reader));
            let _writer_reset = WriterReset(replace_write_cache_position_value(recording_writer));
            let mut volume = FatVolume { header_words: [0; 27], format: 3 };
            fat_cluster_chain_release(&mut volume, 0, 0, 0);
            assert_eq!(WRITE_COUNT, 0);
        }
    }
}
