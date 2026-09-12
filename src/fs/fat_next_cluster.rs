//! `fat_next_cluster` — original: `FUN_082e0378` @ `0x082e0378` (124 bytes,
//! `0x082e0378..0x082e03f0`; the next separately entered function starts at
//! `0x082e03f4`). Decoding every ARM `B`/`BL` word in `osos.dec` finds exactly
//! eight direct callers: all are unconditional plain `bl` at `0x082b2074`,
//! `0x082e0258`, `0x082e031c`, `0x082e1920`, `0x082e2ba0`, `0x082e5f60`,
//! `0x082e66d0`, and `0x082e6774`; no predicated form reaches this entry.
//!
//! # Algorithm
//!
//! Reads the raw next-cluster value through unported `FUN_082e0cac`. A failed
//! read returns zero. FAT12 (format 3) rejects `0xff8..=0xfff`; FAT32 (format
//! 8) retains only the low 28 bits and rejects exactly `0x0fff_ffff`; every
//! other format rejects `0xfff7..=0xffff`. Other values return unchanged.
//!
//! # Deliberate deviations
//!
//! None. `FUN_082e0cac` remains a resident boundary; its shared host seam is
//! used only to test the unchanged call ABI.

use super::cache_position_value::read_cache_position_value;
use super::fat_dirent::FatVolume;

const FAT12_RESERVED_START: u32 = 0x0ff8;
const FAT12_RESERVED_COUNT: u32 = 8;
const FAT32_VALUE_MASK: u32 = 0x0fff_ffff;
const FAT16_RESERVED_START: u32 = 0xfff7;
const FAT16_RESERVED_COUNT: u32 = 9;

/// Reads and validates a FAT cluster's next-cluster value.
///
/// Original: `FUN_082e0378` at `0x082e0378`, 124 bytes, with eight verified
/// unconditional direct `bl` callers. `volume` is forwarded without a NULL
/// guard to `FUN_082e0cac`; it is read for the format only after that helper
/// reports success.
///
/// # Safety
///
/// `volume` must meet the resident reader's requirements and, after a
/// successful read, point to a readable [`FatVolume`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fat_next_cluster")]
#[inline(never)]
pub unsafe extern "C" fn fat_next_cluster(volume: *mut FatVolume, cluster: u32) -> u32 {
    let mut next = 0;
    if read_cache_position_value(volume.cast(), cluster, &mut next) == 0 {
        return 0;
    }

    match (*volume).format {
        3 => {
            if next.wrapping_sub(FAT12_RESERVED_START) < FAT12_RESERVED_COUNT {
                0
            } else {
                next
            }
        }
        8 => {
            let next = next & FAT32_VALUE_MASK;
            if next == FAT32_VALUE_MASK { 0 } else { next }
        }
        _ => {
            if next.wrapping_sub(FAT16_RESERVED_START) < FAT16_RESERVED_COUNT {
                0
            } else {
                next
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cache_position_value::{
        replace_read_cache_position_value, ReadCachePositionValue, CACHE_POSITION_VALUE_TEST_LOCK,
    };

    static mut READER_STATUS: u32 = 0;
    static mut READER_VALUE: u32 = 0;
    static mut READER_CACHE: *mut u8 = core::ptr::null_mut();
    static mut READER_CLUSTER: u32 = 0;

    unsafe extern "C" fn record_reader(cache: *mut u8, cluster: u32, value: *mut u32) -> u32 {
        READER_CACHE = cache;
        READER_CLUSTER = cluster;
        if READER_STATUS != 0 {
            value.write(READER_VALUE);
        }
        READER_STATUS
    }

    struct ReaderReset(ReadCachePositionValue);

    impl Drop for ReaderReset {
        fn drop(&mut self) {
            unsafe {
                replace_read_cache_position_value(self.0);
            }
        }
    }

    unsafe fn install_reader(status: u32, value: u32) -> ReaderReset {
        READER_STATUS = status;
        READER_VALUE = value;
        READER_CACHE = core::ptr::null_mut();
        READER_CLUSTER = 0;
        ReaderReset(replace_read_cache_position_value(record_reader))
    }

    fn volume(format: u16) -> FatVolume {
        FatVolume { header_words: [0; 27], format }
    }

    #[test]
    fn failure_returns_before_reading_the_volume() {
        let _guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let _reset = unsafe { install_reader(0, 0xffff_ffff) };

        assert_eq!(unsafe { fat_next_cluster(core::ptr::null_mut(), 0x1234) }, 0);
        unsafe {
            assert!(READER_CACHE.is_null());
            assert_eq!(READER_CLUSTER, 0x1234);
        }
    }

    #[test]
    fn fat12_preserves_valid_values_and_rejects_eoc_range() {
        let _guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let mut filesystem = volume(3);

        for (entry, expected) in [(0x0ff7, 0x0ff7), (0x0ff8, 0), (0x0fff, 0), (0x1234, 0x1234)] {
            let _reset = unsafe { install_reader(1, entry) };
            assert_eq!(unsafe { fat_next_cluster(&mut filesystem, 7) }, expected);
            unsafe {
                assert_eq!(READER_CACHE, (&mut filesystem as *mut FatVolume).cast());
                assert_eq!(READER_CLUSTER, 7);
            }
        }
    }

    #[test]
    fn fat32_masks_high_nibble_and_rejects_masked_sentinel() {
        let _guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let mut filesystem = volume(8);

        let _reset = unsafe { install_reader(1, 0xf123_4567) };
        assert_eq!(unsafe { fat_next_cluster(&mut filesystem, 2) }, 0x0123_4567);
        drop(_reset);

        let _reset = unsafe { install_reader(1, 0xffff_ffff) };
        assert_eq!(unsafe { fat_next_cluster(&mut filesystem, 2) }, 0);
    }

    #[test]
    fn non_fat12_non_fat32_formats_reject_fat16_reserved_values() {
        let _guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let mut filesystem = volume(4);

        for (entry, expected) in [(0xfff6, 0xfff6), (0xfff7, 0), (0xffff, 0), (0x1_0000, 0x1_0000)] {
            let _reset = unsafe { install_reader(1, entry) };
            assert_eq!(unsafe { fat_next_cluster(&mut filesystem, 42) }, expected);
        }
    }
}
