//! `fat_cluster_clear` — retailOS `FUN_082e03f4` at `0x082e03f4`.
//!
//! Raw `osos.dec` words establish the 88-byte extent
//! `0x082e03f4..0x082e044b`; `push {r4-r8,lr}` at `0x082e044c` starts the
//! next real function. Whole-image ARM decoding finds three inbound plain
//! `bl` calls at `0x082e1910`, `0x082e326c`, and `0x082e32fc`, zero predicated
//! calls, and one direct plain `bl` to the shared cache-position writer at
//! `0x082e0414`.
//!
//! # Algorithm
//!
//! Clusters below two are reserved and ignored. All other clusters are written
//! as zero through the common cache-position writer. When that succeeds, a
//! cluster within the inclusive cache-position interval updates its upper
//! bound, and a nonzero dirty counter at `cache + 0x1f4` is incremented.
//!
//! # Deliberate deviations
//!
//! The common writer at `0x082e39f4` remains a resident boundary. This port
//! uses its established target dispatch and host recording seam; it does not
//! infer the writer's format-specific I/O behavior.

use core::ptr::{read, write};

use super::cache_position_default_value::write_cache_position_value;

const CACHE_POSITION_MIN_OFFSET: usize = 0x1ec;
const CACHE_POSITION_MAX_OFFSET: usize = 0x1f0;
const CACHE_DIRTY_COUNT_OFFSET: usize = 0x1f4;

/// Clears one allocatable FAT cluster through the shared cache-position writer.
///
/// Original: `FUN_082e03f4` at `0x082e03f4`, 88 bytes, with three plain `bl`
/// callers and no predicated forms. The raw body overwrites `unused_value` with
/// zero before calling the writer, while passing `packed_value` through in r3.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fat_cluster_clear(
    cache: *mut u8,
    cluster: u32,
    _unused_value: u32,
    packed_value: u32,
) {
    if cluster < 2 {
        return;
    }

    if write_cache_position_value(cache, cluster, 0, packed_value) == 0 {
        return;
    }

    let minimum = read(cache.add(CACHE_POSITION_MIN_OFFSET).cast::<u32>());
    let maximum = read(cache.add(CACHE_POSITION_MAX_OFFSET).cast::<u32>());
    if minimum <= cluster && cluster <= maximum {
        write(cache.add(CACHE_POSITION_MAX_OFFSET).cast::<u32>(), cluster);
    }

    let dirty_count = cache.add(CACHE_DIRTY_COUNT_OFFSET).cast::<u32>();
    let dirty_count_value = read(dirty_count);
    if dirty_count_value != 0 {
        write(dirty_count, dirty_count_value.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cache_position_default_value::{
        replace_write_cache_position_value, WriteCachePositionValue,
        CACHE_POSITION_VALUE_WRITE_TEST_LOCK,
    };

    static mut WRITER_RESULT: u32 = 0;
    static mut WRITER_CALLS: u32 = 0;
    static mut WRITER_ARGUMENTS: (u32, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn recording_writer(
        cache: *mut u8,
        cluster: u32,
        value: u32,
        packed_value: u32,
    ) -> u32 {
        WRITER_CALLS += 1;
        WRITER_ARGUMENTS = (cluster, value, packed_value);
        assert!(!cache.is_null());
        WRITER_RESULT
    }

    struct WriterReset(WriteCachePositionValue);

    impl Drop for WriterReset {
        fn drop(&mut self) {
            unsafe { replace_write_cache_position_value(self.0); }
        }
    }

    fn write_word(cache: &mut [u8], offset: usize, value: u32) {
        unsafe { write(cache.as_mut_ptr().add(offset).cast::<u32>(), value); }
    }

    fn read_word(cache: &[u8], offset: usize) -> u32 {
        unsafe { read(cache.as_ptr().add(offset).cast::<u32>()) }
    }

    #[test]
    fn leaves_reserved_clusters_and_cache_state_untouched() {
        let _lock = CACHE_POSITION_VALUE_WRITE_TEST_LOCK.lock();
        let previous = unsafe { replace_write_cache_position_value(recording_writer) };
        let _reset = WriterReset(previous);
        let mut cache = [0u8; 0x1f8];
        write_word(&mut cache, CACHE_POSITION_MAX_OFFSET, 9);
        write_word(&mut cache, CACHE_DIRTY_COUNT_OFFSET, 5);
        unsafe { WRITER_CALLS = 0; fat_cluster_clear(cache.as_mut_ptr(), 1, 0xdeadbeef, 7); }
        assert_eq!(unsafe { WRITER_CALLS }, 0);
        assert_eq!(read_word(&cache, CACHE_POSITION_MAX_OFFSET), 9);
        assert_eq!(read_word(&cache, CACHE_DIRTY_COUNT_OFFSET), 5);
    }

    #[test]
    fn updates_range_and_dirty_count_only_after_a_successful_clear() {
        let _lock = CACHE_POSITION_VALUE_WRITE_TEST_LOCK.lock();
        let previous = unsafe { replace_write_cache_position_value(recording_writer) };
        let _reset = WriterReset(previous);
        let mut cache = [0u8; 0x1f8];
        write_word(&mut cache, CACHE_POSITION_MIN_OFFSET, 3);
        write_word(&mut cache, CACHE_POSITION_MAX_OFFSET, 8);
        write_word(&mut cache, CACHE_DIRTY_COUNT_OFFSET, u32::MAX);
        unsafe {
            WRITER_RESULT = 1;
            WRITER_CALLS = 0;
            fat_cluster_clear(cache.as_mut_ptr(), 6, 0x12345678, 0xaabbccdd);
        }
        assert_eq!(unsafe { WRITER_CALLS }, 1);
        assert_eq!(unsafe { WRITER_ARGUMENTS }, (6, 0, 0xaabbccdd));
        assert_eq!(read_word(&cache, CACHE_POSITION_MAX_OFFSET), 6);
        assert_eq!(read_word(&cache, CACHE_DIRTY_COUNT_OFFSET), 0);

        unsafe { WRITER_RESULT = 0; fat_cluster_clear(cache.as_mut_ptr(), 4, 0, 0); }
        assert_eq!(read_word(&cache, CACHE_POSITION_MAX_OFFSET), 6);
        assert_eq!(read_word(&cache, CACHE_DIRTY_COUNT_OFFSET), 0);
    }

    #[test]
    fn preserves_range_bound_when_cluster_is_outside_it() {
        let _lock = CACHE_POSITION_VALUE_WRITE_TEST_LOCK.lock();
        let previous = unsafe { replace_write_cache_position_value(recording_writer) };
        let _reset = WriterReset(previous);
        let mut cache = [0u8; 0x1f8];
        write_word(&mut cache, CACHE_POSITION_MIN_OFFSET, 5);
        write_word(&mut cache, CACHE_POSITION_MAX_OFFSET, 8);
        write_word(&mut cache, CACHE_DIRTY_COUNT_OFFSET, 1);
        unsafe { WRITER_RESULT = 1; fat_cluster_clear(cache.as_mut_ptr(), 9, 0, 0); }
        assert_eq!(read_word(&cache, CACHE_POSITION_MAX_OFFSET), 8);
        assert_eq!(read_word(&cache, CACHE_DIRTY_COUNT_OFFSET), 2);
    }
}
