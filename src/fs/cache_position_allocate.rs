//! `allocate_cache_position` — original: `FUN_082e026c` @ `0x082e026c`
//! (152 bytes, `0x082e026c..0x082e0300`; the next separately linked function
//! begins at `0x082e0304`). Raw ARM decoding finds four direct calls, all
//! unconditional plain `bl`, and no predicated `bl` calls.
//!
//! # Algorithm
//!
//! Normalizes the requested position to two when it is below two or outside
//! the cache's primary range. It searches `[position, cache+0x1ec)`, then
//! `[2, position)`, then `[cache+0x1ec, cache+0x7c)` for a zero position. A
//! found position is initialized through the format-specific default writer.
//! On a successful write, a nonzero cache word at `+0x1f4` is decremented and
//! the position is returned; failure returns zero.
//!
//! # Deliberate deviations
//!
//! The original preserves incoming `r3` across each zero-position search and
//! forwards it as the packed-value argument to `FUN_082e3bcc`. Rust makes that
//! ABI dependency explicit as `packed_value`; the incoming `r2` is dead.

use super::cache_position_default_value::cache_position_write_default_value;
use super::zero_cache_position::find_zero_cache_position;

const PRIMARY_END_OFFSET: usize = 0x1ec;
const FALLBACK_END_OFFSET: usize = 0x7c;
const OUTSTANDING_COUNT_OFFSET: usize = 0x1f4;

/// Finds and initializes an available cache position.
///
/// Original: `FUN_082e026c` at `0x082e026c`, 152 bytes, with four verified
/// unconditional direct `bl` instructions. `cache` must have aligned u32
/// fields at offsets `+0x7c`, `+0x1ec`, and `+0x1f4`; as in retailOS, no NULL
/// or bounds guards precede those reads and writes.
///
/// # Safety
///
/// `cache` must satisfy the resident cache-reader and cache-writer contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.allocate_cache_position")]
#[inline(never)]
pub unsafe extern "C" fn allocate_cache_position(
    cache: *mut u8,
    requested_position: u32,
    _unused: u32,
    packed_value: u32,
) -> u32 {
    let primary_end = unsafe { cache.add(PRIMARY_END_OFFSET).cast::<u32>().read() };
    let position = if requested_position < 2 || primary_end <= requested_position {
        2
    } else {
        requested_position
    };

    let found = unsafe { find_zero_cache_position(cache, position, primary_end) };
    let found = if found != 0 {
        found
    } else {
        let found = unsafe { find_zero_cache_position(cache, 2, position) };
        if found != 0 {
            found
        } else {
            let fallback_end = unsafe { cache.add(FALLBACK_END_OFFSET).cast::<u32>().read() };
            unsafe { find_zero_cache_position(cache, primary_end, fallback_end) }
        }
    };

    if found == 0 || unsafe { cache_position_write_default_value(cache, found, 0, packed_value) } == 0 {
        return 0;
    }

    let outstanding = unsafe { cache.add(OUTSTANDING_COUNT_OFFSET).cast::<u32>() };
    if unsafe { outstanding.read() } != 0 {
        unsafe { outstanding.write(outstanding.read().wrapping_sub(1)) };
    }
    found
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::cache_position_default_value::{
        replace_write_cache_position_value, WriteCachePositionValue, CACHE_POSITION_VALUE_WRITE_TEST_LOCK,
    };
    use super::super::cache_position_value::{
        replace_read_cache_position_value, ReadCachePositionValue, CACHE_POSITION_VALUE_TEST_LOCK,
    };

    #[repr(C, align(4))]
    struct CacheFixture {
        prefix: [u8; FALLBACK_END_OFFSET],
        fallback_end: u32,
        middle: [u8; PRIMARY_END_OFFSET - FALLBACK_END_OFFSET - 4],
        primary_end: u32,
        tail: [u8; OUTSTANDING_COUNT_OFFSET - PRIMARY_END_OFFSET - 4],
        outstanding: u32,
    }

    static mut READ_VALUES: [u32; 8] = [0; 8];
    static mut READ_CALLS: [u32; 8] = [0; 8];
    static mut READ_COUNT: usize = 0;
    static mut WRITTEN: Option<(u32, u32, u32)> = None;
    static mut WRITE_RESULT: u32 = 0;

    unsafe extern "C" fn record_read(_cache: *mut u8, position: u32, value: *mut u32) -> u32 {
        READ_CALLS[READ_COUNT] = position;
        value.write(READ_VALUES[READ_COUNT]);
        READ_COUNT += 1;
        1
    }

    unsafe extern "C" fn record_write(
        _cache: *mut u8,
        position: u32,
        value: u32,
        packed_value: u32,
    ) -> u32 {
        WRITTEN = Some((position, value, packed_value));
        WRITE_RESULT
    }

    unsafe fn install(read_values: &[u32], write_result: u32) -> (ReadCachePositionValue, WriteCachePositionValue) {
        READ_VALUES = [0; 8];
        READ_VALUES[..read_values.len()].copy_from_slice(read_values);
        READ_CALLS = [0; 8];
        READ_COUNT = 0;
        WRITTEN = None;
        WRITE_RESULT = write_result;
        (
            replace_read_cache_position_value(record_read),
            replace_write_cache_position_value(record_write),
        )
    }

    fn fixture(primary_end: u32, fallback_end: u32, outstanding: u32) -> CacheFixture {
        CacheFixture {
            prefix: [0; FALLBACK_END_OFFSET],
            fallback_end,
            middle: [0; PRIMARY_END_OFFSET - FALLBACK_END_OFFSET - 4],
            primary_end,
            tail: [0; OUTSTANDING_COUNT_OFFSET - PRIMARY_END_OFFSET - 4],
            outstanding,
        }
    }

    #[test]
    fn clamps_low_request_writes_default_and_decrements_outstanding() {
        let _read_guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let _write_guard = CACHE_POSITION_VALUE_WRITE_TEST_LOCK.lock();
        let previous = unsafe { install(&[7, 0], 1) };
        let mut cache = fixture(5, 9, 3);

        let result = unsafe { allocate_cache_position((&mut cache as *mut CacheFixture).cast(), 1, 0, 0x1234_5678) };

        unsafe {
            replace_read_cache_position_value(previous.0);
            replace_write_cache_position_value(previous.1);
            assert_eq!(READ_COUNT, 2);
            assert_eq!(&READ_CALLS[..READ_COUNT], &[2, 3]);
            assert_eq!(WRITTEN, Some((3, 0xffff, 0x1234_5678)));
        }
        assert_eq!(result, 3);
        assert_eq!(cache.outstanding, 2);
    }

    #[test]
    fn searches_wraparound_then_fallback_and_keeps_count_when_zero() {
        let _read_guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let _write_guard = CACHE_POSITION_VALUE_WRITE_TEST_LOCK.lock();
        let previous = unsafe { install(&[9, 9, 9, 0], 1) };
        let mut cache = fixture(5, 8, 0);

        let result = unsafe { allocate_cache_position((&mut cache as *mut CacheFixture).cast(), 4, 0, 0xa5a5_5a5a) };

        unsafe {
            replace_read_cache_position_value(previous.0);
            replace_write_cache_position_value(previous.1);
            assert_eq!(READ_COUNT, 4);
            assert_eq!(&READ_CALLS[..READ_COUNT], &[4, 2, 3, 5]);
            assert_eq!(WRITTEN, Some((5, 0xffff, 0xa5a5_5a5a)));
        }
        assert_eq!(result, 5);
        assert_eq!(cache.outstanding, 0);
    }

    #[test]
    fn writer_failure_returns_zero_without_decrementing() {
        let _read_guard = CACHE_POSITION_VALUE_TEST_LOCK.lock();
        let _write_guard = CACHE_POSITION_VALUE_WRITE_TEST_LOCK.lock();
        let previous = unsafe { install(&[0], 0) };
        let mut cache = fixture(5, 8, 2);

        let result = unsafe { allocate_cache_position((&mut cache as *mut CacheFixture).cast(), 2, 0, 0) };

        unsafe {
            replace_read_cache_position_value(previous.0);
            replace_write_cache_position_value(previous.1);
            assert_eq!(WRITTEN, Some((2, 0xffff, 0)));
        }
        assert_eq!(result, 0);
        assert_eq!(cache.outstanding, 2);
    }
}
