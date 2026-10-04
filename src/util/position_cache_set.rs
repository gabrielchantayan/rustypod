//! `position_cache_set` — `FUN_081dc578` @ `0x081dc578`.
//!
//! True extent: 104 bytes through `0x081dc5e0`, including the 366-byte
//! length literal at `0x081dc5dc`; instructions occupy 100 bytes. Whole-image
//! raw A32 decoding finds one plain inbound BL (`0x08299d08`) and one BLNE
//! (`0x0812733c`). The body has three plain BLs and no predicated BLs.
//!
//! If the unsigned key is outside the cached half-open interval, clear the
//! 366-byte table at +13, construct a resolution-one range state, and copy
//! its bucket bounds at words 7/8 into the cache's first two words. Store
//! the low byte of value at +13 + (key - start), whether hit or miss.
//! Deviations: reuse the existing range and memzero ports, replacing the
//! verified 0x08037dc8 -> 0x220002d4 IRAM mirror veneer. The range constructor
//! retains its retail configuration seam on target; host miss tests use key
//! zero, whose bounds are initialized without that unported configuration.

use crate::util::half_open_word_range_contains::half_open_word_range_contains;
use crate::util::range_state::{range_state_construct, RangeState};

/// # Safety
/// `cache` must be four-byte aligned and writable through byte 378. The
/// key must yield a table offset below 366 after retail range construction.
/// The configuration callee must satisfy the existing range-state contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn position_cache_set(cache: *mut u8, key: u32, value: u32) {
    let bounds = cache.cast::<u32>();
    if half_open_word_range_contains(bounds, &key) == 0 {
        crate::libc::memzero::memzero(cache.add(13), 366);
        let mut state = core::mem::MaybeUninit::<RangeState>::uninit();
        range_state_construct(state.as_mut_ptr(), &key, 1);
        // Only read constructor-initialized bucket words, not untouched fields.
        let words = state.as_ptr().cast::<u32>();
        let start = words.add(7).read();
        let end = words.add(8).read();
        bounds.write(start);
        bounds.add(1).write(end);
    }
    let offset = key.wrapping_sub(bounds.read());
    cache.add(13 + offset as usize).write(value as u8);
}

#[cfg(test)]
mod tests {
    use super::position_cache_set;

    #[test]
    fn hits_preserve_bounds_header_neighbors_and_other_entries() {
        for (start, end, keys) in [
            (10, 376, [10, 11, 375]),
            (0xffff_fe91, u32::MAX, [0xffff_fe91, 0xffff_fe92, 0xffff_fffe]),
        ] {
            for key in keys {
                for value in [0, 1, 2, 0xff, 0x1234_5680] {
                    let mut storage = [0xa5a5_a5a5u32; 97];
                    storage[1] = start;
                    storage[2] = end;
                    let mut expected = storage;
                    let expected_bytes = unsafe {
                        core::slice::from_raw_parts_mut(expected.as_mut_ptr().cast::<u8>(), 388)
                    };
                    expected_bytes[4 + 13 + (key - start) as usize] = value as u8;
                    unsafe { position_cache_set(storage.as_mut_ptr().add(1).cast(), key, value); }
                    assert_eq!(storage, expected);
                }
            }
        }
    }

    #[test]
    fn zero_key_misses_clear_exact_table_and_replace_bounds_before_store() {
        // Below start, at exclusive end, empty interval, and reversed interval.
        for (start, end) in [(1, 367), (0, 0), (8, 8), (9, 2)] {
            let mut storage = [0xa5a5_a5a5u32; 97];
            storage[1] = start;
            storage[2] = end;
            let mut expected = storage;
            expected[1] = 0;
            expected[2] = 0;
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(expected.as_mut_ptr().cast::<u8>(), 388)
            };
            bytes[17..383].fill(0);
            bytes[17] = 0x82;
            unsafe { position_cache_set(storage.as_mut_ptr().add(1).cast(), 0, 0x182); }
            assert_eq!(storage, expected);
        }
    }
}
