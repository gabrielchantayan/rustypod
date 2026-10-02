//! MOV sample-cache entry-array accessor.
//!
//! Original: `FUN_0827b3f0` at load address `0x0827b3f0`, true size
//! **8 bytes**, ending before the independent `push {r4, lr}` at
//! `0x0827b3f8`. Raw words: `e5900008` (`ldr r0, [r0, #8]`),
//! `e12fff1e` (`bx lr`). Whole-image aligned A32 decoding verifies two
//! inbound plain BLs (at `0x081c4600` and `0x081c77a8`), zero predicated
//! inbound BLs, and zero outgoing BLs.
//!
//! Returns the entry-array address in cache word two. The initializer at
//! `0x0827b31c` allocates and zeroes this array; callers at `0x081c45a0`
//! and `0x081c776c` populate and consume its 16-byte sample records.
//! No allocation, dereference of the returned address, or validation occurs.
//! Deliberate deviation: the result is a `u32` firmware address, not a
//! host-width pointer; word indexing preserves the target's four-byte fields.

/// Returns the stored sample-entry array address, including zero unchanged.
///
/// # Safety
/// `cache` must point to at least three readable, aligned `u32` words.
/// The firmware does not check NULL, bounds, or alignment.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_sample_cache_entries(cache: *const u32) -> u32 {
    unsafe { cache.add(2).read() }
}

#[cfg(test)]
mod tests {
    use super::mov_sample_cache_entries;

    #[test]
    fn returns_only_the_target_width_entry_address() {
        for address in [0, 1, 0x0800_0000, 0x2200_0000, 0x8000_0000, u32::MAX] {
            let cache = [0x1234_5678, !address, address, 0xdead_beef];
            let before = cache;
            assert_eq!(unsafe { mov_sample_cache_entries(cache.as_ptr()) }, address);
            assert_eq!(cache, before);
        }
    }

    #[test]
    fn observes_replaced_and_cleared_entry_arrays() {
        let mut cache = [0xaaaa_aaaa, 0xbbbb_bbbb, 0x0801_0000];
        assert_eq!(unsafe { mov_sample_cache_entries(cache.as_ptr()) }, 0x0801_0000);
        cache[2] = 0x0830_0000;
        assert_eq!(unsafe { mov_sample_cache_entries(cache.as_ptr()) }, 0x0830_0000);
        cache[2] = 0;
        assert_eq!(unsafe { mov_sample_cache_entries(cache.as_ptr()) }, 0);
    }
}
