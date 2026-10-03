//! MOV sample-cache loaded-state setter.
//!
//! Original: `FUN_0827b3e0` at load address `0x0827b3e0`, true size
//! **8 bytes**, ending at the independent cursor accessor at `0x0827b3e8`.
//! Raw words: `e5c01018` (`strb r1, [r0, #0x18]`), `e12fff1e` (`bx lr`).
//! Whole-image aligned A32 decoding verifies two inbound plain BLs at
//! `0x081c5c24` and `0x081c7934`, zero predicated inbound BLs, and zero
//! outbound plain or predicated BLs.
//!
//! Stores the low byte of the supplied loaded state at cache +0x18 without
//! changing any other field. The seek path clears it before resetting the
//! cursor; the sample-loading path sets it after populating cache entries.
//! The status query at 0x0827b3f8 distinguishes zero from nonzero states.
//! Deliberate deviations: none; a byte pointer keeps target offsets exact
//! on hosts, and a u32 argument models the original r1 truncation.

/// Sets the sample-cache loaded byte without normalizing nonzero values.
///
/// # Safety
/// `cache` must belong to a writable allocation of at least 0x19 bytes.
/// The firmware does not check NULL or bounds; byte alignment suffices.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_sample_cache_set_loaded(cache: *mut u8, loaded: u32) {
    unsafe { cache.add(0x18).write(loaded as u8) }
}

#[cfg(test)]
mod tests {
    use super::mov_sample_cache_set_loaded;

    #[test]
    fn stores_low_byte_and_preserves_adjacent_fields_at_every_alignment() {
        for offset in 0..4 {
            for loaded in [0, 1, 2, 0x80, 0xff, 0x100, 0x1234_5678, u32::MAX] {
                let mut storage = [0xa5; 0x24];
                let mut expected = storage;
                expected[offset + 0x18] = loaded as u8;
                unsafe { mov_sample_cache_set_loaded(storage.as_mut_ptr().add(offset), loaded) };
                assert_eq!(storage, expected);
            }
        }
    }

    #[test]
    fn replaces_and_clears_previously_loaded_state() {
        let mut cache = [0x5a; 0x19];
        for loaded in [1, 0x80, 0, 0xff, 0x100] {
            unsafe { mov_sample_cache_set_loaded(cache.as_mut_ptr(), loaded) };
            assert_eq!(cache[0x18], loaded as u8);
            assert_eq!(&cache[..0x18], &[0x5a; 0x18]);
        }
    }
}
