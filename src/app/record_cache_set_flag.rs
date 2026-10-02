//! Byte flag update for the singleton record cache.

/// record_cache_set_flag — original: `FUN_08284388` @ `0x08284388`.
/// True size: 8 bytes, ending before the independent push at `0x08284390`.
/// Whole-image ARM decoding verifies two inbound plain BLs (`0x081c5c4c`,
/// `0x081c7b68`), zero predicated BLs, and no outbound calls.
///
/// Stores the low byte of `flag` at cache byte offset `0x18`. The callers
/// obtain the singleton from `0x082841c8` and write zero before resetting
/// its cursor, or one after traversing its 0x50-byte records. The precise
/// flag meaning remains unresolved; no boolean normalization is performed.
/// Raw words are `e5c01018` (strb r1,[r0,#24]) and `e12fff1e` (bx lr).
/// Deliberate deviation: exposes the unchanged r0 as the return value even
/// though Ghidra declares void; existing retail callers ignore it.
/// ARM match preserves the byte store and r0; LLVM adds a frame-pointer
/// prologue and returns via pop {fp,pc} rather than bx lr.
///
/// # Safety
/// `cache` must point into a live allocation writable at byte offset `0x18`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_cache_set_flag(cache: *mut u8, flag: u32) -> *mut u8 {
    cache.add(0x18).write(flag as u8);
    cache
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_to_byte_without_touching_adjacent_fields() {
        for alignment in 0..4 {
            for flag in [0, 1, 2, 0x80, 0xff, 0x100, 0x1234_5678, u32::MAX] {
                let mut storage = [0xa5u8; 40];
                let mut expected = storage;
                expected[alignment + 0x18] = flag as u8;
                let cache = unsafe { storage.as_mut_ptr().add(alignment) };
                let result = unsafe { record_cache_set_flag(cache, flag) };
                assert_eq!(result, cache);
                assert_eq!(storage, expected);
            }
        }
    }

    #[test]
    fn overwrites_previous_flag_in_both_directions() {
        let mut cache = [0x5au8; 0x20];
        for flag in [1, 0, 0xff, 0, 1] {
            unsafe { record_cache_set_flag(cache.as_mut_ptr(), flag); }
            assert_eq!(cache[0x18], flag as u8);
            assert_eq!(&cache[..0x18], &[0x5a; 0x18]);
            assert_eq!(&cache[0x19..], &[0x5a; 7]);
        }
    }
}
