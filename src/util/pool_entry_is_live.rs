//! pool_entry_is_live — `FUN_080ac160` @ 0x080ac160 (28 bytes; **5 direct
//! `bl` call sites — all unconditional, no predicated direct calls**).
//!
//! Raw `osos.dec` words establish the exact extent: `ldr r1,[r0]` begins at
//! 0x080ac160, `bx lr` returns at 0x080ac178, and the next separately linked
//! function begins at 0x080ac17c. The predicate reads the two aligned entry
//! words and returns one only when the signed blob offset is non-negative and
//! the signed byte length is positive. Otherwise it returns zero.
//!
//! Deliberate deviations: none. As with the two original `ldr` instructions,
//! a NULL or invalid entry pointer is not guarded.

use crate::util::string_pool::PoolEntry;

/// Returns the normalized C-ABI truth value for a live string-pool entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pool_entry_is_live(entry: *const PoolEntry) -> u32 {
    u32::from(((*entry).blob_offset as i32) >= 0 && (*entry).length > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_non_negative_offset_and_positive_length() {
        let cases = [
            (0, 1, 1),
            (0x7fff_ffff, i32::MAX, 1),
            (0x8000_0000, 1, 0),
            (ENTRY_RECLAIMABLE, 1, 0),
            (0, 0, 0),
            (0, -1, 0),
        ];

        for (blob_offset, length, expected) in cases {
            let entry = PoolEntry { blob_offset, length };
            assert_eq!(unsafe { pool_entry_is_live(&entry) }, expected);
        }
    }

    use crate::util::string_pool::ENTRY_RECLAIMABLE;
}
