//! Nullable owner collection item count.

use super::opaque_collection_item_count::opaque_collection_item_count;

/// Original: `FUN_082996f0` @ **0x082996f0**, **16 bytes**
/// (`0x082996f0..0x08299700`; the next function begins with push {r4,lr}).
/// Raw words: e59000bc e3500000 1a00019e e12fff1e. Two inbound plain
/// BL calls (0x081273c4, 0x082346c4), zero predicated BL calls; zero
/// outbound BLs and one conditional tail branch to 0x08299d78.
/// Read the target-width collection pointer at owner+0xbc. Return zero
/// when absent; otherwise return its aligned count word at +8 through the
/// existing opaque_collection_item_count port. No deliberate deviation.
///
/// # Safety
/// `owner` must permit an aligned u32 read at +0xbc. A nonzero collection
/// pointer must permit an aligned u32 read at +8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_collection_item_count(owner: *const u32) -> u32 {
    let collection = owner.add(0xbc / 4).read() as usize as *const u8;
    if collection.is_null() {
        0
    } else {
        opaque_collection_item_count(collection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn absent_collection_returns_zero_without_changing_owner() {
        let mut owner = [0xa5a5_a5a5u32; 0xbc / 4 + 1];
        owner[0xbc / 4] = 0;
        let before = owner;
        assert_eq!(unsafe { owner_collection_item_count(owner.as_ptr()) }, 0);
        assert_eq!(owner, before);
    }

    #[test]
    fn present_collection_preserves_count_bits_and_both_objects() {
        let Some(slab) = try_map_u32_slab(hints::OWNER_COLLECTION_ITEM_COUNT, 0x1000) else {
            assert!(note_missing_u32_fixture("app::owner_collection_item_count"));
            return;
        };
        let collection = slab.cast::<u32>();
        let mut owner = [0x5a5a_5a5au32; 0xbc / 4 + 1];
        owner[0xbc / 4] = collection as usize as u32;
        let before = owner;
        for count in [0, 1, 37, 0x8000_0000, u32::MAX] {
            let words = [0x1111_1111, 0x2222_2222, count];
            unsafe {
                core::ptr::copy_nonoverlapping(words.as_ptr(), collection, words.len());
                assert_eq!(owner_collection_item_count(owner.as_ptr()), count);
                assert_eq!(core::slice::from_raw_parts(collection, 3), &words);
            }
            assert_eq!(owner, before);
        }
    }
}
