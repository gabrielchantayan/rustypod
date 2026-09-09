//! Opaque collection item-count accessor.
//!
//! `opaque_collection_item_count` — original: `FUN_08299d78` @ 0x08299d78
//! (8 bytes). Raw ARM is `ldr r0,[r0,#8]; bx lr`: return the untyped word at
//! collection+0x8 with no NULL guard, validation, or writes.
//!
//! Call-site census (binary-scanned over every ARM B/BL immediate in
//! osos.dec): 12 plain unconditional `bl` sites and no predicated `bl`
//! sites. One `bne` tail branch at 0x082996f8 first loads an owning
//! application object's +0xbc collection pointer and checks it against NULL;
//! direct callers use the returned word as a count, including item-loop bounds.
//! No literal data word names 0x08299d78, so this accessor is not dispatched
//! virtually. The collection's concrete class is not recovered.

/// Returns the opaque collection's item-count word.
///
/// Original: `FUN_08299d78` @ 0x08299d78 (8 bytes). Performs exactly one
/// aligned 32-bit load from `collection + 8` and returns it unchanged. No
/// deviation: this intentionally has no NULL guard or range validation.
#[cfg_attr(target_os = "none", link_section = ".text.opaque_collection_item_count")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_collection_item_count(collection: *const u8) -> u32 {
    unsafe { (collection.add(8) as *const u32).read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn returns_the_exact_count_word() {
        let mut collection = [0u32; 4];
        collection[2] = 37;

        unsafe {
            assert_eq!(opaque_collection_item_count(collection.as_ptr() as *const u8), 37);
        }
    }

    #[test]
    fn preserves_extreme_count_representations() {
        let mut collection = [0u32; 4];

        for count in [0, 1, u32::MAX, 0x8000_0000] {
            collection[2] = count;
            unsafe {
                assert_eq!(opaque_collection_item_count(collection.as_ptr() as *const u8), count);
            }
        }
    }

    #[test]
    fn reads_only_the_word_at_offset_eight() {
        let mut collection = [0xaaaa_aaaau32; 4];
        collection[2] = 0x1234_5678;
        let before = collection;

        unsafe {
            assert_eq!(
                opaque_collection_item_count(collection.as_ptr() as *const u8),
                0x1234_5678
            );
        }
        assert_eq!(collection, before, "accessor must not modify the collection");
    }
}
