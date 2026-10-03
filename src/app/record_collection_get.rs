//! Indexed eight-byte record lookup in a target-width collection.
//!
//! `record_collection_get` — `FUN_08269d30` at `0x08269d30`, 36 bytes
//! through the BX LR at 0x08269d50; next real prologue is 0x08269d54.
//! Raw ARM scan verifies two incoming plain BLs (0x08269900, 0x08269a40),
//! zero incoming predicated BLs, and zero outgoing plain/predicated BLs.
//! Reads count at +0x14; if index <= count.wrapping_sub(1), reads the
//! two-word record at the +0x10 table pointer plus index * 8. Otherwise
//! returns zero in r0/r1. Both callers consume the pair as a 64-bit key.
//! Count zero deliberately underflows and permits every index; pointer
//! arithmetic also wraps at 32 bits, exactly as in the original words.
//! Deliberate deviations: two aligned u32 reads express the stock LDRD;
//! no allocation, validation, native-pointer widening or callee seams.

/// # Safety
/// `collection` points to at least six aligned target-width words. Whenever
/// the wrapping bounds check accepts `index`, the wrapped table address must
/// point to two readable aligned u32 words, including when count is zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_collection_get(collection: *const u32, index: u32) -> u64 {
    let count = unsafe { collection.add(5).read() };
    if index > count.wrapping_sub(1) {
        return 0;
    }
    let table = unsafe { collection.add(4).read() };
    let record = table.wrapping_add(index.wrapping_mul(8)) as usize as *const u32;
    let low = unsafe { record.read() };
    let high = unsafe { record.add(1).read() };
    (low as u64) | ((high as u64) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_bounds_underflow_and_target_address_wrap() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::RECORD_COLLECTION_GET, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("record_collection_get");
            return;
        };
        unsafe {
            let collection = slab.cast::<u32>();
            // Only four-byte aligned: the firmware does not require an
            // eight-byte-aligned Rust u64 reference for its word pair.
            let table = slab.add(260).cast::<u32>();
            let pairs = [[0x89ab_cdefu32, 0x0123_4567], [0, 0], [7, u32::MAX]];
            for (i, pair) in pairs.iter().enumerate() {
                table.add(i * 2).write(pair[0]);
                table.add(i * 2 + 1).write(pair[1]);
            }
            collection.add(4).write(table as usize as u32);
            collection.add(5).write(3);
            for (index, pair) in pairs.iter().enumerate() {
                assert_eq!(record_collection_get(collection, index as u32),
                    pair[0] as u64 | ((pair[1] as u64) << 32));
            }
            // A rejected index must not dereference even an invalid table.
            collection.add(4).write(0);
            for index in [3, 4, u32::MAX] {
                assert_eq!(record_collection_get(collection, index), 0);
            }
            collection.add(4).write(table as usize as u32);
            collection.add(5).write(1);
            assert_eq!(record_collection_get(collection, 0), 0x0123_4567_89ab_cdef);
            assert_eq!(record_collection_get(collection, 1), 0);
            // Zero count is NOT an empty check in the original.
            collection.add(5).write(0);
            assert_eq!(record_collection_get(collection, 2), 0xffff_ffff_0000_0007);
            table.sub(2).write(0x7654_3210);
            table.sub(1).write(0xfedc_ba98);
            assert_eq!(record_collection_get(collection, u32::MAX), 0xfedc_ba98_7654_3210);
            assert_eq!(record_collection_get(collection, 0x2000_0000), 0x0123_4567_89ab_cdef);
        }
    }
}
