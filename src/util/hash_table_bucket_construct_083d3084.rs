//! `hash_table_bucket_construct_083d3084` — retailOS `FUN_083d3084` at load
//! address `0x083d3084` (200 bytes).
//!
//! Raw `osos.dec` establishes the exact 50-word A32 extent from `push
//! {r4-r7,lr}` at `0x083d3084` through `pop {r4-r7,pc}` at `0x083d3148`.
//! `0x083d314c` begins `hash_table_chain_prepend`. The body has two
//! unconditional plain `bl` calls — `operator_new_checked` at `0x08266c70`
//! and the unreachable exception-cleanup `cxx_array_dealloc` at `0x08266f2c`
//! — and no predicated `bl` calls.
//!
//! Allocates `bucket_count + 1` target words, clears every word, then makes the
//! final word a self-linked sentinel. The allocation, count, and current-bucket
//! cursor occupy target words `+4`, `+8`, and `+12` respectively.
//!
//! ## Deliberate deviations
//!
//! Rust has no C++ exception landing pad, so it omits the unreachable cleanup
//! block that deallocates the allocation if an intervening exception transfers
//! control to `0x083d3134`. The normal allocation, clearing, sentinel, and
//! target-width layout are unchanged. This separately exported duplicate of
//! `0x083d351c` remains a distinct hook target.

use crate::heap::veneers::operator_new_checked;
use crate::util::hash_table_bucket_construct::HashTableBuckets;

/// Initializes the table's cleared bucket array and terminal self-link.
///
/// # Safety
///
/// `table` must be valid for writes. Its `bucket_count` is multiplied by four
/// with target-width wrapping; the configured checked allocator must return a
/// writable allocation of that resulting `(bucket_count + 1) * 4` byte span.
/// Like retailOS, a NULL allocation faults while writing the sentinel.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.hash_table_bucket_construct_083d3084"))]
#[inline(never)]
pub unsafe extern "C" fn hash_table_bucket_construct_083d3084(table: *mut HashTableBuckets) {
    let bucket_count = (*table).bucket_count;
    let word_count = bucket_count.wrapping_add(1);
    let buckets = operator_new_checked(word_count.wrapping_mul(4) as usize).cast::<u32>();
    for index in 0..word_count {
        buckets.add(index as usize).write_volatile(0);
    }

    let sentinel = buckets.add(bucket_count as usize);
    (*table).current_bucket = sentinel as usize as u32;
    sentinel.write(sentinel as usize as u32);
    (*table).bucket_base = buckets as usize as u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn initializes_empty_and_populated_bucket_arrays() {
        let _heap = mock_heap();
        let Some(slab) = try_map_u32_slab(hints::HASH_TABLE_BUCKET_CONSTRUCT_083D3084, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };

        unsafe {
            let table = slab.cast::<HashTableBuckets>();
            let buckets = slab.add(0x100).cast::<u32>();
            set_alloc_ret(buckets.cast());

            (*table).allocator = 0x1234_5678;
            (*table).bucket_count = 0;
            hash_table_bucket_construct_083d3084(table);
            assert_eq!(alloc_log().1, 4);
            assert_eq!(((*table).bucket_base, (*table).current_bucket), (buckets as usize as u32, buckets as usize as u32));
            assert_eq!(buckets.read(), buckets as usize as u32);
            assert_eq!((*table).allocator, 0x1234_5678);

            for index in 0..4usize {
                buckets.add(index).write(u32::MAX);
            }
            (*table).bucket_count = 3;
            hash_table_bucket_construct_083d3084(table);
            assert_eq!(alloc_log().1, 16);
            assert_eq!([buckets.read(), buckets.add(1).read(), buckets.add(2).read()], [0, 0, 0]);
            assert_eq!(((*table).bucket_base, (*table).current_bucket), (buckets as usize as u32, buckets.add(3) as usize as u32));
            assert_eq!(buckets.add(3).read(), buckets.add(3) as usize as u32);
        }
    }
}
