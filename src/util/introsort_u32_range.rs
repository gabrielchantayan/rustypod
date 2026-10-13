//! Hybrid quicksort/insertion sort wrapper from retailOS.
//!
//! Load address: `0x083ea6f4`; true size: 128 bytes (`0x083ea6f4..0x083ea774`).
//! Raw A32 decoding verifies three unconditional direct `bl` instructions and no
//! predicated direct `bl` instructions. It first invokes the retail partitioning
//! helper with a depth budget equal to the word count. Ranges of at most sixteen
//! words tail-dispatch to the guarded insertion helper; larger ranges have their
//! first sixteen words guarded-sorted, then each remaining word is inserted by
//! the unguarded helper. Deliberate deviations: partitioning still delegates
//! to the verified retail address on target and a host fixture; both insertion
//! helpers now call their Rust ports directly on all targets.

pub use crate::cxx::word_insertion_sort_insert::WordOrder as WordComparator;
use crate::cxx::word_insertion_sort::word_insertion_sort as guarded_insertion_sort;
use crate::cxx::word_insertion_sort_insert::word_insertion_sort_insert as unguarded_insert;
type PartitionSort = unsafe extern "C" fn(*mut u32, *mut u32, i32, WordComparator);

const RETAIL_PARTITION_SORT: usize = 0x083e_83f0;
const INSERTION_PREFIX_WORDS: usize = 16;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn partition_sort(first: *mut u32, last: *mut u32, depth: i32, compare: WordComparator) {
    unsafe { core::mem::transmute::<usize, PartitionSort>(RETAIL_PARTITION_SORT)(first, last, depth, compare) }
}

#[cfg(not(target_os = "none"))]
pub struct IntrosortU32RangeOps {
    pub partition_sort: PartitionSort,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_partition_sort(_: *mut u32, _: *mut u32, _: i32, _: WordComparator) {
    panic!("introsort_u32_range requires a partition-sort fixture")
}
#[cfg(not(target_os = "none"))]
pub static mut INTROSORT_U32_RANGE_OPS: IntrosortU32RangeOps = IntrosortU32RangeOps {
    partition_sort: missing_partition_sort,
};

/// # Safety
/// `first..last` must be a valid contiguous range of `u32`s. `compare` must
/// satisfy the retail sort helpers' comparator contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn introsort_u32_range(first: *mut u32, last: *mut u32, compare: WordComparator) {
    if first == last {
        return;
    }
    let count = unsafe { last.offset_from(first) } as i32;
    #[cfg(target_os = "none")]
    unsafe { partition_sort(first, last, count, compare) };
    #[cfg(not(target_os = "none"))]
    unsafe { (INTROSORT_U32_RANGE_OPS.partition_sort)(first, last, count, compare) };

    if count <= INSERTION_PREFIX_WORDS as i32 {
        unsafe { guarded_insertion_sort(first, last, compare) };
        return;
    }

    let prefix_end = unsafe { first.add(INSERTION_PREFIX_WORDS) };
    unsafe { guarded_insertion_sort(first, prefix_end, compare) };
    let mut current = prefix_end;
    while current != last {
        let value = unsafe { current.read() };
        unsafe { unguarded_insert(current, value, compare) };
        current = unsafe { current.add(1) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut PARTITION_CALLS: u32 = 0;

    unsafe extern "C" fn ascending(left: u32, right: u32) -> i32 { i32::from(left < right) }
    unsafe extern "C" fn partition(_: *mut u32, _: *mut u32, _: i32, _: WordComparator) { unsafe { PARTITION_CALLS += 1; } }

    unsafe fn install_fixtures() {
        unsafe { INTROSORT_U32_RANGE_OPS = IntrosortU32RangeOps { partition_sort: partition }; }
    }

    #[test]
    fn sorts_small_ranges_with_guarded_helper_only() {
        let _lock = LOCK.lock();
        unsafe { PARTITION_CALLS = 0; install_fixtures(); }
        let mut words = [9, 1, 9, 2, 0];
        unsafe { introsort_u32_range(words.as_mut_ptr(), words.as_mut_ptr().add(words.len()), ascending); }
        assert_eq!(words, [0, 1, 2, 9, 9]);
    }

    #[test]
    fn sorts_large_range_through_prefix_and_unguarded_inserts() {
        let _lock = LOCK.lock();
        unsafe { PARTITION_CALLS = 0; install_fixtures(); }
        let mut words = [19, 3, 18, 2, 17, 1, 16, 0, 15, 4, 14, 5, 13, 6, 12, 7, 11, 8, 10, 9];
        unsafe { introsort_u32_range(words.as_mut_ptr(), words.as_mut_ptr().add(words.len()), ascending); }
        assert_eq!(words, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
    }

    #[test]
    fn empty_range_skips_all_helpers() {
        let _lock = LOCK.lock();
        unsafe { PARTITION_CALLS = 0; install_fixtures(); }
        let mut word = 42;
        unsafe { introsort_u32_range(&mut word, &mut word, ascending); }
        assert_eq!(unsafe { PARTITION_CALLS }, 0);
    }
}
