//! Hybrid quicksort/insertion sort wrapper from retailOS.
//!
//! Load address: `0x083ea6f4`; true size: 128 bytes (`0x083ea6f4..0x083ea774`).
//! Raw A32 decoding verifies three unconditional direct `bl` instructions and no
//! predicated direct `bl` instructions. It first invokes the retail partitioning
//! helper with a depth budget equal to the word count. Ranges of at most sixteen
//! words tail-dispatch to the guarded insertion helper; larger ranges have their
//! first sixteen words guarded-sorted, then each remaining word is inserted by
//! the unguarded helper. Deliberate deviations: the target delegates the three
//! unrecovered helper bodies to their verified retail addresses; host tests
//! inject equivalent helpers through `INTROSORT_U32_RANGE_OPS`.

pub type WordComparator = unsafe extern "C" fn(u32, u32) -> i32;
type PartitionSort = unsafe extern "C" fn(*mut u32, *mut u32, i32, WordComparator);
type GuardedInsertionSort = unsafe extern "C" fn(*mut u32, *mut u32, WordComparator);
type UnguardedInsert = unsafe extern "C" fn(*mut u32, u32, WordComparator);

const RETAIL_PARTITION_SORT: usize = 0x083e_83f0;
const RETAIL_GUARDED_INSERTION_SORT: usize = 0x083e_8378;
const RETAIL_UNGUARDED_INSERT: usize = 0x083e_9aec;
const INSERTION_PREFIX_WORDS: usize = 16;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn partition_sort(first: *mut u32, last: *mut u32, depth: i32, compare: WordComparator) {
    unsafe { core::mem::transmute::<usize, PartitionSort>(RETAIL_PARTITION_SORT)(first, last, depth, compare) }
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn guarded_insertion_sort(first: *mut u32, last: *mut u32, compare: WordComparator) {
    unsafe { core::mem::transmute::<usize, GuardedInsertionSort>(RETAIL_GUARDED_INSERTION_SORT)(first, last, compare) }
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unguarded_insert(current: *mut u32, value: u32, compare: WordComparator) {
    unsafe { core::mem::transmute::<usize, UnguardedInsert>(RETAIL_UNGUARDED_INSERT)(current, value, compare) }
}

#[cfg(not(target_os = "none"))]
pub struct IntrosortU32RangeOps {
    pub partition_sort: PartitionSort,
    pub guarded_insertion_sort: GuardedInsertionSort,
    pub unguarded_insert: UnguardedInsert,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_partition_sort(_: *mut u32, _: *mut u32, _: i32, _: WordComparator) {
    panic!("introsort_u32_range requires a partition-sort fixture")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_guarded_insertion_sort(_: *mut u32, _: *mut u32, _: WordComparator) {
    panic!("introsort_u32_range requires a guarded-insertion-sort fixture")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_unguarded_insert(_: *mut u32, _: u32, _: WordComparator) {
    panic!("introsort_u32_range requires an unguarded-insert fixture")
}
#[cfg(not(target_os = "none"))]
pub static mut INTROSORT_U32_RANGE_OPS: IntrosortU32RangeOps = IntrosortU32RangeOps {
    partition_sort: missing_partition_sort,
    guarded_insertion_sort: missing_guarded_insertion_sort,
    unguarded_insert: missing_unguarded_insert,
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
        #[cfg(target_os = "none")]
        unsafe { guarded_insertion_sort(first, last, compare) };
        #[cfg(not(target_os = "none"))]
        unsafe { (INTROSORT_U32_RANGE_OPS.guarded_insertion_sort)(first, last, compare) };
        return;
    }

    let prefix_end = unsafe { first.add(INSERTION_PREFIX_WORDS) };
    #[cfg(target_os = "none")]
    unsafe { guarded_insertion_sort(first, prefix_end, compare) };
    #[cfg(not(target_os = "none"))]
    unsafe { (INTROSORT_U32_RANGE_OPS.guarded_insertion_sort)(first, prefix_end, compare) };
    let mut current = prefix_end;
    while current != last {
        let value = unsafe { current.read() };
        #[cfg(target_os = "none")]
        unsafe { unguarded_insert(current, value, compare) };
        #[cfg(not(target_os = "none"))]
        unsafe { (INTROSORT_U32_RANGE_OPS.unguarded_insert)(current, value, compare) };
        current = unsafe { current.add(1) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut PARTITION_CALLS: u32 = 0;
    static mut GUARDED_CALLS: u32 = 0;
    static mut UNGUARDED_CALLS: u32 = 0;

    unsafe extern "C" fn ascending(left: u32, right: u32) -> i32 { i32::from(left < right) }
    unsafe extern "C" fn partition(_: *mut u32, _: *mut u32, _: i32, _: WordComparator) { unsafe { PARTITION_CALLS += 1; } }
    unsafe extern "C" fn guarded(first: *mut u32, last: *mut u32, compare: WordComparator) {
        let mut current = unsafe { first.add(1) };
        while current != last {
            let value = unsafe { current.read() };
            let mut destination = current;
            while destination != first && unsafe { compare(value, destination.sub(1).read()) } != 0 {
                unsafe { destination.write(destination.sub(1).read()) };
                destination = unsafe { destination.sub(1) };
            }
            unsafe { destination.write(value) };
            current = unsafe { current.add(1) };
        }
        unsafe { GUARDED_CALLS += 1; }
    }
    unsafe extern "C" fn unguarded(mut current: *mut u32, value: u32, compare: WordComparator) {
        while unsafe { compare(value, current.sub(1).read()) } != 0 {
            unsafe { current.write(current.sub(1).read()) };
            current = unsafe { current.sub(1) };
        }
        unsafe { current.write(value); UNGUARDED_CALLS += 1; }
    }

    unsafe fn install_fixtures() {
        unsafe { INTROSORT_U32_RANGE_OPS = IntrosortU32RangeOps { partition_sort: partition, guarded_insertion_sort: guarded, unguarded_insert: unguarded }; }
    }

    #[test]
    fn sorts_small_ranges_with_guarded_helper_only() {
        let _lock = LOCK.lock();
        unsafe { PARTITION_CALLS = 0; GUARDED_CALLS = 0; UNGUARDED_CALLS = 0; install_fixtures(); }
        let mut words = [9, 1, 9, 2, 0];
        unsafe { introsort_u32_range(words.as_mut_ptr(), words.as_mut_ptr().add(words.len()), ascending); }
        assert_eq!(words, [0, 1, 2, 9, 9]);
        assert_eq!(unsafe { (PARTITION_CALLS, GUARDED_CALLS, UNGUARDED_CALLS) }, (1, 1, 0));
    }

    #[test]
    fn sorts_large_range_through_prefix_and_unguarded_inserts() {
        let _lock = LOCK.lock();
        unsafe { PARTITION_CALLS = 0; GUARDED_CALLS = 0; UNGUARDED_CALLS = 0; install_fixtures(); }
        let mut words = [19, 3, 18, 2, 17, 1, 16, 0, 15, 4, 14, 5, 13, 6, 12, 7, 11, 8, 10, 9];
        unsafe { introsort_u32_range(words.as_mut_ptr(), words.as_mut_ptr().add(words.len()), ascending); }
        assert_eq!(words, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
        assert_eq!(unsafe { (PARTITION_CALLS, GUARDED_CALLS, UNGUARDED_CALLS) }, (1, 1, 4));
    }

    #[test]
    fn empty_range_skips_all_helpers() {
        let _lock = LOCK.lock();
        unsafe { PARTITION_CALLS = 0; GUARDED_CALLS = 0; UNGUARDED_CALLS = 0; install_fixtures(); }
        let mut word = 42;
        unsafe { introsort_u32_range(&mut word, &mut word, ascending); }
        assert_eq!(unsafe { (PARTITION_CALLS, GUARDED_CALLS, UNGUARDED_CALLS) }, (0, 0, 0));
    }
}
