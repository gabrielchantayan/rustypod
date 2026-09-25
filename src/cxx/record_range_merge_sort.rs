//! Bottom-up stable merge sort of twelve-byte records.
//!
//! The leaf sorter and run-merger have not been recovered independently, so
//! they remain typed device calls with volatile host seams.

use crate::runtime::rt_div::__rt_sdiv;
#[cfg(not(target_os = "none"))]
use core::ptr;

const LEAF_SORT_ADDRESS: usize = 0x083e_8274;
const RUN_MERGE_ADDRESS: usize = 0x083e_8814;
const RECORD_BYTES: i32 = 12;
const INITIAL_RUN_RECORDS: i32 = 7;

/// ABI boundaries used by the bottom-up record merge sorter.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RecordRangeMergeSortOps {
    pub leaf_sort: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8),
    pub merge_runs: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, i32, *mut u8),
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn leaf_sort(first: *mut u8, last: *mut u8, compare: *mut u8) {
    let routine: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) = core::mem::transmute(LEAF_SORT_ADDRESS);
    routine(first, last, compare)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn merge_runs(first: *mut u8, last: *mut u8, output: *mut u8, run_records: i32, compare: *mut u8) {
    let routine: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, i32, *mut u8) = core::mem::transmute(RUN_MERGE_ADDRESS);
    routine(first, last, output, run_records, compare)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_leaf_sort(_: *mut u8, _: *mut u8, _: *mut u8) {
    panic!("record_range_merge_sort requires leaf sorter 0x083e8274")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_merge_runs(_: *mut u8, _: *mut u8, _: *mut u8, _: i32, _: *mut u8) {
    panic!("record_range_merge_sort requires run merger 0x083e8814")
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_RANGE_MERGE_SORT_OPS: RecordRangeMergeSortOps = RecordRangeMergeSortOps {
    leaf_sort: unavailable_leaf_sort,
    merge_runs: unavailable_merge_runs,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn leaf_sort(first: *mut u8, last: *mut u8, compare: *mut u8) {
    (ptr::read_volatile(ptr::addr_of!(RECORD_RANGE_MERGE_SORT_OPS)).leaf_sort)(first, last, compare)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn merge_runs(first: *mut u8, last: *mut u8, output: *mut u8, run_records: i32, compare: *mut u8) {
    (ptr::read_volatile(ptr::addr_of!(RECORD_RANGE_MERGE_SORT_OPS)).merge_runs)(first, last, output, run_records, compare)
}

/// `record_range_merge_sort` — original: `FUN_083e9a20` @ `0x083e9a20`
/// (**204 bytes**, `0x083e9a20..0x083e9aec`; the next real function begins at
/// `0x083e9aec`). Raw ARM decoding finds seven unconditional direct `bl`
/// instructions and no predicated `bl`; its two inbound call sites are both
/// unconditional direct `bl` instructions in `FUN_083e9928`.
///
/// Sorts consecutive seven-record leaves, then merges adjacent runs into the
/// supplied scratch range. Each pass doubles the run width and alternates the
/// source/output ranges, ending in `first..last` when the total record count
/// is at least seven.
///
/// Deliberate deviation: the unrecovered leaf-sort and run-merge routines are
/// fixed-address calls on device builds and volatile host seams for tests. The
/// original's third and fifth arguments are not read; they remain in the ABI.
///
/// # Safety
/// `first..last` and `scratch` must denote writable ARM-addressable ranges of
/// equal twelve-byte-record capacity; `compare` must be valid for both retail
/// helper routines.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_range_merge_sort(first: *mut u8, last: *mut u8, _unused: *mut u8, scratch: *mut u8, _unused2: *mut u8, compare: *mut u8) {
    let record_count = __rt_sdiv((last as usize).wrapping_sub(first as usize) as i32, RECORD_BYTES);
    let mut leaf_first = first;
    while __rt_sdiv((last as usize).wrapping_sub(leaf_first as usize) as i32, RECORD_BYTES) > INITIAL_RUN_RECORDS - 1 {
        let leaf_last = leaf_first.add((INITIAL_RUN_RECORDS * RECORD_BYTES) as usize);
        leaf_sort(leaf_first, leaf_last, compare);
        leaf_first = leaf_last;
    }
    leaf_sort(leaf_first, last, compare);

    let mut run_records = INITIAL_RUN_RECORDS;
    while run_records < record_count {
        merge_runs(first, last, scratch, run_records, compare);
        run_records = run_records.wrapping_mul(2);
        merge_runs(scratch, scratch.add((record_count * RECORD_BYTES) as usize), first, run_records, compare);
        run_records = run_records.wrapping_mul(2);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn leaf_sort(first: *mut u8, last: *mut u8, _: *mut u8) {
        let records = core::slice::from_raw_parts_mut(first.cast::<[u32; 3]>(), last.offset_from(first) as usize / RECORD_BYTES as usize);
        records.sort_by_key(|record| record[0]);
    }

    unsafe extern "C" fn merge_runs(first: *mut u8, last: *mut u8, output: *mut u8, run_records: i32, _: *mut u8) {
        let input = core::slice::from_raw_parts(first.cast::<[u32; 3]>(), last.offset_from(first) as usize / RECORD_BYTES as usize);
        let destination = core::slice::from_raw_parts_mut(output.cast::<[u32; 3]>(), input.len());
        let width = run_records as usize;
        for (output_chunk, input_chunk) in destination.chunks_mut(width * 2).zip(input.chunks(width * 2)) {
            let split = core::cmp::min(width, input_chunk.len());
            let (mut left, mut right, mut next) = (0, split, 0);
            while left < split && right < input_chunk.len() {
                if input_chunk[left][0] <= input_chunk[right][0] { output_chunk[next] = input_chunk[left]; left += 1; } else { output_chunk[next] = input_chunk[right]; right += 1; }
                next += 1;
            }
            while left < split { output_chunk[next] = input_chunk[left]; left += 1; next += 1; }
            while right < input_chunk.len() { output_chunk[next] = input_chunk[right]; right += 1; next += 1; }
        }
    }

    unsafe fn sort(records: &mut [[u32; 3]], scratch: &mut [[u32; 3]]) {
        record_range_merge_sort(records.as_mut_ptr().cast(), records.as_mut_ptr().add(records.len()).cast(), ptr::null_mut(), scratch.as_mut_ptr().cast(), ptr::null_mut(), ptr::null_mut());
    }

    #[test]
    fn sorts_short_and_partial_leaf_ranges() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let old = ptr::read_volatile(ptr::addr_of!(RECORD_RANGE_MERGE_SORT_OPS));
            ptr::addr_of_mut!(RECORD_RANGE_MERGE_SORT_OPS).write_volatile(RecordRangeMergeSortOps { leaf_sort, merge_runs });
            let mut empty = [];
            let mut empty_scratch = [];
            sort(&mut empty, &mut empty_scratch);
            let mut records = [[0u32; 3]; 13];
            let mut scratch = [[0u32; 3]; 13];
            for (index, record) in records.iter_mut().enumerate() { record[0] = (12 - index) as u32; record[1] = index as u32; }
            sort(&mut records, &mut scratch);
            assert!(records.windows(2).all(|pair| pair[0][0] <= pair[1][0]));
            ptr::addr_of_mut!(RECORD_RANGE_MERGE_SORT_OPS).write_volatile(old);
        }
    }

    #[test]
    fn preserves_stability_across_multiple_merge_passes() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let old = ptr::read_volatile(ptr::addr_of!(RECORD_RANGE_MERGE_SORT_OPS));
            ptr::addr_of_mut!(RECORD_RANGE_MERGE_SORT_OPS).write_volatile(RecordRangeMergeSortOps { leaf_sort, merge_runs });
            let mut records = [[0u32; 3]; 29];
            let mut scratch = [[0u32; 3]; 29];
            for (index, record) in records.iter_mut().enumerate() { record[0] = (index % 5) as u32; record[1] = index as u32; }
            sort(&mut records, &mut scratch);
            assert!(records.windows(2).all(|pair| pair[0][0] <= pair[0][0]));
            for pair in records.windows(2) { if pair[0][0] == pair[1][0] { assert!(pair[0][1] < pair[1][1]); } }
            ptr::addr_of_mut!(RECORD_RANGE_MERGE_SORT_OPS).write_volatile(old);
        }
    }
}
