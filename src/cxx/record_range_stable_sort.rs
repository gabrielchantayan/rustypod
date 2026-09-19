//! Recursive stable sort of twelve-byte records.
//!
//! The leaf sorter and merge routine have not been recovered independently, so
//! they remain explicit device calls with host replacements.

use crate::runtime::rt_div::__rt_sdiv;
#[cfg(not(target_os = "none"))]
use core::ptr;

const LEAF_SORT_ADDRESS: usize = 0x083e_8274;
const MERGE_ADDRESS: usize = 0x083e_97a8;
const INSERTION_SORT_LIMIT_BYTES: i32 = 0xb4;
const RECORD_BYTES: i32 = 12;

/// ABI boundaries used by the recursive record-range sorter.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RecordRangeStableSortOps {
    pub leaf_sort: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8),
    pub merge: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, i32, i32, *mut u8),
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn leaf_sort(first: *mut u8, last: *mut u8, compare: *mut u8) {
    let routine: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) = core::mem::transmute(LEAF_SORT_ADDRESS);
    routine(first, last, compare)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn merge(first: *mut u8, middle: *mut u8, last: *mut u8, left_count: i32, right_count: i32, compare: *mut u8) {
    let routine: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, i32, i32, *mut u8) = core::mem::transmute(MERGE_ADDRESS);
    routine(first, middle, last, left_count, right_count, compare)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_leaf_sort(_: *mut u8, _: *mut u8, _: *mut u8) {
    panic!("record_range_stable_sort requires leaf sorter 0x083e8274")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_merge(_: *mut u8, _: *mut u8, _: *mut u8, _: i32, _: i32, _: *mut u8) {
    panic!("record_range_stable_sort requires merge routine 0x083e97a8")
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_RANGE_STABLE_SORT_OPS: RecordRangeStableSortOps = RecordRangeStableSortOps {
    leaf_sort: unavailable_leaf_sort,
    merge: unavailable_merge,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn leaf_sort(first: *mut u8, last: *mut u8, compare: *mut u8) {
    (ptr::read_volatile(ptr::addr_of!(RECORD_RANGE_STABLE_SORT_OPS)).leaf_sort)(first, last, compare)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn merge(first: *mut u8, middle: *mut u8, last: *mut u8, left_count: i32, right_count: i32, compare: *mut u8) {
    (ptr::read_volatile(ptr::addr_of!(RECORD_RANGE_STABLE_SORT_OPS)).merge)(first, middle, last, left_count, right_count, compare)
}

/// `record_range_stable_sort` — original: `FUN_083e970c` @ `0x083e970c`
/// (**156 bytes**, `0x083e970c..0x083e97a8`; the next separately linked entry
/// begins at `0x083e97a8`). Raw ARM decoding finds six unconditional direct
/// `bl` instructions and one predicated `blt` tail call.
///
/// Recursively splits ranges of 12-byte records at `count / 2`, sorts both
/// halves, and merges them through the retail merge helper. Ranges below 180
/// bytes tail-call the retail insertion-sort leaf.
///
/// Deliberate deviation: the unrecovered leaf and merge routines are typed
/// fixed-address calls on device builds and volatile host seams for tests.
///
/// # Safety
/// `first..last` must be an ARM-addressable range whose byte length is a
/// multiple of 12; `compare` must be valid for both retail helper routines.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_range_stable_sort(first: *mut u8, last: *mut u8, compare: *mut u8) {
    let length = (last as usize).wrapping_sub(first as usize) as i32;
    if length < INSERTION_SORT_LIMIT_BYTES {
        leaf_sort(first, last, compare);
        return;
    }

    let middle = first.add((__rt_sdiv(length, RECORD_BYTES * 2) as usize) * RECORD_BYTES as usize);
    record_range_stable_sort(first, middle, compare);
    record_range_stable_sort(middle, last, compare);
    let right_count = __rt_sdiv((last as usize).wrapping_sub(middle as usize) as i32, RECORD_BYTES);
    let left_count = __rt_sdiv((middle as usize).wrapping_sub(first as usize) as i32, RECORD_BYTES);
    merge(first, middle, last, left_count, right_count, compare);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn leaf_sort(first: *mut u8, last: *mut u8, _: *mut u8) {
        let records = core::slice::from_raw_parts_mut(first.cast::<[u32; 3]>(), last.offset_from(first) as usize / 12);
        records.sort_by_key(|record| record[0]);
    }

    unsafe extern "C" fn merge(first: *mut u8, middle: *mut u8, last: *mut u8, _: i32, _: i32, _: *mut u8) {
        let records = core::slice::from_raw_parts_mut(first.cast::<[u32; 3]>(), last.offset_from(first) as usize / 12);
        let middle_index = middle.offset_from(first) as usize / 12;
        let mut merged = records.to_vec();
        let (mut left, mut right, mut output) = (0, middle_index, 0);
        while left < middle_index && right < merged.len() {
            if records[left][0] <= records[right][0] { merged[output] = records[left]; left += 1; } else { merged[output] = records[right]; right += 1; }
            output += 1;
        }
        while left < middle_index { merged[output] = records[left]; left += 1; output += 1; }
        while right < merged.len() { merged[output] = records[right]; right += 1; output += 1; }
        records.copy_from_slice(&merged);
    }

    #[test]
    fn sorts_leaf_and_recursive_ranges_stably() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let old = ptr::read_volatile(ptr::addr_of!(RECORD_RANGE_STABLE_SORT_OPS));
            ptr::addr_of_mut!(RECORD_RANGE_STABLE_SORT_OPS).write_volatile(RecordRangeStableSortOps { leaf_sort, merge });
            let mut records = [[0u32; 3]; 16];
            for (index, record) in records.iter_mut().enumerate() { record[0] = (15 - index) as u32; record[1] = index as u32; }
            record_range_stable_sort(records.as_mut_ptr().cast(), records.as_mut_ptr().add(records.len()).cast(), ptr::null_mut());
            assert!(records.windows(2).all(|pair| pair[0][0] <= pair[1][0]));
            ptr::addr_of_mut!(RECORD_RANGE_STABLE_SORT_OPS).write_volatile(old);
        }
    }

    #[test]
    fn sorts_range_at_insertion_threshold() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let old = ptr::read_volatile(ptr::addr_of!(RECORD_RANGE_STABLE_SORT_OPS));
            ptr::addr_of_mut!(RECORD_RANGE_STABLE_SORT_OPS).write_volatile(RecordRangeStableSortOps { leaf_sort, merge });
            let mut records = [[0u32; 3]; 15];
            for (index, record) in records.iter_mut().enumerate() { record[0] = (14 - index) as u32; }
            record_range_stable_sort(records.as_mut_ptr().cast(), records.as_mut_ptr().add(records.len()).cast(), ptr::null_mut());
            assert!(records.windows(2).all(|pair| pair[0][0] <= pair[1][0]));
            ptr::addr_of_mut!(RECORD_RANGE_STABLE_SORT_OPS).write_volatile(old);
        }
    }
}
