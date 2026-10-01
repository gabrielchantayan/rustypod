//! `record_min_heap_sift_up` — original: `FUN_083e7d7c` @ `0x083e7d7c`
//! (92 bytes; `0x083e7d7c..0x083e7dd7`).
//!
//! Raw A32 decoding finds one plain body `bl` (`record_priority_is_greater` at
//! `0x082a1d1c`) and no predicated body `bl` instructions. The two inbound BL
//! callers are `0x083d9e28` and `0x083e7eb8`.
//!
//! Inserts `value` at `child_index` in a binary min-heap of target-width record
//! pointers, shifting strict-greater parents downward until `start_index` is
//! reached or heap order holds. The comparator orders records lexicographically
//! by unsigned word `+0x1c`, then signed word `+0x20`.
//!
//! # Deliberate deviations
//!
//! Rust uses element indexing rather than literal `lsl #2` address arithmetic.
//! The comparator now calls the ported Rust implementation on both platforms.

use crate::util::record_priority_is_greater::record_priority_is_greater;

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_min_heap_sift_up(
    heap: *mut u32,
    mut child_index: i32,
    start_index: i32,
    value: u32,
) {
    let mut parent_index = (child_index - 1) / 2;
    while child_index > start_index
        && unsafe { record_priority_is_greater(core::ptr::null(), heap.add(parent_index as usize).read() as usize as *const u32, value as usize as *const u32) != 0 }
    {
        unsafe { heap.add(child_index as usize).write(heap.add(parent_index as usize).read()) };
        child_index = parent_index;
        parent_index = (parent_index - 1) / 2;
    }
    unsafe { heap.add(child_index as usize).write(value) };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn shifts_strictly_greater_parents_and_preserves_equal_parent() {
        let Some(slab) = try_map_u32_slab(hints::RECORD_MIN_HEAP_SIFT_UP, 4096) else {
            assert!(note_missing_u32_fixture("util/record_min_heap_sift_up"));
            return;
        };
        let words = slab.cast::<u32>();
        let heap = words;
        let records = unsafe { words.add(32) };
        let record = |slot: usize, priority: u32, tiebreak: i32| unsafe {
            let entry = records.add(slot * 9);
            entry.add(7).write(priority);
            entry.add(8).write(tiebreak as u32);
            entry as usize as u32
        };
        let one = record(0, 1, 0);
        let four = record(1, 4, 0);
        let two = record(2, 2, 0);
        let three = record(3, 3, 0);
        let zero = record(4, 0, 0);
        let equal_two = record(5, 2, 0);

        unsafe {
            heap.add(0).write(one);
            heap.add(1).write(four);
            heap.add(2).write(two);
            record_min_heap_sift_up(heap, 3, 0, three);
            assert_eq!([heap.read(), heap.add(1).read(), heap.add(2).read(), heap.add(3).read()], [one, three, two, four]);
            record_min_heap_sift_up(heap, 4, 0, zero);
            assert_eq!([heap.read(), heap.add(1).read(), heap.add(2).read(), heap.add(3).read(), heap.add(4).read()], [zero, one, two, four, three]);
            record_min_heap_sift_up(heap, 5, 0, equal_two);
            assert_eq!(heap.add(5).read(), equal_two);
        }
    }
}
