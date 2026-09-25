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
//! The unported comparator is a target-address call on firmware and a replaceable
//! host seam for behavioral tests.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

type RecordPriorityIsGreater = unsafe extern "C" fn(*const u8, u32, u32) -> u32;

const RETAIL_RECORD_PRIORITY_IS_GREATER: usize = 0x082a_1d1c;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_priority_is_greater(_: *const u8, _: u32, _: u32) -> u32 {
    panic!("install record-min-heap comparator before host use")
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_MIN_HEAP_SIFT_UP_OPS: RecordMinHeapSiftUpOps = RecordMinHeapSiftUpOps {
    record_priority_is_greater: missing_record_priority_is_greater,
};

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RecordMinHeapSiftUpOps {
    pub record_priority_is_greater: RecordPriorityIsGreater,
}

#[inline(always)]
unsafe fn record_priority_is_greater(left: u32, right: u32) -> bool {
    #[cfg(target_os = "none")]
    {
        let comparator: RecordPriorityIsGreater = unsafe { core::mem::transmute(RETAIL_RECORD_PRIORITY_IS_GREATER) };
        return unsafe { comparator(core::ptr::null(), left, right) != 0 };
    }

    #[cfg(not(target_os = "none"))]
    {
        let comparator = unsafe {
            core::ptr::read_volatile(addr_of!(RECORD_MIN_HEAP_SIFT_UP_OPS.record_priority_is_greater))
        };
        unsafe { comparator(core::ptr::null(), left, right) != 0 }
    }
}

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
        && unsafe { record_priority_is_greater(heap.add(parent_index as usize).read(), value) }
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
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn record_priority_is_greater(_: *const u8, left: u32, right: u32) -> u32 {
        let left = left as usize as *const u32;
        let right = right as usize as *const u32;
        let left_priority = unsafe { left.add(7).read() };
        let right_priority = unsafe { right.add(7).read() };
        let left_tiebreak = unsafe { left.add(8).read() as i32 };
        let right_tiebreak = unsafe { right.add(8).read() as i32 };
        u32::from(
            left_priority > right_priority
                || (left_priority == right_priority && left_tiebreak > right_tiebreak),
        )
    }

    #[test]
    fn shifts_strictly_greater_parents_and_preserves_equal_parent() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
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
            let previous = core::ptr::read_volatile(addr_of!(RECORD_MIN_HEAP_SIFT_UP_OPS));
            core::ptr::write_volatile(
                addr_of_mut!(RECORD_MIN_HEAP_SIFT_UP_OPS),
                RecordMinHeapSiftUpOps { record_priority_is_greater },
            );
            record_min_heap_sift_up(heap, 3, 0, three);
            assert_eq!([heap.read(), heap.add(1).read(), heap.add(2).read(), heap.add(3).read()], [one, three, two, four]);
            record_min_heap_sift_up(heap, 4, 0, zero);
            assert_eq!([heap.read(), heap.add(1).read(), heap.add(2).read(), heap.add(3).read(), heap.add(4).read()], [zero, one, two, four, three]);
            record_min_heap_sift_up(heap, 5, 0, equal_two);
            assert_eq!(heap.add(5).read(), equal_two);
            core::ptr::write_volatile(addr_of_mut!(RECORD_MIN_HEAP_SIFT_UP_OPS), previous);
        }
    }
}
