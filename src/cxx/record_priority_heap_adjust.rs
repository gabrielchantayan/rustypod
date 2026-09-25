//! Priority-record binary-heap adjustment from retailOS.
//!
//! `FUN_083e7eb8` @ `0x083e7eb8` is **136 bytes**
//! (`0x083e7eb8..0x083e7f40`; the next independently linked function starts
//! at `0x083e7f40`). Full-image A32 decoding finds two inbound unconditional
//! plain `bl` calls (`0x082622f4`, `0x082624d4`) and no predicated `bl` calls.
//! Its body has two unconditional direct `bl` calls: the priority-record
//! comparison at `0x082a1d1c` and the matching sift-up helper at `0x083e7d7c`.
//!
//! Algorithm: move the lesser child down from `hole_index`, choosing between
//! children with the fixed record ordering (unsigned word +0x1c, then signed
//! word +0x20), then invoke the matching sift-up helper to place `value`.
//!
//! Deliberate deviation: the two unported direct callees remain fixed-address
//! calls on the target; host builds reproduce their byte-observed behavior so
//! the complete adjustment can be tested.

const RETAIL_RECORD_PRIORITY_GREATER: usize = 0x082a_1d1c;
const RETAIL_RECORD_PRIORITY_SIFT_UP: usize = 0x083e_7d7c;

type RecordPriorityGreater = unsafe extern "C" fn(*const u8, u32, u32) -> i32;
type RecordPrioritySiftUp = unsafe extern "C" fn(*mut u32, i32, i32, u32, *const u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn record_priority_greater(context: *const u8, left: u32, right: u32) -> i32 {
    let compare: RecordPriorityGreater = unsafe { core::mem::transmute(RETAIL_RECORD_PRIORITY_GREATER) };
    unsafe { compare(context, left, right) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn record_priority_greater(_context: *const u8, left: u32, right: u32) -> i32 {
    let left = left as usize as *const u32;
    let right = right as usize as *const u32;
    let left_priority = unsafe { left.add(7).read() };
    let right_priority = unsafe { right.add(7).read() };
    let left_tiebreak = unsafe { left.add(8).read() as i32 };
    let right_tiebreak = unsafe { right.add(8).read() as i32 };
    ((left_priority > right_priority)
        || (left_priority == right_priority && left_tiebreak > right_tiebreak)) as i32
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn sift_record_priority_up(heap: *mut u32, hole: i32, top: i32, value: u32, context: *const u8) {
    let sift: RecordPrioritySiftUp = unsafe { core::mem::transmute(RETAIL_RECORD_PRIORITY_SIFT_UP) };
    unsafe { sift(heap, hole, top, value, context) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn sift_record_priority_up(heap: *mut u32, mut hole: i32, top: i32, value: u32, context: *const u8) {
    while top < hole {
        let parent = (hole - 1) / 2;
        if unsafe { record_priority_greater(context, heap.add(parent as usize).read(), value) } == 0 {
            break;
        }
        unsafe { heap.add(hole as usize).write(heap.add(parent as usize).read()) };
        hole = parent;
    }
    unsafe { heap.add(hole as usize).write(value) };
}

/// Restores the fixed-priority binary heap after removing its `hole_index` value.
///
/// Original: `FUN_083e7eb8` @ `0x083e7eb8` (136 bytes; 2 plain inbound `bl`
/// call sites, 0 predicated). See the module header for the direct-callee ABI.
///
/// # Safety
///
/// `heap` must point to the target-width priority-record pointer array. Every
/// word read by the heap walk must identify a record with readable words at
/// byte offsets +0x1c and +0x20.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_priority_heap_adjust(
    heap: *mut u32,
    hole_index: i32,
    element_count: i32,
    value: u32,
    context: *const u8,
) {
    let mut hole = hole_index;
    let mut child = hole * 2 + 2;
    while child < element_count {
        if unsafe { record_priority_greater(context, heap.add(child as usize).read(), heap.add((child - 1) as usize).read()) } != 0 {
            child -= 1;
        }
        unsafe { heap.add(hole as usize).write(heap.add(child as usize).read()) };
        hole = child;
        child = hole * 2 + 2;
    }
    if child == element_count {
        unsafe { heap.add(hole as usize).write(heap.add((child - 1) as usize).read()) };
        hole = child - 1;
    }
    unsafe { sift_record_priority_up(heap, hole, hole_index, value, context) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const ARRAY_WORDS: usize = 8;
    const RECORD_WORDS: usize = 9;

    unsafe fn record(slab: *mut u8, index: usize, priority: u32, tiebreak: i32) -> u32 {
        let record = unsafe { (slab as *mut u32).add(ARRAY_WORDS + index * RECORD_WORDS) };
        unsafe {
            record.write_bytes(0, RECORD_WORDS);
            record.add(7).write(priority);
            record.add(8).write(tiebreak as u32);
        }
        record as usize as u32
    }

    #[test]
    fn chooses_the_lower_right_child_and_places_the_value_below_it() {
        let Some(slab) = try_map_u32_slab(hints::RECORD_PRIORITY_HEAP_ADJUST, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/record_priority_heap_adjust"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let heap = slab as *mut u32;
            let value = record(slab, 0, 20, 0);
            let left = record(slab, 1, 9, 0);
            let right = record(slab, 2, 8, 0);
            heap.write(value);
            heap.add(1).write(left);
            heap.add(2).write(right);
            record_priority_heap_adjust(heap, 0, 3, value, core::ptr::null());
            assert_eq!([heap.read(), heap.add(1).read(), heap.add(2).read()], [right, left, value]);
        }
    }

    #[test]
    fn uses_the_signed_tiebreak_and_keeps_equal_records_in_child_order() {
        let Some(slab) = try_map_u32_slab(hints::RECORD_PRIORITY_HEAP_ADJUST, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/record_priority_heap_adjust"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let heap = slab as *mut u32;
            let value = record(slab, 0, 20, 0);
            let left = record(slab, 1, 8, 1);
            let right = record(slab, 2, 8, -1);
            heap.write(value);
            heap.add(1).write(left);
            heap.add(2).write(right);
            record_priority_heap_adjust(heap, 0, 3, value, core::ptr::null());
            assert_eq!(heap.read(), right);
        }
    }
}
