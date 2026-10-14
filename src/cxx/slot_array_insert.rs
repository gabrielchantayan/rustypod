//! Slot-array insertion — `FUN_083d4dd4` @ `0x083d4dd4`.
//!
//! True extent: 164 bytes [0x083d4dd4,0x083d4e78), ending with a pop-return
//! immediately before the expansion prologue. Whole-image raw A32 decoding:
//! one incoming plain BL at 0x081ef1d0, zero incoming predicated BLs;
//! one outgoing plain BL (bounds check), one BLEQ (expansion).
//! Reject an existing value before growing when count equals capacity. Scan
//! the possibly relocated storage for the first zero slot; validate its index,
//! increment count modulo 2^32 and store the value. Return -1 for duplicates
//! or no hole. Capacity comparisons are signed; zero is not special-cased.
//! Deliberate deviations: none in behavior. Reuse the existing target-width
//! header and both ported callees; private expansion injection isolates tests.

use super::slot_array_construct::TrackedSlotArray;
use super::slot_array_expand::slot_array_expand;
use super::slot_array_index_in_bounds::slot_array_index_in_bounds;

/// # Safety
/// `array` must be a writable six-word header with readable/writable storage
/// for its positive capacity. Expansion must satisfy `slot_array_expand`'s
/// allocation contract. Storage pointers must fit in u32 even on hosts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn slot_array_insert(array: *mut TrackedSlotArray, value: u32) -> i32 {
    insert_with(array, value, |array| slot_array_expand(array))
}

#[inline(always)]
unsafe fn insert_with(
    array: *mut TrackedSlotArray, value: u32,
    expand: impl FnOnce(*mut TrackedSlotArray),
) -> i32 {
    let mut index = 0i32;
    while index < (*array).slots.capacity {
        let storage = (*array).slots.storage as usize as *const u32;
        if storage.add(index as usize).read() == value { return -1; }
        index += 1;
    }
    if (*array).slots.count == (*array).slots.capacity { expand(array); }
    index = 0;
    while index < (*array).slots.capacity {
        let storage = (*array).slots.storage as usize as *const u32;
        if storage.add(index as usize).read() == 0 { break; }
        index += 1;
    }
    if index >= (*array).slots.capacity { index = -1; }
    if slot_array_index_in_bounds(core::ptr::addr_of!((*array).slots), index) != 0 {
        (*array).slots.count = (*array).slots.count.wrapping_add(1);
        let storage = (*array).slots.storage as usize as *mut u32;
        storage.add(index as usize).write(value);
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::slot_array_index_in_bounds::SlotArray;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn duplicates_holes_zero_and_relocated_expansion() {
        let Some(base) = try_map_u32_slab(hints::SLOT_ARRAY_INSERT, 0x1000) else { return };
        unsafe {
            let storage = base.cast::<u32>();
            let relocated = storage.add(16);
            let mut array = TrackedSlotArray {
                slots: SlotArray { storage: storage as usize as u32, capacity: 4, count: 3 },
                options: 7, growth: 2, tracker_label: 9,
            };
            for hole in 0..4 {
                for i in 0..4 { storage.add(i).write(if i == hole { 0 } else { 10 + i as u32 }); }
                array.slots.count = 3;
                assert_eq!(slot_array_insert(&mut array, 42), hole as i32);
                assert_eq!(array.slots.count, 4);
                for i in 0..4 { assert_eq!(storage.add(i).read(), if i == hole { 42 } else { 10 + i as u32 }); }
                assert_eq!(insert_with(&mut array, 42, |_| panic!("duplicate must not grow")), -1);
                assert_eq!(array.slots.count, 4);
            }
            assert_eq!(insert_with(&mut array, 99, |array| {
                core::ptr::copy_nonoverlapping(storage, relocated, 4);
                for i in 4..8 { relocated.add(i).write(0); }
                (*array).slots.storage = relocated as usize as u32;
                (*array).slots.capacity = 8;
            }), 4);
            assert_eq!(relocated.add(4).read(), 99);
            assert_eq!(array.slots.count, 5);
            assert_eq!((array.options, array.growth, array.tracker_label), (7, 2, 9));
            assert_eq!(slot_array_insert(&mut array, 0), -1);
            for i in 0..8 { relocated.add(i).write(i as u32 + 1); }
            array.slots.count = 0;
            assert_eq!(slot_array_insert(&mut array, 0), -1);
            assert_eq!(array.slots.count, 0);
            relocated.add(2).write(0);
            array.slots.count = i32::MAX;
            assert_eq!(slot_array_insert(&mut array, 99), 2);
            assert_eq!(array.slots.count, i32::MIN);
        }
    }

    #[test]
    fn signed_empty_capacity_and_unchanged_growth() {
        for capacity in [0, -1, i32::MIN] {
            let mut array = TrackedSlotArray {
                slots: SlotArray { storage: 0, capacity, count: 1 },
                options: 0, growth: 1, tracker_label: 0,
            };
            assert_eq!(unsafe { slot_array_insert(&mut array, 7) }, -1);
            assert_eq!(array.slots.count, 1);
            array.slots.count = capacity;
            assert_eq!(unsafe { insert_with(&mut array, 7, |_| {}) }, -1);
            assert_eq!(array.slots.count, capacity);
        }
    }
}
