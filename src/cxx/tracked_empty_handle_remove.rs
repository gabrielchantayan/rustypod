//! Remove an owned handle with an empty destructor from a tracked slot array.
//!
//! `FUN_083d3bdc` @ 0x083d3bdc: true size 76 bytes,
//! [0x083d3bdc,0x083d3c28), ending in POP before the next independent PUSH.
//! Whole-image aligned A32 decoding finds zero incoming plain BLs and one
//! incoming BLNE at 0x081062fc; two outgoing plain BLs, no predicated BLs.
//! Reject negative indices and indices >= signed capacity; ignore NULL slots.
//! Call empty_destructor_1070b4, tag-2 delete its returned handle, reload storage,
//! clear the selected slot, then decrement the reloaded used count modulo 2^32.
//! Caller 0x08106108 drains this array at owner +0x48. Ghidra's erroneous
//! noreturn delete annotation omits the final 28 bytes; class identity is unknown.
//! Deliberate deviations: native header pointers widen on hosts; slots remain
//! u32. LLVM may remove the inert destructor call and change predication or
//! registers. Generic delete injection tests lifecycle mutations without a seam.

use super::tracked_slot_array_construct::TrackedSlotArray;
use super::empty_destructor_1070b4::empty_destructor_1070b4;
use crate::heap::veneers::operator_delete;

unsafe fn remove_with(array: *mut TrackedSlotArray, index: i32, delete: impl FnOnce(*mut u8)) {
    if index < 0 || (*array).slots as i32 <= index { return; }
    let handle = (*array).data.add(index as usize).read();
    if handle == 0 { return; }
    let handle = empty_destructor_1070b4(handle as usize as *mut core::ffi::c_void);
    delete(handle.cast());
    (*array).data.add(index as usize).write(0);
    (*array).used = (*array).used.wrapping_sub(1);
}

/// # Safety
/// For nonnegative indices, `array` must be a valid writable tracked header.
/// In-range slots must be readable/writable and live handles must uniquely own
/// tag-2 allocations. Deletion must leave the header and its current storage
/// valid. Negative indices access no memory.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_empty_handle_remove(array: *mut TrackedSlotArray, index: i32) {
    remove_with(array, index, |handle| operator_delete(handle));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn array(slots: &mut [u32], used: u32) -> TrackedSlotArray {
        TrackedSlotArray {
            data: slots.as_mut_ptr(), slots: slots.len() as u32, used,
            options: 17, growth: 2, tracker_label: core::ptr::null_mut(),
        }
    }

    #[test]
    fn signed_bounds_and_null_slots_preserve_state() {
        unsafe {
            tracked_empty_handle_remove(core::ptr::null_mut(), i32::MIN);
            for capacity in [0, 3, 0x8000_0000, u32::MAX] {
                for index in [-1, 0, 2, 3, i32::MAX] {
                    let mut slots = [0, 22, 0];
                    let mut header = array(&mut slots, 7);
                    header.slots = capacity;
                    remove_with(&mut header, index, |_| panic!("invalid deletion"));
                    assert_eq!(slots, [0, 22, 0]);
                    assert_eq!((header.slots, header.used, header.options, header.growth), (capacity, 7, 17, 2));
                }
            }
        }
    }

    #[test]
    fn live_slots_are_deleted_before_clearing_and_only_once() {
        for index in 0..3 {
            let mut slots = [11, 22, 33];
            let mut header = array(&mut slots, 3);
            let pointer = &mut header as *mut TrackedSlotArray;
            unsafe {
                remove_with(pointer, index, |handle| {
                    assert_eq!(handle as usize, [11, 22, 33][index as usize] as usize);
                    assert_eq!((*pointer).data.add(index as usize).read(), handle as usize as u32);
                    assert_eq!((*pointer).used, 3);
                });
                let mut expected = [11, 22, 33];
                expected[index as usize] = 0;
                assert_eq!(slots, expected);
                assert_eq!(header.used, 2);
                remove_with(pointer, index, |_| panic!("double deletion"));
                assert_eq!(header.used, 2);
            }
        }
    }

    #[test]
    fn delete_mutations_are_reloaded_and_used_wraps() {
        for used in [0, 1, u32::MAX] {
            let mut old = [11, 22, 33];
            let mut replacement = [44, 55, 66];
            let mut header = array(&mut old, 8);
            let pointer = &mut header as *mut TrackedSlotArray;
            unsafe {
                remove_with(pointer, 1, |_| {
                    (*pointer).data = replacement.as_mut_ptr();
                    (*pointer).used = used;
                });
            }
            assert_eq!(old, [11, 22, 33]);
            assert_eq!(replacement, [44, 0, 66]);
            assert_eq!(header.used, used.wrapping_sub(1));
            assert_eq!((header.slots, header.options, header.growth), (3, 17, 2));
            assert!(header.tracker_label.is_null());
        }
    }
}
