//! Remove an owned object with an empty destructor from a tracked slot array.
//!
//! `FUN_083d4a48` @ 0x083d4a48: true size 76 bytes,
//! [0x083d4a48, 0x083d4a94), ending in POP before the next constructor PUSH.
//! Whole-image aligned A32 decoding verifies zero incoming plain BLs and one
//! incoming BLNE at 0x0810618c; two outgoing plain BLs, zero predicated BLs.
//! Reject negative indices and indices >= signed capacity; ignore NULL slots.
//! Call empty_destructor, tag-2 delete its returned owner, reload storage, clear
//! the selected slot, then decrement the reloaded used count modulo 2^32.
//! Ghidra's erroneous noreturn delete annotation truncates the final 28 bytes.
//! Deliberate deviations: native header pointers widen on hosts; slot words
//! remain u32. LLVM may branch instead of predicate and change registers.
//! Generic delete injection exercises lifecycle mutations without a new seam.
//! ARM review: LLVM removes the inert empty_destructor BL despite noinline;
//! its identity result feeds the retained operator_delete BL. Signed guards,
//! NULL handling, slot clearing and post-delete storage/count reloads remain.

use super::tracked_slot_array_construct::TrackedSlotArray;
use super::empty_destructor::empty_destructor;
use crate::heap::veneers::operator_delete;

unsafe fn remove_with(array: *mut TrackedSlotArray, index: i32, delete: impl FnOnce(*mut u8)) {
    if index < 0 || (*array).slots as i32 <= index { return; }
    let owner = (*array).data.add(index as usize).read();
    if owner == 0 { return; }
    let owner = empty_destructor(owner as usize as *mut core::ffi::c_void);
    delete(owner.cast());
    (*array).data.add(index as usize).write(0);
    (*array).used = (*array).used.wrapping_sub(1);
}

/// # Safety
/// For nonnegative indices, `array` must be a valid writable tracked header.
/// In-range slots must be readable/writable, and nonzero entries must uniquely
/// own allocations suitable for tag-2 deletion. Deletion must leave the header
/// and its current slot storage valid. Negative indices do not access memory.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_opaque_owner_remove(array: *mut TrackedSlotArray, index: i32) {
    remove_with(array, index, |owner| operator_delete(owner));
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
    fn signed_bounds_and_empty_slots_are_inert() {
        unsafe {
            tracked_opaque_owner_remove(core::ptr::null_mut(), i32::MIN);
            for capacity in [0, 3, 0x8000_0000, u32::MAX] {
                for index in [-1, 0, 2, 3, i32::MAX] {
                    let mut slots = [0, 22, 0];
                    let mut header = array(&mut slots, 7);
                    header.slots = capacity;
                    tracked_opaque_owner_remove(&mut header, index);
                    assert_eq!(slots, [0, 22, 0]);
                    assert_eq!((header.slots, header.used, header.options, header.growth), (capacity, 7, 17, 2));
                }
            }
        }
    }

    #[test]
    fn removes_each_live_slot_once_and_preserves_neighbors() {
        for index in 0..3 {
            let mut slots = [11, 22, 33];
            let mut header = array(&mut slots, 3);
            let pointer = &mut header as *mut TrackedSlotArray;
            unsafe {
                remove_with(pointer, index, |owner| {
                    assert_eq!(owner as usize, [11, 22, 33][index as usize] as usize);
                    assert_eq!((*pointer).data.add(index as usize).read(), owner as usize as u32);
                    assert_eq!((*pointer).used, 3);
                });
                let mut expected = [11, 22, 33];
                expected[index as usize] = 0;
                assert_eq!(slots, expected);
                assert_eq!(header.used, 2);
                remove_with(pointer, index, |_| panic!("double delete"));
                assert_eq!(header.used, 2);
            }
        }
    }

    #[test]
    fn reloads_storage_and_used_after_delete_with_wrapping_subtraction() {
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
