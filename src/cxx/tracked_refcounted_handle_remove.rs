//! Remove a tracked, heap-allocated refcounted handle.
//!
//! `FUN_083d4568` @ 0x083d4568: true extent 76 bytes,
//! [0x083d4568, 0x083d45b4), ending in POP before the next PUSH.
//! Whole-image A32 decoding: zero incoming plain BLs, one incoming BLNE
//! at 0x0810612c; two outgoing plain BLs, zero predicated outgoing BLs.
//! Reject negative indices and indices >= signed capacity; ignore NULL slots.
//! Release the handle via 0x0816ccb0, tag-2 delete the returned handle slot,
//! reload storage, clear the indexed word, then wrapping-decrement used.
//! Ghidra's 48-byte extent incorrectly stops at its noreturn delete annotation.
//! Deliberate deviations: header and handle pointers widen on hosts; tracker
//! storage remains u32. LLVM may replace predication with branches. Generic
//! delete injection tests post-destruction mutations without a runtime seam.

use super::tracked_slot_array_construct::TrackedSlotArray;
use super::handle::{refcounted_ptr_release_dtor_copy, RefcountedBody};
use crate::heap::veneers::operator_delete;

unsafe fn remove_with(array: *mut TrackedSlotArray, index: i32, delete: impl FnOnce(*mut u8)) {
    if index < 0 || (*array).slots as i32 <= index { return; }
    let handle = (*array).data.add(index as usize).read();
    if handle == 0 { return; }
    let handle = refcounted_ptr_release_dtor_copy(handle as usize as *mut *mut RefcountedBody);
    delete(handle.cast());
    (*array).data.add(index as usize).write(0);
    (*array).used = (*array).used.wrapping_sub(1);
}

/// # Safety
/// Nonnegative indices require a valid header; in-range storage must be valid.
/// Nonzero words must own tag-2 allocations holding valid refcounted handles.
/// Destruction must leave the header and its reloaded storage valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_refcounted_handle_remove(array: *mut TrackedSlotArray, index: i32) {
    remove_with(array, index, |handle| operator_delete(handle));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(data: &mut [u32], used: u32) -> TrackedSlotArray {
        TrackedSlotArray { data: data.as_mut_ptr(), slots: data.len() as u32,
            used, options: 17, growth: 2, tracker_label: core::ptr::null_mut() }
    }

    #[test]
    fn signed_bounds_and_empty_slots_do_not_release() {
        unsafe {
            tracked_refcounted_handle_remove(core::ptr::null_mut(), i32::MIN);
            for capacity in [0, 3, 0x8000_0000, u32::MAX] {
                for index in [-1, 0, 2, 3, i32::MAX] {
                    let mut slots = [0, 22, 0];
                    let mut array = header(&mut slots, 7);
                    array.slots = capacity;
                    tracked_refcounted_handle_remove(&mut array, index);
                    assert_eq!(slots, [0, 22, 0]);
                    assert_eq!(array.used, 7);
                }
            }
        }
    }

    #[test]
    fn releases_shared_body_once_then_reloads_storage_and_count() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::TRACKED_REFCOUNTED_HANDLE_REMOVE, 4096,
        ).expect("low-address handle fixture");
        let handle = slab.cast::<*mut RefcountedBody>();
        for used in [0, 1, u32::MAX] {
            let mut body = RefcountedBody { opaque0: 0, refcount: 2, mutex: core::ptr::null_mut() };
            let mut old = [11, handle as usize as u32, 33];
            let mut replacement = [44, 55, 66];
            let mut array = header(&mut old, 8);
            let pointer = &mut array as *mut TrackedSlotArray;
            unsafe {
                handle.write(&mut body);
                remove_with(pointer, 1, |released| {
                    assert_eq!(released, handle.cast());
                    assert!(handle.read().is_null());
                    assert_eq!(body.refcount, 1);
                    assert_eq!(old[1], handle as usize as u32);
                    assert_eq!((*pointer).used, 8);
                    (*pointer).data = replacement.as_mut_ptr();
                    (*pointer).used = used;
                });
                remove_with(pointer, 1, |_| panic!("double release"));
            }
            assert_eq!(old, [11, handle as usize as u32, 33]);
            assert_eq!(replacement, [44, 0, 66]);
            assert_eq!(array.used, used.wrapping_sub(1));
            assert_eq!((array.slots, array.options, array.growth), (3, 17, 2));
        }
    }
}
