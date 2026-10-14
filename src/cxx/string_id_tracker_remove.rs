//! Remove an owned (string, id) record from a sparse tracker.

use super::string_object::{string_id_record_destroy, StringIdRecord};
use crate::heap::veneers::operator_delete;

/// Accessed prefix of the tracker; target offsets are +0, +4, +8.
/// Native-width pointers deliberately widen the host model.
#[repr(C)]
pub struct StringIdTracker {
    pub slots: *mut *mut StringIdRecord,
    pub capacity: i32,
    pub live_count: u32,
}

/// Original: FUN_083d566c @ 0x083d566c, 76 bytes through 0x083d56b8.
/// Raw A32 scan: zero plain and one predicated incoming BL (BLNE at
/// 0x081062a0); two plain outgoing BLs, zero predicated outgoing BLs.
/// Reject negative indices and indices >= signed capacity. For a non-NULL
/// slot, destroy the StringIdRecord, delete the destructor's returned pointer,
/// reload the slot table, clear the indexed slot, then decrement the current
/// live count modulo 2^32. Empty slots do not change the count.
/// Deviations: repr(C) pointers widen on hosts; LLVM uses branches instead of
/// ARM predication. Existing destructor and heap dispatch remain unchanged.
///
/// # Safety
/// For nonnegative indices, tracker must be valid. An in-range index requires
/// valid slot storage and a live owned record (unless NULL). Lifecycle calls
/// must leave tracker and its reloaded slot table valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_id_tracker_remove(tracker: *mut StringIdTracker, index: i32) {
    remove_with(tracker, index, |record| string_id_record_destroy(record),
        |record| operator_delete(record.cast()));
}

#[inline(always)]
unsafe fn remove_with(
    tracker: *mut StringIdTracker,
    index: i32,
    destroy: impl FnOnce(*mut StringIdRecord) -> *mut StringIdRecord,
    delete: impl FnOnce(*mut StringIdRecord),
) {
    if index < 0 || index >= (*tracker).capacity {
        return;
    }
    let record = *(*tracker).slots.add(index as usize);
    if record.is_null() {
        return;
    }
    delete(destroy(record));
    *(*tracker).slots.add(index as usize) = core::ptr::null_mut();
    (*tracker).live_count = (*tracker).live_count.wrapping_sub(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::string_object::StringObject;
    use core::ptr::null_mut;

    #[test]
    fn invalid_indices_and_empty_slots_preserve_tracker() {
        unsafe {
            // Negative indices must not even read the owner.
            for index in [i32::MIN, -1] {
                string_id_tracker_remove(null_mut(), index);
            }
            for capacity in [i32::MIN, -1, 0, 1, 3] {
                let mut slots = [null_mut(); 3];
                let mut tracker = StringIdTracker {
                    slots: slots.as_mut_ptr(), capacity, live_count: 17,
                };
                for index in [0, 1, 2, 3, i32::MAX] {
                    remove_with(&mut tracker, index, |_| panic!("destroy"), |_| panic!("delete"));
                    assert_eq!(tracker.live_count, 17);
                    assert_eq!(tracker.capacity, capacity);
                    assert_eq!(tracker.slots, slots.as_mut_ptr());
                    assert_eq!(slots, [null_mut(); 3]);
                }
            }
        }
    }

    #[test]
    fn destroys_before_delete_then_reloads_storage_and_wraps_current_count() {
        unsafe {
            let mut record = StringIdRecord {
                vtable: core::ptr::null(),
                string: StringObject { vtable: core::ptr::null(), payload: null_mut() },
                id: 42,
            };
            let pointer = &mut record as *mut _;
            let mut returned = StringIdRecord {
                vtable: core::ptr::null(),
                string: StringObject { vtable: core::ptr::null(), payload: null_mut() },
                id: 99,
            };
            let returned_pointer = &mut returned as *mut _;
            let mut slots = [pointer; 3];
            let mut replacement = [returned_pointer; 3];
            let mut tracker = StringIdTracker {
                slots: slots.as_mut_ptr(), capacity: 3, live_count: 7,
            };
            let owner = &mut tracker as *mut StringIdTracker;
            let destroyed = core::cell::Cell::new(false);
            remove_with(owner, 2, |p| {
                assert_eq!(p, pointer);
                assert_eq!((*owner).live_count, 7);
                destroyed.set(true);
                returned_pointer
            }, |p| {
                assert!(destroyed.get());
                assert_eq!(p, returned_pointer);
                assert_eq!(slots[2], pointer);
                (*owner).slots = replacement.as_mut_ptr();
                (*owner).live_count = 0;
            });
            assert_eq!(slots, [pointer; 3]);
            assert_eq!(replacement, [returned_pointer, returned_pointer, null_mut()]);
            assert_eq!(tracker.live_count, u32::MAX);
            assert_eq!(tracker.capacity, 3);
            // A second removal of the now-empty slot is a no-op.
            remove_with(owner, 2, |_| panic!("destroy twice"), |_| panic!("delete twice"));
            assert_eq!(tracker.live_count, u32::MAX);
        }
    }
}
