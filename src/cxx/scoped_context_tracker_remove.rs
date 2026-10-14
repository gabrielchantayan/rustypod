//! Remove an owned scoped-context token from a sparse tracker.

use crate::app::scoped_context::{scoped_context_destroy, ScopedContext};
use crate::heap::veneers::operator_delete;

/// Accessed prefix; target offsets +0, +4, +8. Host pointers widen naturally.
#[repr(C)]
pub struct ScopedContextTracker {
    pub slots: *mut *mut ScopedContext,
    pub capacity: i32,
    pub live_count: u32,
}

/// Original: FUN_083d4ca8 @ 0x083d4ca8, 76 bytes through 0x083d4cf4.
/// Raw A32 scan: zero plain incoming BLs, one BLNE at 0x081061e8;
/// two plain outgoing BLs, zero predicated outgoing BLs.
/// Reject negative indices and indices >= signed capacity; skip NULL slots.
/// Destroy and delete the token, reload slots, clear the indexed slot, and
/// decrement the current live count modulo 2^32. The original destructor is
/// exactly BX LR and preserves r0, so delete receives the original token.
/// Deviations: native-width repr(C) pointers widen the host model; LLVM may
/// eliminate the empty destructor call and replaces predication with branches.
///
/// # Safety
/// For nonnegative indices, tracker must be valid. In-range indices require
/// valid slot storage and a live owned token unless NULL. Deletion must leave
/// the tracker and its reloaded slot storage valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_tracker_remove(tracker: *mut ScopedContextTracker, index: i32) {
    remove_with(tracker, index, |token| {
        scoped_context_destroy(token);
        operator_delete(token.cast());
    });
}

#[inline(always)]
unsafe fn remove_with(
    tracker: *mut ScopedContextTracker,
    index: i32,
    delete: impl FnOnce(*mut ScopedContext),
) {
    if index < 0 || index >= (*tracker).capacity {
        return;
    }
    let token = *(*tracker).slots.add(index as usize);
    if token.is_null() {
        return;
    }
    delete(token);
    *(*tracker).slots.add(index as usize) = core::ptr::null_mut();
    (*tracker).live_count = (*tracker).live_count.wrapping_sub(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    #[test]
    fn signed_bounds_and_empty_slots_preserve_state() {
        unsafe {
            for index in [i32::MIN, -1] {
                scoped_context_tracker_remove(null_mut(), index);
            }
            for capacity in [i32::MIN, -1, 0, 1, 3] {
                let mut slots = [null_mut(); 3];
                let mut tracker = ScopedContextTracker {
                    slots: slots.as_mut_ptr(), capacity, live_count: 17,
                };
                for index in [0, 1, 2, 3, i32::MAX] {
                    remove_with(&mut tracker, index, |_| panic!("delete"));
                    assert_eq!(tracker.live_count, 17);
                    assert_eq!(tracker.capacity, capacity);
                    assert_eq!(tracker.slots, slots.as_mut_ptr());
                    assert_eq!(slots, [null_mut(); 3]);
                }
            }
        }
    }

    #[test]
    fn deletion_precedes_clear_and_reloads_storage_and_count() {
        unsafe {
            let mut token = core::mem::MaybeUninit::<ScopedContext>::zeroed();
            let pointer = token.as_mut_ptr();
            let mut slots = [pointer; 3];
            let mut replacement = [pointer; 3];
            let mut tracker = ScopedContextTracker {
                slots: slots.as_mut_ptr(), capacity: 3, live_count: 7,
            };
            let owner = &mut tracker as *mut ScopedContextTracker;
            remove_with(owner, 2, |p| {
                assert_eq!(p, pointer);
                assert_eq!(slots[2], pointer);
                assert_eq!((*owner).live_count, 7);
                (*owner).slots = replacement.as_mut_ptr();
                (*owner).live_count = 0;
            });
            assert_eq!(slots, [pointer; 3]);
            assert_eq!(replacement, [pointer, pointer, null_mut()]);
            assert_eq!(tracker.live_count, u32::MAX);
            assert_eq!(tracker.capacity, 3);
            remove_with(owner, 2, |_| panic!("delete twice"));
            assert_eq!(tracker.live_count, u32::MAX);
        }
    }
}
