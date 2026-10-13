//! Owned observable-array slot replacement — FUN_083e7544 @ 0x083e7544.
//! True size: 56 bytes, [0x083e7544, 0x083e757c), ending with pop
//! before the next independent push. Raw whole-image A32 decoding verifies
//! one incoming plain BL (0x081fa688), no predicated BLs; two outgoing
//! plain BLs (0x083e7568, 0x083e7570), no predicated BLs.
//!
//! Leave an identical slot unchanged. Otherwise destroy a non-NULL old
//! allocation's ObservableArray at +4, delete the returned pointer minus
//! four, then publish the saved replacement. The sole caller passes its
//! member at +0x30. Ghidra incorrectly treats operator_delete as noreturn.
//! Deliberate deviations: slot pointers widen on hosts; the array retains
//! target-word layout. Calls use the existing canonical Rust ports.

use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};
use crate::heap::veneers::operator_delete;

#[inline(always)]
unsafe fn replace_with(
    slot: *mut *mut u8, replacement: *mut u8,
    destroy: impl FnOnce(*mut ObservableArray) -> *mut ObservableArray,
    delete: impl FnOnce(*mut u8),
) {
    let old = slot.read_volatile();
    if old == replacement { return; }
    if !old.is_null() {
        let destroyed = destroy(old.add(4).cast());
        delete(destroyed.cast::<u8>().sub(4));
    }
    slot.write_volatile(replacement);
}

/// Replace the allocation owned by a pointer slot, destroying its array at +4.
///
/// # Safety
/// `slot` must be aligned and writable, and remain live through teardown.
/// A non-NULL old allocation must contain a live ObservableArray at +4
/// and support tag-2 operator delete. Ownership of `replacement` transfers
/// without validation or retain.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_observable_array_slot_replace(
    slot: *mut *mut u8, replacement: *mut u8,
) {
    replace_with(slot, replacement,
        |array| observable_array_destruct(array), |allocation| operator_delete(allocation));
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{cell::Cell, ptr::null_mut};

    #[test]
    fn unchanged_and_null_old_slots_skip_teardown() {
        let mut allocation = [0u32; 5];
        let pointer = allocation.as_mut_ptr().cast();
        for old in [null_mut(), pointer] {
            let mut slot = old;
            unsafe { replace_with(&mut slot, old,
                |_| panic!("destroy unchanged"), |_| panic!("delete unchanged")); }
            assert_eq!(slot, old);
        }
        let mut slot = null_mut();
        unsafe { replace_with(&mut slot, pointer,
            |_| panic!("destroy NULL"), |_| panic!("delete NULL")); }
        assert_eq!(slot, pointer);
    }

    #[test]
    fn teardown_precedes_publish_and_uses_destructor_return() {
        for clear in [false, true] {
            let mut old = [0u32; 5];
            let mut redirected = [0u32; 5];
            let mut new = [0u32; 5];
            let old_pointer = old.as_mut_ptr().cast::<u8>();
            let redirected_pointer = redirected.as_mut_ptr().cast::<u8>();
            let replacement = if clear { null_mut() } else { new.as_mut_ptr().cast() };
            let mut slot = old_pointer;
            let slot_pointer = &mut slot as *mut *mut u8;
            let stage = Cell::new(0);
            unsafe {
                replace_with(slot_pointer, replacement, |array| {
                    assert_eq!(array.cast::<u8>(), old_pointer.add(4));
                    assert_eq!(*slot_pointer, old_pointer);
                    stage.set(1);
                    *slot_pointer = redirected_pointer;
                    redirected_pointer.add(4).cast()
                }, |allocation| {
                    assert_eq!(stage.get(), 1);
                    assert_eq!(allocation, redirected_pointer);
                    assert_eq!(*slot_pointer, redirected_pointer);
                    *slot_pointer = old_pointer;
                    stage.set(2);
                });
            }
            assert_eq!(stage.get(), 2);
            assert_eq!(slot, replacement);
        }
    }
}
