//! Owned observable-array slot replacement — FUN_083e71d8 @ 0x083e71d8.
//! True size: 56 bytes, [0x083e71d8, 0x083e7210), ending with pop
//! before the next independent push. Whole-image raw A32 decoding verifies
//! one incoming plain BL at 0x081fa77c, zero predicated BLs; two outgoing
//! plain BLs at 0x083e71fc and 0x083e7204, zero predicated BLs.
//!
//! Leave an identical slot unchanged. Otherwise destroy the non-NULL old
//! allocation's ObservableArray at +4, delete the destructor return minus
//! four, then publish the saved replacement. The caller supplies its member
//! at +0x38. Ghidra incorrectly marks operator_delete as noreturn.
//! Deliberate deviations: native slot pointers widen on hosts. Reuse the
//! identical slot-replacement helper and canonical Rust callees; LLVM may
//! fold identical exported entries without changing their contracts.

use super::owned_observable_array_slot_replace::replace_with;
use crate::cxx::observable_array::observable_array_destruct;
use crate::heap::veneers::operator_delete;

/// Replace an owned allocation containing an observable-array member at +4.
///
/// # Safety
/// `slot` must be aligned, writable, and remain live throughout teardown.
/// A non-NULL old allocation must contain a live ObservableArray at +4 and
/// support tag-2 operator delete. Replacement ownership transfers without
/// validation or retain.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_observable_array_slot_replace_38(
    slot: *mut *mut u8, replacement: *mut u8,
) {
    replace_with(slot, replacement,
        |array| observable_array_destruct(array), |allocation| operator_delete(allocation));
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    #[test]
    fn identity_skips_invalid_payload_and_null_slot_accepts_replacement() {
        let mut allocation = [0xdeadbeefu32; 5];
        let pointer = allocation.as_mut_ptr().cast();
        let mut slot = null_mut();
        unsafe {
            owned_observable_array_slot_replace_38(&mut slot, null_mut());
            assert!(slot.is_null());
            owned_observable_array_slot_replace_38(&mut slot, pointer);
            assert_eq!(slot, pointer);
            // This is not a live array: teardown on identity would be invalid.
            owned_observable_array_slot_replace_38(&mut slot, pointer);
        }
        assert_eq!(slot, pointer);
        assert_eq!(allocation, [0xdeadbeef; 5]);
    }
}
