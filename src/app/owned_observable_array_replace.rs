//! Owned observable-array replacement — `FUN_0817e4c8` @ 0x0817e4c8.
//! True extent: 56 bytes, [0x0817e4c8, 0x0817e500). Raw A32 decoding
//! verifies two inbound plain BLs, zero predicated BLs; two outbound plain
//! BLs, zero predicated BLs. The next entry is an independent `bx lr`.
//!
//! If the owned pointer at +0x20 equals the replacement, do nothing.
//! Otherwise destroy a non-NULL old allocation's observable-array member
//! at +4, subtract four from the destructor's returned pointer, and delete
//! that allocation. Publish the saved replacement only after teardown.
//! Deliberate deviations: native owner pointers widen on hosts; the array
//! retains its target-word layout. Calls use the existing Rust ports, not
//! retail addresses. Ghidra incorrectly marks operator_delete as noreturn.

use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};
use crate::heap::veneers::operator_delete;

#[repr(C)]
pub struct ObservableArrayOwner {
    pub opaque_prefix: [u32; 8],
    pub owned_array: *mut u8,
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(ObservableArrayOwner, owned_array) == 0x20);

#[inline(always)]
unsafe fn replace_with(
    owner: *mut ObservableArrayOwner, replacement: *mut u8,
    destroy: impl FnOnce(*mut ObservableArray) -> *mut ObservableArray,
    delete: impl FnOnce(*mut u8),
) {
    let old = core::ptr::addr_of!((*owner).owned_array).read_volatile();
    if old == replacement { return; }
    if !old.is_null() {
        let destroyed = destroy(old.add(4).cast());
        delete(destroyed.cast::<u8>().sub(4));
    }
    core::ptr::addr_of_mut!((*owner).owned_array).write_volatile(replacement);
}

/// Replace the owned allocation whose observable-array subobject begins at +4.
///
/// # Safety
/// `owner` must be writable and aligned. A non-NULL old allocation must
/// contain a live ObservableArray at +4 and support tag-2 operator delete.
/// `replacement` transfers ownership to the caller's object; no retain or
/// validation is performed. Teardown callbacks must leave `owner` alive.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_observable_array_replace(
    owner: *mut ObservableArrayOwner, replacement: *mut u8,
) {
    replace_with(owner, replacement,
        |array| observable_array_destruct(array), |allocation| operator_delete(allocation));
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;
    use core::cell::Cell;

    #[test]
    fn identical_and_empty_slots_do_not_destroy() {
        let mut storage = [0u32; 5];
        let pointer = storage.as_mut_ptr().cast();
        for old in [null_mut(), pointer] {
            let mut owner = ObservableArrayOwner { opaque_prefix: [0xa5a5a5a5; 8], owned_array: old };
            unsafe { replace_with(&mut owner, old, |_| panic!("destroy unchanged"), |_| panic!("delete unchanged")); }
            assert_eq!(owner.owned_array, old);
            assert_eq!(owner.opaque_prefix, [0xa5a5a5a5; 8]);
        }
        let mut owner = ObservableArrayOwner { opaque_prefix: [7; 8], owned_array: null_mut() };
        unsafe { replace_with(&mut owner, pointer, |_| panic!("destroy NULL"), |_| panic!("delete NULL")); }
        assert_eq!(owner.owned_array, pointer);
        assert_eq!(owner.opaque_prefix, [7; 8]);
    }

    #[test]
    fn teardown_return_and_callback_mutation_do_not_change_saved_replacement() {
        for clear in [false, true] {
            let mut old = [0u32; 5];
            let mut returned = [0u32; 5];
            let mut new = [0u32; 5];
            let old_pointer = old.as_mut_ptr().cast::<u8>();
            let returned_pointer = returned.as_mut_ptr().cast::<u8>();
            let replacement = if clear { null_mut() } else { new.as_mut_ptr().cast() };
            let mut owner = ObservableArrayOwner { opaque_prefix: [42; 8], owned_array: old_pointer };
            let owner_pointer = &mut owner as *mut ObservableArrayOwner;
            let stage = Cell::new(0);
            unsafe {
                replace_with(owner_pointer, replacement, |array| {
                    assert_eq!(array.cast::<u8>(), old_pointer.add(4));
                    assert_eq!((*owner_pointer).owned_array, old_pointer);
                    stage.set(1);
                    (*owner_pointer).owned_array = returned_pointer;
                    returned_pointer.add(4).cast()
                }, |allocation| {
                    assert_eq!(stage.get(), 1);
                    assert_eq!(allocation, returned_pointer);
                    assert_eq!((*owner_pointer).owned_array, returned_pointer);
                    (*owner_pointer).owned_array = old_pointer;
                    stage.set(2);
                });
            }
            assert_eq!(stage.get(), 2);
            assert_eq!(owner.owned_array, replacement);
            assert_eq!(owner.opaque_prefix, [42; 8]);
        }
    }
}
