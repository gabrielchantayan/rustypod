//! Destroy an owned string-with-member and erase: `FUN_083d17d8` @
//! `0x083d17d8`, **68 bytes**, [0x083d17d8,0x083d181c).
//! Raw A32 ends in a tail B before the next independent PUSH. Three outgoing
//! plain BLs (0x083d6b6c, 0x0828a148, 0x082aad24), zero predicated BLs;
//! one incoming plain BL at 0x0815bc00, zero predicated BLs.
//!
//! If ownership byte +0x10 is nonzero, fetch the indexed pointer through
//! vtable +0x40 and its cell load. Destroy and tag-2-delete a non-NULL object,
//! then base-erase using the unchanged signed index and return its result.
//! Cleanup precedes validation; the cell is not cleared. All callees reuse
//! existing ports. Deviations: host pointers widen, accessor indices preserve
//! target u32 bits, and LLVM selects registers and tail-call layout.

use super::observable_array::{observable_array_erase_at, ObservableArray};
use super::templates::container_element_at_alias_6b6c;
use super::string_object::{string_object_with_owned_member_destroy, StringObjectWithOwnedMember};
use crate::heap::veneers::operator_delete;
#[cfg(not(target_os = "none"))]
use super::opaque_observable_array_dispose_elements::HostOpaqueObservableArray;

#[inline(always)]
unsafe fn erase_with(this: *mut ObservableArray, index: i32,
    cleanup: impl FnOnce(*mut StringObjectWithOwnedMember)) -> i32 {
    #[cfg(target_os = "none")]
    let enabled = this.cast::<u8>().add(0x10).read_volatile();
    #[cfg(not(target_os = "none"))]
    let enabled = core::ptr::addr_of!((*this.cast::<HostOpaqueObservableArray>()).enabled).read_volatile();
    if enabled != 0 {
        let object = container_element_at_alias_6b6c(this.cast(), index as u32 as usize).cast::<StringObjectWithOwnedMember>();
        if !object.is_null() {
            cleanup(object);
        }
    }
    observable_array_erase_at(this, index)
}

/// # Safety
/// `this` must satisfy base erase's contract. When ownership is enabled,
/// its accessor must accept the original index before validation and return
/// a readable cell containing NULL or an owned StringObjectWithOwnedMember.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_string_member_array_erase_at(this: *mut ObservableArray, index: i32) -> i32 {
    erase_with(this, index, |object| {
        operator_delete(string_object_with_owned_member_destroy(object).cast());
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[repr(C)]
    struct Fixture {
        array: HostOpaqueObservableArray,
        element: *mut StringObjectWithOwnedMember,
        fetched: usize,
    }

    unsafe extern "C" fn element_at(this: *mut u8, index: usize) -> *mut *mut u8 {
        let fixture = &mut *this.cast::<Fixture>();
        fixture.fetched = index;
        (&mut fixture.element as *mut *mut StringObjectWithOwnedMember).cast()
    }

    #[test]
    fn cleanup_precedes_validation_without_clearing_cell() {
        let table = [element_at as unsafe extern "C" fn(*mut u8, usize) -> *mut *mut u8; 17];
        for enabled in [0, 1, 0x80, 0xff] {
            for index in [i32::MIN, -1, 0, i32::MAX] {
                for null in [false, true] {
                    let mut storage = core::mem::MaybeUninit::<StringObjectWithOwnedMember>::zeroed();
                    let pointer = if null { core::ptr::null_mut() } else { storage.as_mut_ptr() };
                    let mut fixture = Fixture {
                        array: HostOpaqueObservableArray { vtable: table.as_ptr().cast(), count: 0,
                            unresolved_08_0f: [0; 8], enabled },
                        element: pointer, fetched: 77,
                    };
                    let cleaned = Cell::new(false);
                    let result = unsafe {
                        erase_with((&mut fixture.array as *mut HostOpaqueObservableArray).cast(), index, |p| {
                            assert_eq!(p, pointer);
                            // Exercise cleanup on a correctly sized object.
                            (*p).owned_member = core::ptr::null_mut();
                            cleaned.set(true);
                        })
                    };
                    assert_eq!(result, -1);
                    assert_eq!(cleaned.get(), enabled != 0 && !null);
                    assert_eq!(fixture.fetched, if enabled != 0 { index as u32 as usize } else { 77 });
                    assert_eq!(fixture.element, pointer);
                }
            }
        }
    }

    #[test]
    fn disabled_empty_array_needs_no_vtable() {
        let mut array = HostOpaqueObservableArray { vtable: core::ptr::null(), count: 0,
            unresolved_08_0f: [0; 8], enabled: 0 };
        for index in [i32::MIN, -1, 0, i32::MAX] {
            assert_eq!(unsafe { owned_string_member_array_erase_at((&mut array as *mut HostOpaqueObservableArray).cast(), index) }, -1);
        }
    }
}
