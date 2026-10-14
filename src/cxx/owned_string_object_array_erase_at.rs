//! Destroy and delete an owned StringObject, then erase: `FUN_083d1b58`
//! @ `0x083d1b58`. Raw A32 extent [0x083d1b58,0x083d1b9c), 68 bytes,
//! ends in a tail B before the next independent PUSH. Three outgoing plain
//! BLs (accessor 0x083d6bec, destructor 0x08201610, delete 0x082aad24),
//! zero predicated BLs; one incoming plain BL at 0x08201b0c, zero predicated.
//!
//! If ownership byte +0x10 is nonzero, fetch the indexed pointer through
//! vtable +0x40 and dereference its cell. Destroy and tag-2-delete a non-NULL
//! object, then always tail into base erase with the unchanged signed index.
//! Cleanup precedes base validation and leaves the cell untouched.
//! Deviations: host header pointers widen; the existing usize accessor gets
//! the zero-extended target u32 index bits. LLVM chooses registers and tail
//! calls. All callees reuse existing ports; no new fixed-address seams.

use super::observable_array::{observable_array_erase_at, ObservableArray};
use super::templates::container_element_at_alias_6bec;
use super::string_object::{string_object_destroy_08201610, StringObject};
use crate::heap::veneers::operator_delete;
#[cfg(not(target_os = "none"))]
use super::opaque_observable_array_dispose_elements::HostOpaqueObservableArray;

#[inline(always)]
unsafe fn erase_with(this: *mut ObservableArray, index: i32, cleanup: impl FnOnce(*mut StringObject)) -> i32 {
    #[cfg(target_os = "none")]
    let enabled = this.cast::<u8>().add(0x10).read_volatile();
    #[cfg(not(target_os = "none"))]
    let enabled = core::ptr::addr_of!((*this.cast::<HostOpaqueObservableArray>()).enabled).read_volatile();
    if enabled != 0 {
        let object = container_element_at_alias_6bec(this.cast(), index as u32 as usize).cast::<StringObject>();
        if !object.is_null() {
            cleanup(object);
        }
    }
    observable_array_erase_at(this, index)
}

/// # Safety
/// `this` must be a live observable array. If ownership is enabled, its
/// accessor must accept the original index even when base erase rejects it,
/// and return a readable cell containing NULL or an owned StringObject.
/// Base erase's virtual operations and observers must remain valid afterward.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_string_object_array_erase_at(this: *mut ObservableArray, index: i32) -> i32 {
    erase_with(this, index, |object| {
        operator_delete(string_object_destroy_08201610(object).cast());
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[repr(C)]
    struct Fixture {
        array: HostOpaqueObservableArray,
        element: *mut StringObject,
        fetched: usize,
    }

    unsafe extern "C" fn element_at(this: *mut u8, index: usize) -> *mut *mut u8 {
        let fixture = &mut *this.cast::<Fixture>();
        fixture.fetched = index;
        (&mut fixture.element as *mut *mut StringObject).cast()
    }

    #[test]
    fn ownership_and_null_guard_precede_real_base_validation() {
        let table = [element_at as unsafe extern "C" fn(*mut u8, usize) -> *mut *mut u8; 17];
        for enabled in [0, 1, 0x80, 0xff] {
            for index in [i32::MIN, -1, 0, i32::MAX] {
                for null in [false, true] {
                    let mut object = StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() };
                    let pointer = if null { core::ptr::null_mut() } else { &mut object as *mut StringObject };
                    let mut fixture = Fixture {
                        array: HostOpaqueObservableArray { vtable: table.as_ptr().cast(), count: 0,
                            unresolved_08_0f: [0; 8], enabled },
                        element: pointer, fetched: 77,
                    };
                    let cleaned = Cell::new(false);
                    let result = unsafe {
                        erase_with((&mut fixture.array as *mut HostOpaqueObservableArray).cast(), index, |p| {
                            assert_eq!(p, pointer);
                            (*p).payload = 0x1234usize as *mut u8;
                            cleaned.set(true);
                        })
                    };
                    assert_eq!(result, -1);
                    assert_eq!(cleaned.get(), enabled != 0 && !null);
                    assert_eq!(fixture.fetched, if enabled != 0 { index as u32 as usize } else { 77 });
                    assert_eq!(fixture.element, pointer);
                    assert_eq!(object.payload as usize, if enabled != 0 && !null { 0x1234 } else { 0 });
                }
            }
        }
    }

    #[test]
    fn disabled_empty_array_needs_no_vtable() {
        let mut array = HostOpaqueObservableArray { vtable: core::ptr::null(), count: 0,
            unresolved_08_0f: [0; 8], enabled: 0 };
        for index in [i32::MIN, -1, 0, i32::MAX] {
            assert_eq!(unsafe { owned_string_object_array_erase_at((&mut array as *mut HostOpaqueObservableArray).cast(), index) }, -1);
        }
    }
}
