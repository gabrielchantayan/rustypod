//! Delete an owned element then erase: `FUN_083d1f80` @ `0x083d1f80`.
//!
//! True raw A32 extent [0x083d1f80,0x083d1fb8), 56 bytes, ends in a
//! tail B before the next independent PUSH. One incoming plain BL at
//! 0x081b937c, zero predicated incoming BLs. Two outgoing plain BLs to
//! container_element_at_alias_6c6c and operator_delete, zero predicated BLs,
//! then a tail B to observable_array_erase_at. If byte +0x10 is nonzero,
//! fetch the indexed element and tag-2-delete it, including NULL, before
//! base erase validation. Preserve the signed index and base return value;
//! do not clear the cell or invoke an element destructor.
//! Deliberate deviations: host header/vtable pointers widen; the signed
//! index is zero-extended from its target u32 bit pattern for the existing
//! usize accessor ABI. LLVM may change registers and tail-call selection.

use super::observable_array::{observable_array_erase_at, ObservableArray};
use super::templates::container_element_at_alias_6c6c;
use crate::heap::veneers::operator_delete;
#[cfg(not(target_os = "none"))]
use super::opaque_observable_array_dispose_elements::HostOpaqueObservableArray;

#[inline(always)]
unsafe fn erase_with(this: *mut ObservableArray, index: i32, delete: impl FnOnce(*mut u8)) -> i32 {
    #[cfg(target_os = "none")]
    let enabled = this.cast::<u8>().add(0x10).read_volatile();
    #[cfg(not(target_os = "none"))]
    let enabled = core::ptr::addr_of!((*this.cast::<HostOpaqueObservableArray>()).enabled).read_volatile();
    if enabled != 0 {
        delete(container_element_at_alias_6c6c(this.cast(), index as u32 as usize));
    }
    observable_array_erase_at(this, index)
}

/// # Safety
/// `this` must be a live observable-array-derived object. When ownership is
/// enabled, its +0x40 accessor must return a readable cell for the unchanged
/// index, containing NULL or a tag-2-owned allocation. Base erase's virtual
/// operations and observers must remain valid after deletion.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_element_array_erase_at(this: *mut ObservableArray, index: i32) -> i32 {
    erase_with(this, index, |element| operator_delete(element))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[repr(C)]
    struct Fixture {
        array: HostOpaqueObservableArray,
        element: *mut u8,
        fetched: usize,
    }

    unsafe extern "C" fn element_at(this: *mut u8, index: usize) -> *mut *mut u8 {
        let fixture = &mut *this.cast::<Fixture>();
        fixture.fetched = index;
        &mut fixture.element
    }

    #[test]
    fn deletes_before_real_base_rejects_without_clearing_cell() {
        let table = [element_at as unsafe extern "C" fn(*mut u8, usize) -> *mut *mut u8; 17];
        for enabled in [0, 1, 0x80, 0xff] {
            for index in [i32::MIN, -1, 0, i32::MAX] {
                for null in [false, true] {
                    let mut allocation = 0x1234u32;
                    let pointer = if null { core::ptr::null_mut() } else { (&mut allocation as *mut u32).cast() };
                    let mut fixture = Fixture {
                        array: HostOpaqueObservableArray { vtable: table.as_ptr().cast(), count: 0,
                            unresolved_08_0f: [0; 8], enabled },
                        element: pointer, fetched: 77,
                    };
                    let deleted = Cell::new(false);
                    let result = unsafe {
                        erase_with((&mut fixture.array as *mut HostOpaqueObservableArray).cast(), index, |p| {
                            assert_eq!(p, pointer);
                            if !p.is_null() { p.cast::<u32>().write(0xdead); }
                            deleted.set(true);
                        })
                    };
                    assert_eq!(result, -1);
                    assert_eq!(deleted.get(), enabled != 0);
                    assert_eq!(fixture.fetched, if enabled != 0 { index as u32 as usize } else { 77 });
                    assert_eq!(fixture.element, pointer);
                    assert_eq!(allocation, if enabled != 0 && !null { 0xdead } else { 0x1234 });
                }
            }
        }
    }

    #[test]
    fn disabled_empty_array_needs_no_vtable() {
        let mut array = HostOpaqueObservableArray { vtable: core::ptr::null(), count: 0,
            unresolved_08_0f: [0; 8], enabled: 0 };
        for index in [i32::MIN, -1, 0, i32::MAX] {
            assert_eq!(unsafe { owned_element_array_erase_at((&mut array as *mut HostOpaqueObservableArray).cast(), index) }, -1);
        }
    }
}
