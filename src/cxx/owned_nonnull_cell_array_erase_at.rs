//! Delete a non-NULL owned cell allocation before erasing its index.
//!
//! `FUN_083d05b8` @ `0x083d05b8`: 72 bytes, [0x083d05b8,0x083d0600),
//! ending in a tail B before the next independent PUSH. Raw A32 decoding
//! finds zero outgoing plain BLs, one BLNE to operator_delete @ 0x082aad24,
//! one virtual BLX through slot +0x40, and a tail B to the existing
//! observable_array_erase_at @ 0x08271bec. One incoming plain BL at
//! 0x08264bdc; no predicated incoming BLs.
//!
//! If ownership byte +0x10 is nonzero, fetch the cell with the unchanged
//! signed index and delete its allocation only when non-NULL. Then perform
//! base erase, including its validation/sentinel handling, and return its
//! result. Neither clear the cell nor invoke an element destructor.
//! Deliberate deviations: native-pointer host fixtures replace target words;
//! LLVM may change register allocation, predication and tail-call selection.

use super::observable_array::{observable_array_erase_at, ObservableArray};
use crate::heap::veneers::operator_delete;
#[cfg(not(target_os = "none"))]
use super::opaque_observable_array_dispose_elements::HostOpaqueObservableArray;

#[inline(always)]
unsafe fn erase_with(
    this: *mut ObservableArray, index: i32,
    delete: impl FnOnce(*mut u8),
    erase: impl FnOnce(*mut ObservableArray, i32) -> i32,
) -> i32 {
    #[cfg(target_os = "none")]
    let allocation = if this.cast::<u8>().add(0x10).read_volatile() != 0 {
        let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
        let element_at: unsafe extern "C" fn(*mut ObservableArray, i32) -> *mut u32 =
            core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize);
        element_at(this, index).read_volatile() as usize as *mut u8
    } else { core::ptr::null_mut() };
    #[cfg(not(target_os = "none"))]
    let allocation = {
        let array = &*this.cast::<HostOpaqueObservableArray>();
        if array.enabled != 0 {
            ((*array.vtable).element_at)(this.cast(), index).read().element
        } else { core::ptr::null_mut() }
    };
    if !allocation.is_null() {
        delete(allocation);
    }
    erase(this, index)
}

/// # Safety
/// `this` must satisfy the base observable-array erase contract. If ownership
/// is enabled, slot +0x40 must return a readable cell for the original index,
/// even if that index is invalid for base erase. Its non-NULL allocation must
/// belong to the tag-2 allocator. Deletion must leave the array usable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_nonnull_cell_array_erase_at(this: *mut ObservableArray, index: i32) -> i32 {
    erase_with(this, index, |allocation| operator_delete(allocation),
        |array, index| observable_array_erase_at(array, index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::opaque_observable_array_dispose_elements::{
        HostElementCell, HostOpaqueObservableArrayVtable,
    };
    use core::cell::Cell;

    #[repr(C)]
    struct Fixture {
        array: HostOpaqueObservableArray,
        cell: HostElementCell,
        fetched: i32,
    }

    unsafe extern "C" fn element_at(this: *mut u8, index: i32) -> *mut HostElementCell {
        let fixture = &mut *this.cast::<Fixture>();
        fixture.fetched = index;
        &mut fixture.cell
    }

    #[test]
    fn null_guard_and_deletion_before_validation_preserve_original_index_and_cell() {
        let vtable = HostOpaqueObservableArrayVtable { unresolved_00_3c: [0; 16], element_at };
        for enabled in [0, 1, 0x80, 0xff] {
            for index in [i32::MIN, -1, 0, 1, i32::MAX] {
                for null in [false, true] {
                    let mut allocation = 0x1234u32;
                    let pointer = if null { core::ptr::null_mut() }
                        else { (&mut allocation as *mut u32).cast() };
                    let mut fixture = Fixture {
                        array: HostOpaqueObservableArray { vtable: &vtable, count: 2,
                            unresolved_08_0f: [0; 8], enabled },
                        cell: HostElementCell { element: pointer }, fetched: 77,
                    };
                    let deleted = Cell::new(false);
                    unsafe {
                        let array = (&mut fixture.array as *mut HostOpaqueObservableArray).cast();
                        let result = erase_with(array, index, |p| {
                            assert_eq!(p, pointer);
                            assert!(!p.is_null());
                            p.cast::<u32>().write(0xdead);
                            deleted.set(true);
                        }, |p, requested| {
                            assert_eq!(p, array);
                            assert_eq!(requested, index);
                            assert_eq!(deleted.get(), enabled != 0 && !null);
                            // Distinct return proves forwarding, not index synthesis.
                            -23
                        });
                        assert_eq!(result, -23);
                    }
                    assert_eq!(fixture.cell.element, pointer);
                    assert_eq!(fixture.fetched, if enabled != 0 { index } else { 77 });
                    assert_eq!(allocation, if enabled != 0 && !null { 0xdead } else { 0x1234 });
                }
            }
        }
    }

    #[test]
    fn disabled_empty_array_uses_real_base_rejection_without_virtual_lookup() {
        let mut array = HostOpaqueObservableArray { vtable: core::ptr::null(),
            count: 0, unresolved_08_0f: [0; 8], enabled: 0 };
        for index in [i32::MIN, -1, 0, i32::MAX] {
            unsafe {
                assert_eq!(owned_nonnull_cell_array_erase_at((&mut array as *mut HostOpaqueObservableArray).cast(), index), -1);
            }
        }
        assert_eq!(array.count, 0);
    }
}
