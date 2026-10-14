//! Delete an owned cell then erase: `FUN_083d2058` @ `0x083d2058`.
//!
//! Raw A32 extent [0x083d2058,0x083d209c) is 68 bytes, ending in a tail
//! branch before the next independent PUSH. Whole-image word decoding finds
//! zero incoming plain BLs and one BLGT at 0x081d0fb8. Outgoing: one plain
//! BL to operator_delete @ 0x082aad24, zero predicated BLs, one virtual BLX
//! through +0x40, and a tail B to observable_array_erase_at @ 0x08271bec.
//! When the byte at +0x10 is nonzero, fetch the cell for the unchanged signed
//! index and tag-2-delete its allocation word (including NULL). Then erase
//! that same index and return the base operation's result. There is no index
//! validation before fetching/deleting and no cell clear or element destructor.
//! Deliberate host deviation: reuse native-pointer opaque-array fixtures;
//! target fields and vtable slots remain four-byte words. Both fixed callees
//! are existing ports; LLVM register allocation/tail-call selection may differ.

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
    if this.cast::<u8>().add(0x10).read_volatile() != 0 {
        let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
        let element_at: unsafe extern "C" fn(*mut ObservableArray, i32) -> *mut u32 =
            core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize);
        delete(element_at(this, index).read_volatile() as usize as *mut u8);
    }
    #[cfg(not(target_os = "none"))]
    if (*this.cast::<HostOpaqueObservableArray>()).enabled != 0 {
        let array = &*this.cast::<HostOpaqueObservableArray>();
        delete(((*array.vtable).element_at)(this.cast(), index).read().element);
    }
    erase(this, index)
}

/// # Safety
/// `this` must be a live observable-array-derived object. When enabled, its
/// +0x40 virtual operation must return a readable cell for `index`, whose
/// allocation is NULL or owned by the tag-2 allocator. The base erase's
/// vtable and observer contracts must hold, even after deletion callbacks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_cell_array_erase_at(this: *mut ObservableArray, index: i32) -> i32 {
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
    fn deletion_precedes_validation_without_clearing_cell_or_normalizing_index() {
        let vtable = HostOpaqueObservableArrayVtable { unresolved_00_3c: [0; 16], element_at };
        for enabled in [0, 1, 0x80, 0xff] {
            for index in [i32::MIN, -1, 0, 1, i32::MAX] {
                for null in [false, true] {
                    let mut allocation = 0x1234u32;
                    let pointer = if null { core::ptr::null_mut() } else { (&mut allocation as *mut u32).cast() };
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
                            if !p.is_null() { p.cast::<u32>().write(0xdead); }
                            deleted.set(true);
                        }, |_, requested| {
                            assert_eq!(deleted.get(), enabled != 0);
                            assert_eq!(requested, index);
                            // Signed bounds/sentinel reference; deletion must happen
                            // even when the base implementation rejects the index.
                            if requested == i32::MAX { 1 }
                            else if (0..2).contains(&requested) { requested }
                            else { -1 }
                        });
                        let expected = if index == i32::MAX { 1 }
                            else if (0..2).contains(&index) { index } else { -1 };
                        assert_eq!(result, expected);
                    }
                    assert_eq!(fixture.cell.element, pointer);
                    assert_eq!(fixture.fetched, if enabled != 0 { index } else { 77 });
                    assert_eq!(allocation, if enabled != 0 && !null { 0xdead } else { 0x1234 });
                }
            }
        }
    }

    #[test]
    fn disabled_invalid_indices_run_real_base_without_fetching_or_deleting() {
        let mut array = HostOpaqueObservableArray { vtable: core::ptr::null(),
            count: 0, unresolved_08_0f: [0; 8], enabled: 0 };
        for index in [i32::MIN, -1, 0, i32::MAX] {
            unsafe {
                assert_eq!(owned_cell_array_erase_at((&mut array as *mut HostOpaqueObservableArray).cast(), index), -1);
            }
        }
        assert_eq!(array.count, 0);
    }
}
