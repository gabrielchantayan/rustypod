//! `scoped_context_container_erase_at` — `FUN_083d1104` @ `0x083d1104`.
//!
//! Raw A32 extent [0x083d1104,0x083d1148) is 68 bytes, ending in a tail
//! B to observable_array_erase_at; the next word is an independent PUSH.
//! Whole-image decoding finds one incoming plain BL at 0x0812fcb8 and no
//! predicated BLs. The body has three plain BLs (element accessor, empty
//! scoped-context destructor, operator_delete), zero predicated BLs.
//!
//! If byte +0x10 is nonzero, retrieve the element using the unchanged index,
//! destroy and tag-2-delete it if non-NULL, then erase through the base array.
//! Lookup/deletion precede base validation, even for negative or INT_MAX
//! indices. Ghidra incorrectly incorporates the tail target into this body.
//! Deliberate deviations: host layout uses existing native-pointer fields;
//! the tail branch is a Rust call. Delete explicitly receives the saved
//! element because the existing void destructor's ABI does not promise the
//! original BX LR's r0 pass-through. No new fixed-address seams.
//! ARM review: LLVM eliminates the proven-empty destructor, predicates the
//! delete BL, adds an FP frame, and preserves the base erase tail B.

use super::observable_array::{observable_array_erase_at, ObservableArray};
use super::templates::container_element_at_alias_6a68;
use crate::app::scoped_context::scoped_context_destroy;
use crate::heap::veneers::operator_delete;
#[cfg(not(target_os = "none"))]
use super::opaque_observable_array_dispose_elements::HostOpaqueObservableArray;

/// Delete the enabled indexed context, then return the base erase result.
///
/// # Safety
/// `this` must satisfy the observable array erase contract. When enabled,
/// its accessor must accept the original index and return a readable cell;
/// a non-NULL element must be an owned context accepted by operator_delete.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_container_erase_at(this: *mut ObservableArray, index: i32) -> i32 {
    #[cfg(target_os = "none")]
    let enabled = this.cast::<u8>().add(0x10).read() != 0;
    #[cfg(not(target_os = "none"))]
    let enabled = (*this.cast::<HostOpaqueObservableArray>()).enabled != 0;
    if enabled {
        let element = container_element_at_alias_6a68(this.cast(), index as usize);
        if !element.is_null() {
            scoped_context_destroy(element.cast());
            operator_delete(element);
        }
    }
    observable_array_erase_at(this, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::opaque_observable_array_dispose_elements::HostOpaqueObservableArrayVtable;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{DEFAULT_HEAP_OPS, HEAP_OPS};

    #[repr(C)]
    struct Fixture {
        array: HostOpaqueObservableArray,
        cell: *mut u8,
        requested: usize,
        lookups: usize,
        deletes: usize,
    }
    unsafe extern "C" fn element_at(this: *mut u8, index: usize) -> *mut *mut u8 {
        let fixture = &mut *this.cast::<Fixture>();
        fixture.requested = index;
        fixture.lookups += 1;
        core::ptr::addr_of_mut!(fixture.cell)
    }
    unsafe extern "C" fn delete_and_empty(_: *mut HeapDescriptorDescriptor, element: *mut u8, tag: usize) {
        assert_eq!(tag, 2);
        let fixture = &mut *element.cast::<Fixture>();
        fixture.deletes += 1;
        fixture.array.count = 0;
    }
    struct RestoreHeap;
    impl Drop for RestoreHeap {
        fn drop(&mut self) {
            unsafe {
                HEAP_OPS = DEFAULT_HEAP_OPS;
                crate::heap::types::DEFAULT_HEAP = core::ptr::null_mut();
            }
        }
    }

    #[test]
    fn deletion_precedes_validation_of_original_signed_index() {
        // The repository runs global-hook tests serially (RUST_TEST_THREADS=1).
        let _restore = RestoreHeap;
        unsafe {
            let mut ops = DEFAULT_HEAP_OPS;
            ops.free = delete_and_empty;
            HEAP_OPS = ops;
            crate::heap::types::DEFAULT_HEAP = 1usize as *mut _;
        }
        let mut slots = [0usize; 17];
        slots[16] = element_at as *const () as usize;
        for index in [0, -1, i32::MIN, i32::MAX] {
            let mut fixture = Fixture {
                array: HostOpaqueObservableArray { vtable: slots.as_ptr().cast::<HostOpaqueObservableArrayVtable>(), count: 2, unresolved_08_0f: [0; 8], enabled: 0x80 },
                cell: core::ptr::null_mut(), requested: 0, lookups: 0, deletes: 0,
            };
            // Empty destructor never reads the element; the recording allocator
            // models deletion by emptying the containing array before validation.
            fixture.cell = (&mut fixture as *mut Fixture).cast();
            assert_eq!(unsafe { scoped_context_container_erase_at((&mut fixture as *mut Fixture).cast(), index) }, -1);
            assert_eq!((fixture.lookups, fixture.deletes, fixture.array.count), (1, 1, 0));
            assert_eq!(fixture.requested, index as usize);
        }
    }

    #[test]
    fn disabled_and_null_elements_preserve_invalid_index_rejection() {
        let mut slots = [0usize; 17];
        slots[16] = element_at as *const () as usize;
        for enabled in [0, 1, 0x80] {
            let mut fixture = Fixture {
                array: HostOpaqueObservableArray { vtable: slots.as_ptr().cast(), count: 2, unresolved_08_0f: [0; 8], enabled },
                cell: core::ptr::null_mut(), requested: 0, lookups: 0, deletes: 0,
            };
            assert_eq!(unsafe { scoped_context_container_erase_at((&mut fixture as *mut Fixture).cast(), -1) }, -1);
            assert_eq!((fixture.lookups, fixture.deletes, fixture.array.count), ((enabled != 0) as usize, 0, 2));
        }
    }
}
