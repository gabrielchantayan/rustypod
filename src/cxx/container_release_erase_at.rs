//! `container_release_erase_at` — retailOS `FUN_083d1628` @ `0x083d1628`.
//!
//! Raw firmware establishes 68 bytes (`0x083d1628..0x083d166b`), ending in
//! a tail B to `observable_array_erase_at` @ `0x08271bec`; the next real
//! function starts with PUSH at `0x083d166c`. Whole-image word decoding finds
//! one inbound plain BL (`0x08235c64`) and zero predicated BLs. The body has
//! one plain BL to `container_element_at_alias_6b14` @ `0x083d6b14`, zero
//! predicated BLs, and one indirect BLXNE through element vtable +0x04.
//!
//! When byte +0x10 is nonzero, fetch the element using the unchanged index,
//! release it if non-NULL, then erase that same index through the base array.
//! Release precedes base validation, including for negative and INT_MAX
//! indices. Ghidra incorrectly incorporates the tail target into this body.
//! Deliberate deviation: host objects use existing native-pointer layouts;
//! the base tail dispatch is expressed as a Rust call returning its result.

use super::observable_array::{observable_array_erase_at, ObservableArray};
use super::templates::container_element_at_alias_6b14;
#[cfg(not(target_os = "none"))]
use super::opaque_observable_array_dispose_elements::{HostElement, HostOpaqueObservableArray};

/// Releases the indexed element when enabled, then erases its slot.
///
/// # Safety
/// `this` must satisfy the observable array layout and base erase contracts.
/// When enabled, the accessor must return a readable cell for the supplied
/// index, and each non-NULL element must support virtual release at +0x04.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_release_erase_at(this: *mut ObservableArray, index: i32) -> i32 {
    #[cfg(target_os = "none")]
    let enabled = this.cast::<u8>().add(0x10).read_volatile() != 0;
    #[cfg(not(target_os = "none"))]
    let enabled = (*this.cast::<HostOpaqueObservableArray>()).enabled != 0;
    if enabled {
        let element = container_element_at_alias_6b14(this.cast(), index as usize);
        if !element.is_null() {
            #[cfg(target_os = "none")]
            {
                let vtable = element.cast::<u32>().read() as usize as *const u32;
                let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(vtable.add(1).read() as usize);
                release(element);
            }
            #[cfg(not(target_os = "none"))]
            ((*(*element.cast::<HostElement>()).vtable).release)(element);
        }
    }
    observable_array_erase_at(this, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::opaque_observable_array_dispose_elements::{HostElementVtable, HostOpaqueObservableArrayVtable};

    #[repr(C)]
    struct Fixture {
        array: HostOpaqueObservableArray,
        cell: *mut u8,
        requested: usize,
        lookups: usize,
        releases: usize,
    }
    #[repr(C)]
    struct Element {
        base: HostElement,
        owner: *mut Fixture,
    }

    unsafe extern "C" fn element_at(this: *mut u8, index: usize) -> *mut *mut u8 {
        let fixture = &mut *this.cast::<Fixture>();
        fixture.requested = index;
        fixture.lookups += 1;
        core::ptr::addr_of_mut!(fixture.cell)
    }
    unsafe extern "C" fn release(element: *mut u8) {
        let fixture = &mut *(*element.cast::<Element>()).owner;
        fixture.releases += 1;
        // Base validation must observe the mutation, not a cached old length.
        fixture.array.count = 0;
    }

    #[test]
    fn release_precedes_validation_and_preserves_unresolved_index() {
        let mut slots = [0usize; 17];
        slots[16] = element_at as *const () as usize;
        let vtable = HostElementVtable { unresolved_00: 0, release };
        for index in [0, -1, i32::MIN, i32::MAX] {
            let mut fixture = Fixture {
                array: HostOpaqueObservableArray { vtable: slots.as_ptr().cast::<HostOpaqueObservableArrayVtable>(), count: 2, unresolved_08_0f: [0; 8], enabled: 0x80 },
                cell: core::ptr::null_mut(), requested: 0, lookups: 0, releases: 0,
            };
            let mut element = Element { base: HostElement { vtable: &vtable }, owner: &mut fixture };
            fixture.cell = (&mut element as *mut Element).cast();
            assert_eq!(unsafe { container_release_erase_at((&mut fixture as *mut Fixture).cast(), index) }, -1);
            assert_eq!((fixture.lookups, fixture.releases, fixture.array.count), (1, 1, 0));
            assert_eq!(fixture.requested, index as usize);
        }
    }

    #[test]
    fn disabled_and_null_elements_leave_base_rejection_unchanged() {
        let mut slots = [0usize; 17];
        slots[16] = element_at as *const () as usize;
        for enabled in [0, 1] {
            let mut fixture = Fixture {
                array: HostOpaqueObservableArray { vtable: slots.as_ptr().cast(), count: 2, unresolved_08_0f: [0; 8], enabled },
                cell: core::ptr::null_mut(), requested: 0, lookups: 0, releases: 0,
            };
            assert_eq!(unsafe { container_release_erase_at((&mut fixture as *mut Fixture).cast(), -1) }, -1);
            assert_eq!((fixture.lookups, fixture.releases, fixture.array.count), (enabled as usize, 0, 2));
        }
    }
}
