//! Indexed access to an opaque owner's secondary collection.
//!
//! Original: `FUN_082a676c` @ `0x082a676c`, 8 bytes, true extent
//! `0x082a676c..0x082a6774`; the next function is the independent count
//! accessor at `0x082a6774`. Raw words: `e2800034 ea04c059`.
//! Full-image A32 decoding finds two incoming plain unconditional BLs
//! (`0x08299a64`, `0x08299bcc`) and zero predicated BLs. The body has
//! zero BLs and one tail B to the verified `0x083d68dc` container accessor.
//!
//! Advance the owner pointer by 0x34 bytes, preserve the index in r1, and
//! return the element loaded through the embedded container's virtual slot
//! 0x40. Callers iterate this collection using the count at owner +0x38,
//! separately from the collection at +0x08. No NULL or bounds checks.
//!
//! Deliberate deviation: none on target. As in `opaque_collection_item_at`,
//! host builds use unaligned pointer reads to retain the literal firmware
//! offset despite native pointers requiring eight-byte alignment.

#[cfg(target_os = "none")]
use crate::cxx::templates::container_element_at_alias_68dc;
#[cfg(not(target_os = "none"))]
use crate::cxx::templates::{ElementSlotFn, ELEMENT_SLOT_VTABLE_INDEX};

/// Returns the indexed element of the collection embedded at owner +0x34.
///
/// # Safety
/// The embedded container must have a valid vtable with element-slot method
/// 16. The index must satisfy that method's contract, and its returned slot
/// must be readable. A NULL element value is valid; a NULL slot is not.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_secondary_collection_item_at(owner: *mut u8, index: usize) -> *mut u8 {
    let container = owner.add(0x34);
    #[cfg(target_os = "none")]
    { container_element_at_alias_68dc(container, index) }
    #[cfg(not(target_os = "none"))]
    {
        let vtable = (container as *const *const ElementSlotFn).read_unaligned();
        let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
        element_slot(container, index).read_unaligned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(C)]
    struct Container {
        vtable: *const ElementSlotFn,
        slots: [*mut u8; 3],
    }

    #[repr(C, packed(4))]
    struct Owner {
        prefix: [u32; 13],
        container: Container,
    }

    unsafe extern "C" fn element_slot(container: *mut u8, index: usize) -> *mut *mut u8 {
        let container = container.cast::<Container>();
        ptr::addr_of_mut!((*container).slots).cast::<*mut u8>().add(index)
    }

    #[test]
    fn returns_boundary_elements_null_and_updated_slot_without_writes() {
        unsafe {
            let vtable = [element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut first = 11u8;
            let mut last = 29u8;
            let mut replacement = 47u8;
            let mut owner = Owner {
                prefix: [0xdead_beef; 13],
                container: Container {
                    vtable: vtable.as_ptr(),
                    slots: [&mut first, ptr::null_mut(), &mut last],
                },
            };
            let base = ptr::addr_of_mut!(owner).cast::<u8>();
            assert_eq!(opaque_secondary_collection_item_at(base, 0), ptr::addr_of_mut!(first));
            assert!(opaque_secondary_collection_item_at(base, 1).is_null());
            assert_eq!(opaque_secondary_collection_item_at(base, 2), ptr::addr_of_mut!(last));
            ptr::addr_of_mut!(owner.container.slots).cast::<*mut u8>().add(2)
                .write_unaligned(ptr::addr_of_mut!(replacement));
            assert_eq!(opaque_secondary_collection_item_at(base, 2), ptr::addr_of_mut!(replacement));
            assert_eq!(owner.prefix, [0xdead_beef; 13]);
            assert_eq!((first, last, replacement), (11, 29, 47));
        }
    }
}
