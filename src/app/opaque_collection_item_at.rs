//! Opaque collection indexed accessor.
//!
//! `opaque_collection_item_at` — original: `FUN_08299d18` @ `0x08299d18`
//! (8 bytes, `0x08299d18..0x08299d20`). Raw ARM is `add r0,r0,#4; b
//! 0x083d5fbc`; the separately entered next function begins at `0x08299d20`.
//! Decoding every ARM B/BL immediate in `osos.dec` finds eight plain,
//! unconditional `bl` call sites — `0x08126c98`, `0x081277a4`, `0x08299a08`,
//! `0x08299ab0`, `0x08299b54`, `0x08299bac`, `0x08299c30`, and `0x08299cc0`
//! — and no predicated calls.
//!
//! # Algorithm
//!
//! The first word is an unknown owner field; its embedded C++ container starts
//! at target word 1. This accessor advances to that container and tail-calls
//! the container's virtual slot-0x40 element lookup. It has no NULL guard,
//! bounds check, or writes. Callers use the result as an indexed collection
//! element while looping over the sibling count accessor at `0x08299d78`.
//!
//! # Deliberate deviation
//!
//! On the 32-bit target this calls the already ported
//! [`container_element_at`] directly, matching the retail tail branch. On a
//! 64-bit host, the embedded target word is four bytes after the owner but a
//! host vtable pointer is eight-byte aligned; the host implementation performs
//! the identical virtual lookup with unaligned reads so tests can preserve the
//! target layout exactly.

#[cfg(target_os = "none")]
use crate::cxx::templates::container_element_at;
#[cfg(not(target_os = "none"))]
use crate::cxx::templates::{ElementSlotFn, ELEMENT_SLOT_VTABLE_INDEX};

/// Returns element `index` from the opaque collection embedded at target word
/// 1.
///
/// Original: `FUN_08299d18` @ `0x08299d18` (8 bytes; 8 plain unconditional
/// `bl` call sites and no predicated calls, binary-scanned). The original is
/// an `add r0,#4` followed by a tail branch to `FUN_083d5fbc`, a byte-identical
/// `container_element_at` instantiation. No target-side deviations.
///
/// # Safety
///
/// `collection` must point to an owner whose second target-width word begins a
/// valid container with a vtable containing element-slot 16. `index` must be
/// valid for that virtual method; neither retailOS nor this port checks it.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_collection_item_at")]
#[inline(never)]
pub unsafe extern "C" fn opaque_collection_item_at(collection: *mut u8, index: usize) -> *mut u8 {
    container_element_at(collection.cast::<u32>().add(1).cast::<u8>(), index)
}

#[cfg(not(target_os = "none"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_collection_item_at")]
#[inline(never)]
pub unsafe extern "C" fn opaque_collection_item_at(collection: *mut u8, index: usize) -> *mut u8 {
    let embedded_container = collection.cast::<u32>().add(1).cast::<u8>();
    let vtable = (embedded_container as *const *const ElementSlotFn).read_unaligned();
    let element_slot = vtable.add(ELEMENT_SLOT_VTABLE_INDEX).read();
    element_slot(embedded_container, index).read_unaligned()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(C)]
    struct FakeContainer {
        vtable: *const ElementSlotFn,
        slots: [*mut u8; 3],
    }

    // `packed(4)` makes the host fixture retain the 32-bit firmware layout:
    // its container begins exactly one target word after the owner base.
    #[repr(C, packed(4))]
    struct EmbeddedContainer {
        owner_word: u32,
        container: FakeContainer,
    }

    static mut LAST_INDEX: usize = usize::MAX;

    unsafe extern "C" fn fake_element_slot(this: *mut u8, index: usize) -> *mut *mut u8 {
        LAST_INDEX = index;
        let container = this as *mut FakeContainer;
        core::ptr::addr_of_mut!((*container).slots[index])
    }

    #[test]
    fn element_at_uses_the_container_at_target_word_one() {
        unsafe {
            let mut vtable = [fake_element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut first = 1u8;
            let mut second = 2u8;
            let mut owner = EmbeddedContainer {
                owner_word: 0xdead_beef,
                container: FakeContainer {
                    vtable: vtable.as_mut_ptr(),
                    slots: [&mut first, &mut second, core::ptr::null_mut()],
                },
            };
            let collection = core::ptr::addr_of_mut!(owner).cast::<u8>();
            let embedded = core::ptr::addr_of_mut!(owner.container).cast::<u8>();

            assert_eq!(embedded as usize - collection as usize, 4);
            assert_eq!(opaque_collection_item_at(collection, 1), &mut second as *mut u8);
            assert_eq!(LAST_INDEX, 1, "the index is passed through unchanged");
            assert!(opaque_collection_item_at(collection, 2).is_null(), "NULL element is returned");
        }
    }
}
