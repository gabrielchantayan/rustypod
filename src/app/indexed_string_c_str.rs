//! Indexed string collection accessor — `FUN_08299d4c` @ 0x08299d4c.
//!
//! True extent: 20 bytes, 0x08299d4c..0x08299d60; the next real function
//! starts with push {r0,r1,r4,lr} at 0x08299d60. Raw-word scanning verifies
//! two incoming plain BLs (0x08126aa4, 0x082999cc), zero predicated BLs.
//! The body adds four to the receiver, calls container_element_at_alias_5fbc
//! @ 0x083d5fbc with the unchanged r1 index, restores registers, and tail-
//! branches to the branch-only veneer @ 0x082a678c, which jumps to
//! string_object_c_str @ 0x082a50b0. Neither receiver nor element
//!
//! Deliberate deviations: the opaque leading word and embedded vtable pointer
//! use native pointer widths on hosts; repr(C) retains +4 on ARM. The existing
//! string accessor models the firmware's shared empty byte with a Rust static.

use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::cxx::vtable_slot_40_result_word_at::container_element_at_alias_5fbc;

/// Accessed prefix only; the embedded collection's concrete type is unknown.
#[repr(C)]
pub struct IndexedStringCollection {
    pub header: usize,
    pub collection_vtable: *const u8,
}

/// Returns the indexed element's string payload, or the shared empty string.
///
/// # Safety
/// `owner` must contain a valid embedded collection whose slot +0x40 accepts
/// `index` and returns a readable u32 cell holding a valid StringObject address.
/// The element address must fit in u32, including on hosts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_string_c_str(
    owner: *mut IndexedStringCollection,
    index: u32,
) -> *const u8 {
    let receiver = core::ptr::addr_of_mut!((*owner).collection_vtable).cast::<u8>();
    let element = container_element_at_alias_5fbc(receiver, index);
    string_object_c_str(element as usize as *const StringObject)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Method = unsafe extern "C" fn(*mut u8, u32) -> *const u32;

    #[repr(C)]
    struct Collection {
        vtable: *const Method,
        elements: [u32; 2],
    }

    #[repr(C)]
    struct Owner {
        header: usize,
        collection: Collection,
    }

    unsafe extern "C" fn element_at(receiver: *mut u8, index: u32) -> *const u32 {
        let collection = &*(receiver as *const Collection);
        &collection.elements[index as usize]
    }

    #[test]
    fn selects_distinct_elements_and_handles_null_and_empty_payloads() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::INDEXED_STRING_C_STR, 4096,
        ) else { return; };
        unsafe {
            let strings = slab.cast::<StringObject>();
            let mut text = *b"selected\0";
            strings.write(StringObject { vtable: core::ptr::null(), payload: text.as_mut_ptr() });
            strings.add(1).write(StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() });
            let vtable = [element_at as Method; 17];
            let mut owner = Owner {
                header: usize::MAX,
                collection: Collection {
                    vtable: vtable.as_ptr(),
                    elements: [strings as usize as u32, strings.add(1) as usize as u32],
                },
            };
            let prefix = (&mut owner as *mut Owner).cast::<IndexedStringCollection>();
            assert_eq!(indexed_string_c_str(prefix, 0), text.as_ptr());
            let fallback = indexed_string_c_str(prefix, 1);
            assert!(!fallback.is_null());
            assert_eq!(*fallback, 0);
            let mut empty = 0u8;
            (*strings.add(1)).payload = &mut empty;
            assert_eq!(indexed_string_c_str(prefix, 1), &empty as *const u8);
            assert_eq!(indexed_string_c_str(prefix, 0), text.as_ptr());
        }
    }
}
