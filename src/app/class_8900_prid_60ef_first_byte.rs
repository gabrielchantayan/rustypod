//! Signed first-byte accessor for the class-0x8900 prID/0x60ef resource.
//!
//! Original FUN_081ebeec @ 0x081ebeec: 40 code bytes plus eight literal
//! bytes, true extent 48 bytes ending at the next push @ 0x081ebf1c.
//! Whole-image raw ARM decoding finds two plain incoming BLs (0x081035b0,
//! 0x081f75d0), zero predicated incoming BLs. The body has one plain BL
//! to resource_chain_find @ 0x0827216c and zero predicated BLs.
//!
//! Load the receiver's store at +0x378, find ("prID", 0x60ef), and return
//! its first byte sign-extended to i32; a NULL result returns zero.
//! Callers compare the result with 1 and 2, but the resource's further
//! meaning is unrecovered. Deliberate deviations: reuse the existing
//! native-pointer Class8900/provider layouts for host fixtures; ordinary
//! Rust control flow replaces the predicated signed-byte load. No new seams.

use crate::app::class_8900::Class8900;
use crate::app::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};

/// Requires a valid receiver and provider chain, and a readable byte for
/// any non-NULL resource answer. The receiver is not NULL-guarded.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_prid_60ef_first_byte(this: *const Class8900) -> i32 {
    let resource = resource_chain_find(
        (*this).store as *mut ResourceProvider,
        ResourceKind(0x7072_4944),
        0x60ef,
    );
    if resource.is_null() { 0 } else { *(resource as *const i8) as i32 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::class_8900::{Class6000, Class6000VTable};
    use crate::app::resource_chain::ResourceProviderVTable;
    use core::ptr;

    #[repr(C)]
    struct Provider {
        class: Class6000,
        state_below_next: [*mut u8; 4],
        next: *mut ResourceProvider,
        answer: *mut u8,
    }

    unsafe extern "C" fn find(provider: *mut ResourceProvider, kind: ResourceKind,
        id: u32, found: *mut *mut u8) -> u32 {
        if kind == ResourceKind(0x7072_4944) && id == 0x60ef {
            *found = (*(provider as *mut Provider)).answer;
            1
        } else { 0 }
    }
    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 { 0 }
    unsafe extern "C" fn replacement(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { 1 }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { 0 }
    const VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22], read, slot_5c: None,
        replacement_allowed: replacement, find, write,
    };

    #[test]
    fn signed_byte_boundaries_and_null_answers() {
        let mut provider = Provider {
            class: Class6000 { vtable: &VTABLE as *const _ as *const Class6000VTable },
            state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut(),
            answer: ptr::null_mut(),
        };
        let mut owner = Class8900 {
            vtable: ptr::null(), state_below_cache: [0; 11], cached_6031: 0,
            state_below_store: [0; 209], store: &mut provider.class,
        };
        unsafe {
            assert_eq!(class_8900_prid_60ef_first_byte(&owner), 0);
            // Exhaustive signed conversion, including both caller-selected values.
            for value in 0..=255u16 {
                let mut bytes = [value as u8, 0x5a];
                provider.answer = bytes.as_mut_ptr();
                assert_eq!(class_8900_prid_60ef_first_byte(&owner),
                    if value < 128 { value as i32 } else { value as i32 - 256 });
            }
            owner.store = ptr::null_mut();
            assert_eq!(class_8900_prid_60ef_first_byte(&owner), 0);
        }
    }
}
