//! `vtable_08990af8_destruct` — retailOS `FUN_081fae30` @ `0x081fae30`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` establishes the true **184-byte** extent: 45 instruction
//! words from `0x081fae30` through `0x081faee4`, followed by the vtable
//! literal `0x08990af8` at `0x081faee8`; `0x081faeec` starts the next real
//! function. Whole-image A32 decoding finds three inbound plain `bl` sites
//! (`0x081dcd64`, `0x081dce28`, and `0x0820fd60`) and no predicated `bl`
//! sites. The body makes eleven plain direct `bl` calls and no predicated
//! calls.
//!
//! ## Algorithm
//!
//! Reinstall the destruction vtable, then visit words `+0x3c` through `+0x28`
//! in descending order. Each non-NULL word is an allocation whose embedded
//! [`ObservableArray`] starts four bytes later: destruct that embedded object,
//! subtract four from its returned pointer, and delete the allocation. Finally,
//! if word `+0x24` is non-NULL, call the already ported
//! `vtable_08980110_construct` entry and delete its returned outer pointer.
//! Return the original receiver.
//!
//! Deliberate deviations: the field class remains unidentified, so this port
//! uses its verified vtable and ownership behavior as its name. Host tests use
//! an operator-delete recorder; firmware calls the ported `operator_delete`
//! directly. `FUN_080fe850` retains its existing, evidence-backed name even
//! though this is a destruction-path call site.

use super::observable_array::{observable_array_destruct, ObservableArray};
use super::vtable_08980110_construct::vtable_08980110_construct;

/// Vtable literal written before releasing any owned member.
pub const VTABLE_08990AF8_DESTRUCT_VTABLE: u32 = 0x0899_0af8;

/// Target-width layout consumed by [`vtable_08990af8_destruct`].
#[repr(C)]
pub struct Vtable08990af8Object {
    pub vtable: u32,
    pub words_04_to_20: [u32; 8],
    pub owned_outer: u32,
    pub owned_arrays: [u32; 6],
}

const _: [u8; 0x40] = [0; core::mem::size_of::<Vtable08990af8Object>()];
const _: [u8; 0x24] = [0; core::mem::offset_of!(Vtable08990af8Object, owned_outer)];
const _: [u8; 0x28] = [0; core::mem::offset_of!(Vtable08990af8Object, owned_arrays)];

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_operator_delete(_ptr: *mut u8) {
    panic!("vtable_08990af8_destruct requires a host delete seam")
}

/// Deallocator used after each embedded observable-array destructor.
///
/// Firmware binds directly to the already ported tag-2 `operator_delete` at
/// `0x082aad24`; hosts replace this only to observe target-width fixtures.
#[cfg(target_os = "none")]
pub static mut VTABLE_08990AF8_DELETE: unsafe extern "C" fn(*mut u8) =
    crate::heap::veneers::operator_delete;
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_08990AF8_DELETE: unsafe extern "C" fn(*mut u8) = host_operator_delete;

/// Destructs the opaque vtable-`0x08990af8` object and returns `this`.
///
/// # Safety
///
/// `this` must name 64 writable target-width bytes. Every nonzero array word
/// must be an allocation with a live [`ObservableArray`] at `+4`; the outer
/// word must satisfy `vtable_08980110_construct`'s observed ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_08990af8_destruct(
    this: *mut Vtable08990af8Object,
) -> *mut Vtable08990af8Object {
    (*this).vtable = VTABLE_08990AF8_DESTRUCT_VTABLE;

    let mut array_index = 6;
    while array_index != 0 {
        array_index -= 1;
        let allocation = (*this).owned_arrays[array_index] as usize as *mut u8;
        if !allocation.is_null() {
            let destroyed = observable_array_destruct(allocation.add(4) as *mut ObservableArray);
            (VTABLE_08990AF8_DELETE)(destroyed.cast::<u8>().sub(4));
        }
    }

    let outer = (*this).owned_outer as usize as *mut u8;
    if !outer.is_null() {
        (VTABLE_08990AF8_DELETE)(vtable_08980110_construct(outer));
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::vtable_08980110_construct::VTABLE_08980110_CONSTRUCT_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut DELETED: [usize; 7] = [0; 7];
    static mut DELETE_COUNT: usize = 0;

    unsafe extern "C" fn record_delete(ptr: *mut u8) {
        DELETED[DELETE_COUNT] = ptr as usize;
        DELETE_COUNT += 1;
    }

    unsafe extern "C" fn construct_embedded_base(base: *mut u8) -> *mut u8 {
        base
    }

    #[test]
    fn destroys_arrays_in_reverse_field_order_then_outer_member() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::VTABLE_08990AF8_DESTRUCT, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/vtable_08990af8_destruct"));
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let object = slab as *mut Vtable08990af8Object;
            let allocations = [0x100usize, 0x140, 0x180, 0x1c0, 0x200, 0x240];
            for (index, offset) in allocations.into_iter().enumerate() {
                (*object).owned_arrays[index] = (slab.add(offset) as usize) as u32;
            }
            (*object).owned_outer = (slab.add(0x300) as usize) as u32;
            let old_delete = VTABLE_08990AF8_DELETE;
            let old_construct = VTABLE_08980110_CONSTRUCT_OPS;
            VTABLE_08990AF8_DELETE = record_delete;
            VTABLE_08980110_CONSTRUCT_OPS = construct_embedded_base;
            DELETE_COUNT = 0;

            assert_eq!(vtable_08990af8_destruct(object), object);
            assert_eq!((*object).vtable, VTABLE_08990AF8_DESTRUCT_VTABLE);
            assert_eq!(DELETE_COUNT, 7);
            for (call, offset) in allocations.into_iter().rev().enumerate() {
                assert_eq!(DELETED[call], slab.add(offset) as usize);
            }
            assert_eq!(DELETED[6], slab.add(0x300) as usize);

            VTABLE_08990AF8_DELETE = old_delete;
            VTABLE_08980110_CONSTRUCT_OPS = old_construct;
        }
    }

    #[test]
    fn null_members_only_replant_the_vtable() {
        let _lock = LOCK.lock();
        let mut object = Vtable08990af8Object {
            vtable: 0,
            words_04_to_20: [0; 8],
            owned_outer: 0,
            owned_arrays: [0; 6],
        };
        unsafe {
            let old_delete = VTABLE_08990AF8_DELETE;
            VTABLE_08990AF8_DELETE = record_delete;
            DELETE_COUNT = 0;
            assert!(vtable_08990af8_destruct(&mut object) == &mut object);
            assert_eq!(object.vtable, VTABLE_08990AF8_DESTRUCT_VTABLE);
            assert_eq!(DELETE_COUNT, 0);
            VTABLE_08990AF8_DELETE = old_delete;
        }
    }
}
