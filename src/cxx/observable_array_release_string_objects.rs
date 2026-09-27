//! `observable_array_release_string_objects` — retailOS `FUN_083d1b0c` @
//! **0x083d1b0c**.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` contains nineteen A32 words from `push {r4,r5,r6,lr}` at
//! `0x083d1b0c` through `pop {r4,r5,r6,pc}` at `0x083d1b54`; the next real
//! function begins at `0x083d1b58`, so the true size is **76 bytes**. The body
//! has **three** plain direct `bl` calls—not Ghidra's reported two—to the
//! virtual-slot `+0x40` accessor `FUN_083d6bec`,
//! `string_object_destroy_08201610` @ `0x08201610`, and `operator_delete` @
//! `0x082aad24`; it has no predicated `bl` calls.
//!
//! ## Algorithm
//!
//! When byte `+0x10` is nonzero, visit signed indices `[0, count)`. Each
//! `+0x40` accessor result is a cell whose first word optionally points at a
//! StringObject allocation. Non-NULL objects are destroyed and then deleted.
//!
//! Deliberate deviations: the target reads 32-bit vtable and cell words at
//! retail offsets; host fixtures use native-width pointers and replace the two
//! direct callees, because fixture objects are not retail heap allocations.

use crate::cxx::string_object::{string_object_destroy_08201610, StringObject};
use crate::heap::veneers::operator_delete;

const ELEMENT_AT_SLOT: usize = 0x40 / 4;
type ElementAt = unsafe extern "C" fn(*mut u8, i32) -> *mut u8;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayReleaseStringObjectsVtable {
    pub unresolved_00_3c: [usize; ELEMENT_AT_SLOT],
    pub element_at: ElementAt,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayReleaseStringObjects {
    pub vtable: *const HostObservableArrayReleaseStringObjectsVtable,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
pub type StringObjectDestroy = unsafe extern "C" fn(*mut StringObject) -> *mut StringObject;
#[cfg(not(target_os = "none"))]
pub type Delete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_RELEASE_STRING_OBJECTS_OPS: (StringObjectDestroy, Delete) =
    (string_object_destroy_08201610, operator_delete);

#[inline(always)]
unsafe fn destroy_and_delete(object: *mut StringObject) {
    if object.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    unsafe {
        operator_delete(string_object_destroy_08201610(object).cast());
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let (destroy, delete) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_RELEASE_STRING_OBJECTS_OPS));
        delete(destroy(object).cast());
    }
}

/// Releases every populated StringObject while enabled.
///
/// Original: `FUN_083d1b0c` @ `0x083d1b0c` (76 bytes; 3 plain direct `bl`
/// calls and no predicated `bl` calls).
///
/// # Safety
///
/// `this` must address a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell;
/// a non-NULL first word must address a StringObject accepted by the destroyer
/// and allocator delete routine.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_release_string_objects(this: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe {
        if this.add(0x10).read_volatile() == 0 {
            return;
        }
        let count = this.add(4).cast::<i32>().read_volatile();
        let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
        let element_at: ElementAt = core::mem::transmute(vtable.add(ELEMENT_AT_SLOT).read_volatile() as usize);
        let mut index = 0;
        while index < count {
            let object = element_at(this, index).cast::<u32>().read_volatile() as usize as *mut StringObject;
            destroy_and_delete(object);
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        let collection = this.cast::<HostObservableArrayReleaseStringObjects>();
        if (*collection).enabled == 0 {
            return;
        }
        let mut index = 0;
        while index < (*collection).count {
            let cell = ((*(*collection).vtable).element_at)(this, index);
            destroy_and_delete(cell.cast::<*mut StringObject>().read());
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUPS: [i32; 3] = [0; 3];
    static mut LOOKUP_COUNT: usize = 0;
    static mut CELLS: [*mut StringObject; 3] = [core::ptr::null_mut(); 3];
    static mut DESTROYED: [*mut StringObject; 3] = [core::ptr::null_mut(); 3];
    static mut DELETED: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut DESTROY_COUNT: usize = 0;
    static mut DELETE_COUNT: usize = 0;

    unsafe extern "C" fn element_at(_: *mut u8, index: i32) -> *mut u8 {
        unsafe {
            LOOKUPS[LOOKUP_COUNT] = index;
            LOOKUP_COUNT += 1;
            CELLS.as_mut_ptr().add(index as usize).cast()
        }
    }

    unsafe extern "C" fn record_destroy(object: *mut StringObject) -> *mut StringObject {
        unsafe { DESTROYED[DESTROY_COUNT] = object; DESTROY_COUNT += 1; }
        object
    }

    unsafe extern "C" fn record_delete(object: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = object; DELETE_COUNT += 1; }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const HostObservableArrayReleaseStringObjectsVtable) -> HostObservableArrayReleaseStringObjects {
        HostObservableArrayReleaseStringObjects { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn inactive_and_nonpositive_collections_do_not_access_cells() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let vtable = HostObservableArrayReleaseStringObjectsVtable { unresolved_00_3c: [0; ELEMENT_AT_SLOT], element_at };
        unsafe {
            LOOKUP_COUNT = 0;
            observable_array_release_string_objects((&mut fixture(0, 2, &vtable) as *mut HostObservableArrayReleaseStringObjects).cast());
            observable_array_release_string_objects((&mut fixture(1, 0, &vtable) as *mut HostObservableArrayReleaseStringObjects).cast());
            observable_array_release_string_objects((&mut fixture(1, -1, &vtable) as *mut HostObservableArrayReleaseStringObjects).cast());
            assert_eq!(LOOKUP_COUNT, 0);
        }
    }

    #[test]
    fn releases_nonnull_cells_in_index_order() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let vtable = HostObservableArrayReleaseStringObjectsVtable { unresolved_00_3c: [0; ELEMENT_AT_SLOT], element_at };
        let mut first = StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() };
        let mut third = StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() };
        unsafe {
            let old = OBSERVABLE_ARRAY_RELEASE_STRING_OBJECTS_OPS;
            OBSERVABLE_ARRAY_RELEASE_STRING_OBJECTS_OPS = (record_destroy, record_delete);
            LOOKUP_COUNT = 0; DESTROY_COUNT = 0; DELETE_COUNT = 0;
            CELLS = [&mut first, core::ptr::null_mut(), &mut third];
            observable_array_release_string_objects((&mut fixture(1, 3, &vtable) as *mut HostObservableArrayReleaseStringObjects).cast());
            OBSERVABLE_ARRAY_RELEASE_STRING_OBJECTS_OPS = old;
            assert_eq!(LOOKUPS, [0, 1, 2]);
            assert_eq!(DESTROY_COUNT, 2);
            assert_eq!(DELETE_COUNT, 2);
            assert_eq!(DESTROYED[0], &mut first as *mut StringObject);
            assert_eq!(DESTROYED[1], &mut third as *mut StringObject);
            assert_eq!(DELETED[0], (&mut first as *mut StringObject).cast());
            assert_eq!(DELETED[1], (&mut third as *mut StringObject).cast());
        }
    }
}
