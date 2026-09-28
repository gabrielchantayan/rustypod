//! Releases the first populated allocation returned by a vtable slot.
//!
//! `vtable_slot_40_release_first` — original: `FUN_0839c6ec` at load address
//! **0x0839c6ec** (88 bytes; true extent `0x0839c6ec..0x0839c740`, with the
//! next independently linked function beginning at `0x0839c744`). Raw ARM
//! decoding finds two inbound plain unconditional `bl` calls (`0x0839c79c` and
//! `0x0839c7c0`) and no predicated `bl` calls. The body has two plain
//! unconditional direct `bl` calls, to unported `FUN_082800f8` at `0x082800f8`
//! and [`operator_delete`] at `0x082aad24`; it also has one unconditional
//! indirect `blx` through vtable slot `+0x40`.
//!
//! # Algorithm
//!
//! If `object.+0x28` is enabled, scans signed indices from zero while they are
//! less than `object.+0x04`. It dispatches vtable slot `+0x40` with `(object,
//! index)` and inspects the returned allocation word. For the first non-NULL
//! allocation, it invokes the nested string-object destroy boundary and then
//! tag-2 `operator_delete`; a NULL result advances to the next index. It
//! returns without changing the object.
//!
//! # Deliberate deviations
//!
//! The nested destructor at `0x082800f8` has no verified semantic identity, so
//! target builds call its fixed retailOS address and host tests use a narrow
//! callback seam. Host vtables and object pointers use native-width fields;
//! target builds preserve 32-bit word offsets.

use crate::heap::veneers::operator_delete;

type ReleaseFirstMethod = unsafe extern "C" fn(*mut u8, u32) -> *mut *mut u8;
pub type NestedStringObjectDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;
const VTABLE_RELEASE_FIRST_SLOT: usize = 0x40 / 4;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_nested_string_object_destroy(object: *mut u8) -> *mut u8 { object }

/// Host seam for the verified but unported `FUN_082800f8` boundary.
#[cfg(not(target_os = "none"))]
pub static mut NESTED_STRING_OBJECT_DESTROY: NestedStringObjectDestroy = missing_nested_string_object_destroy;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn nested_string_object_destroy_target() -> NestedStringObjectDestroy {
    unsafe { core::mem::transmute(0x0828_00f8usize) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_release_first(object: *mut u8, index: u32) -> *mut *mut u8 {
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let method: ReleaseFirstMethod = core::mem::transmute(vtable.add(VTABLE_RELEASE_FIRST_SLOT).read_volatile() as usize);
    method(object, index)
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostReleaseFirstVtable {
    pub unresolved_00_to_3c: [usize; VTABLE_RELEASE_FIRST_SLOT],
    pub release_first: ReleaseFirstMethod,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostReleaseFirstObject {
    pub vtable: *const HostReleaseFirstVtable,
    pub iteration_count: i32,
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_release_first(object: *mut u8, index: u32) -> *mut *mut u8 {
    let object = unsafe { &*object.cast::<HostReleaseFirstObject>() };
    unsafe { ((*object.vtable).release_first)(object as *const _ as *mut u8, index) }
}

/// Destroys and deallocates the first non-NULL allocation yielded by `object`.
///
/// # Safety
///
/// `object`, its vtable, every dispatched result word, and a non-NULL result's
/// nested string-object representation must be valid. retailOS checks none of
/// these boundaries.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_40_release_first(object: *mut u8) {
    #[cfg(target_os = "none")]
    let enabled = unsafe { object.add(0x28).read_volatile() };
    #[cfg(not(target_os = "none"))]
    let enabled = unsafe { (*object.cast::<HostReleaseFirstObject>()).enabled };
    if enabled == 0 { return; }

    #[cfg(target_os = "none")]
    let count = unsafe { object.add(4).cast::<i32>().read_volatile() };
    #[cfg(not(target_os = "none"))]
    let count = unsafe { (*object.cast::<HostReleaseFirstObject>()).iteration_count };

    for index in 0..count.max(0) as u32 {
        let allocation = unsafe { dispatch_release_first(object, index).read_volatile() };
        if !allocation.is_null() {
            #[cfg(target_os = "none")]
            let allocation = unsafe { nested_string_object_destroy_target()(allocation) };
            #[cfg(not(target_os = "none"))]
            let allocation = unsafe { NESTED_STRING_OBJECT_DESTROY(allocation) };
            unsafe { operator_delete(allocation) };
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::{HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::{DEFAULT_HEAP_OPS, HEAP_OPS, HeapVeneerOps};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INDICES: [u32; 4] = [0; 4];
    static mut CALLS: usize = 0;
    static mut RESULTS: [*mut u8; 4] = [ptr::null_mut(); 4];
    static mut DESTROYED: *mut u8 = ptr::null_mut();
    static mut FREED: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn yield_allocation(_: *mut u8, index: u32) -> *mut *mut u8 {
        unsafe { INDICES[CALLS] = index; let result = ptr::addr_of_mut!(RESULTS[CALLS]); CALLS += 1; result }
    }
    unsafe extern "C" fn record_destroy(object: *mut u8) -> *mut u8 {
        unsafe { DESTROYED = object; object.add(1) }
    }
    unsafe extern "C" fn record_free(_: *mut HeapDescriptorDescriptor, object: *mut u8, _: usize) {
        unsafe { FREED = object }
    }
    struct HeapRestore { ops: HeapVeneerOps, heap: *mut HeapDescriptorDescriptor }
    impl Drop for HeapRestore {
        fn drop(&mut self) { unsafe { HEAP_OPS = self.ops; DEFAULT_HEAP = self.heap; NESTED_STRING_OBJECT_DESTROY = missing_nested_string_object_destroy; } }
    }
    unsafe fn install_seams() -> HeapRestore {
        let restore = HeapRestore { ops: unsafe { HEAP_OPS }, heap: unsafe { DEFAULT_HEAP } };
        let mut ops = DEFAULT_HEAP_OPS;
        ops.free = record_free;
        unsafe { HEAP_OPS = ops; DEFAULT_HEAP = 1usize as *mut _; NESTED_STRING_OBJECT_DESTROY = record_destroy; CALLS = 0; DESTROYED = ptr::null_mut(); FREED = ptr::null_mut(); }
        restore
    }
    fn object(vtable: &HostReleaseFirstVtable, count: i32, enabled: u8) -> HostReleaseFirstObject {
        HostReleaseFirstObject { vtable, iteration_count: count, enabled }
    }

    #[test]
    fn releases_only_the_first_populated_vtable_result() {
        let _lock = TEST_LOCK.lock(); let _restore = unsafe { install_seams() };
        let vtable = HostReleaseFirstVtable { unresolved_00_to_3c: [0; VTABLE_RELEASE_FIRST_SLOT], release_first: yield_allocation };
        let mut storage = [0u8; 32];
        unsafe { RESULTS = [ptr::null_mut(), storage.as_mut_ptr(), 0x44usize as *mut u8, ptr::null_mut()]; }
        let object = object(&vtable, 3, 1);
        unsafe { vtable_slot_40_release_first(ptr::addr_of!(object).cast_mut().cast()); assert_eq!(CALLS, 2); assert_eq!(INDICES[..2], [0, 1]); assert_eq!(DESTROYED, storage.as_mut_ptr()); assert_eq!(FREED, storage.as_mut_ptr().add(1)); }
    }

    #[test]
    fn scans_all_null_results_without_destroying_or_freeing() {
        let _lock = TEST_LOCK.lock(); let _restore = unsafe { install_seams() };
        let vtable = HostReleaseFirstVtable { unresolved_00_to_3c: [0; VTABLE_RELEASE_FIRST_SLOT], release_first: yield_allocation };
        unsafe { RESULTS = [ptr::null_mut(); 4]; }
        let object = object(&vtable, 3, 1);
        unsafe { vtable_slot_40_release_first(ptr::addr_of!(object).cast_mut().cast()); assert_eq!(CALLS, 3); assert_eq!(DESTROYED, ptr::null_mut()); assert_eq!(FREED, ptr::null_mut()); }
    }

    #[test]
    fn skips_disabled_zero_and_negative_count_objects() {
        let _lock = TEST_LOCK.lock(); let _restore = unsafe { install_seams() };
        let vtable = HostReleaseFirstVtable { unresolved_00_to_3c: [0; VTABLE_RELEASE_FIRST_SLOT], release_first: yield_allocation };
        for (enabled, count) in [(0, 3), (1, 0), (1, -1)] {
            let object = object(&vtable, count, enabled);
            unsafe { CALLS = 0; vtable_slot_40_release_first(ptr::addr_of!(object).cast_mut().cast()); assert_eq!(CALLS, 0); }
        }
    }
}
