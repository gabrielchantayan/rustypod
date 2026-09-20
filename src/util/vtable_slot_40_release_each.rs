//! Vtable-slot-0x40 release loop.
//!
//! `vtable_slot_40_release_each` — original: `FUN_0839c470` @ **0x0839c470**
//! (72 bytes; true extent `0x0839c470..0x0839c4b8`, with the next distinct
//! function beginning at `0x0839c4bc`). Raw ARM decoding finds three direct
//! incoming calls, all unconditional plain `bl` (at `0x08178d88`, `0x0839c508`,
//! and `0x0839c52c`); there are no predicated direct `bl` calls. The body skips
//! disabled objects, otherwise calls vtable slot `+0x40` once for every index
//! `0..object.+0x04`, and deletes the pointer in each returned result word.
//!
//! Deliberate deviation: host fixtures use native-width vtable pointers and a
//! semantic object layout; target builds retain the firmware's 32-bit words.

use crate::heap::veneers::operator_delete;

type ReleaseEachMethod = unsafe extern "C" fn(*mut u8, u32) -> *mut *mut u8;
const VTABLE_RELEASE_EACH_SLOT: usize = 0x40 / 4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_release_each(object: *mut u8, index: u32) -> *mut *mut u8 {
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let method: ReleaseEachMethod = core::mem::transmute(vtable.add(VTABLE_RELEASE_EACH_SLOT).read_volatile() as usize);
    method(object, index)
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostReleaseEachVtable {
    pub unresolved_00_to_3c: [usize; VTABLE_RELEASE_EACH_SLOT],
    pub release_each: ReleaseEachMethod,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostReleaseEachObject {
    pub vtable: *const HostReleaseEachVtable,
    pub iteration_count: i32,
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_release_each(object: *mut u8, index: u32) -> *mut *mut u8 {
    let object = &*object.cast::<HostReleaseEachObject>();
    ((*object.vtable).release_each)(object as *const _ as *mut u8, index)
}

/// Releases each allocation yielded by `object`'s vtable slot `+0x40`.
///
/// # Safety
///
/// `object` and its vtable must be valid. Each slot result must point to a
/// valid target-width allocation word, as retailOS performs no null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_40_release_each(object: *mut u8) {
    #[cfg(target_os = "none")]
    let enabled = object.add(0x28).read_volatile();
    #[cfg(not(target_os = "none"))]
    let enabled = (*object.cast::<HostReleaseEachObject>()).enabled;
    if enabled == 0 {
        return;
    }
    #[cfg(target_os = "none")]
    let count = object.add(4).cast::<i32>().read_volatile();
    #[cfg(not(target_os = "none"))]
    let count = (*object.cast::<HostReleaseEachObject>()).iteration_count;
    if count < 1 {
        return;
    }
    for index in 0..count as u32 {
        operator_delete(dispatch_release_each(object, index).read_volatile());
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
    static mut FREED: [*mut u8; 4] = [ptr::null_mut(); 4];
    static mut FREE_CALLS: usize = 0;
    static mut RESULTS: [*mut u8; 4] = [ptr::null_mut(); 4];

    unsafe extern "C" fn yield_allocation(_: *mut u8, index: u32) -> *mut *mut u8 {
        INDICES[CALLS] = index;
        let result = ptr::addr_of_mut!(RESULTS[CALLS]);
        CALLS += 1;
        result
    }

    unsafe extern "C" fn record_free(_: *mut HeapDescriptorDescriptor, pointer: *mut u8, _: usize) {
        FREED[FREE_CALLS] = pointer;
        FREE_CALLS += 1;
    }

    struct HeapRestore { ops: HeapVeneerOps, heap: *mut HeapDescriptorDescriptor }
    impl Drop for HeapRestore {
        fn drop(&mut self) { unsafe { ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), self.ops); ptr::write_volatile(ptr::addr_of_mut!(DEFAULT_HEAP), self.heap); } }
    }

    unsafe fn install_heap_mock() -> HeapRestore {
        let ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
        let heap = ptr::read_volatile(ptr::addr_of!(DEFAULT_HEAP));
        let mut mock = DEFAULT_HEAP_OPS;
        mock.free = record_free;
        ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), mock);
        ptr::write_volatile(ptr::addr_of_mut!(DEFAULT_HEAP), 1usize as *mut _);
        HeapRestore { ops, heap }
    }

    #[test]
    fn releases_each_vtable_result_in_index_order() {
        let _lock = TEST_LOCK.lock();
        let _restore = unsafe { install_heap_mock() };
        let vtable = HostReleaseEachVtable { unresolved_00_to_3c: [0; VTABLE_RELEASE_EACH_SLOT], release_each: yield_allocation };
        let object = HostReleaseEachObject { vtable: &vtable, iteration_count: 3, enabled: 1 };
        unsafe {
            CALLS = 0; FREE_CALLS = 0; RESULTS = [0x11usize as *mut u8, 0x22usize as *mut u8, 0x33usize as *mut u8, ptr::null_mut()];
            vtable_slot_40_release_each(ptr::addr_of!(object).cast_mut().cast());
            assert_eq!(CALLS, 3); assert_eq!(INDICES[..3], [0, 1, 2]);
            assert_eq!(FREED[..3], RESULTS[..3]);
        }
    }

    #[test]
    fn skips_disabled_and_empty_objects() {
        let _lock = TEST_LOCK.lock();
        let _restore = unsafe { install_heap_mock() };
        let vtable = HostReleaseEachVtable { unresolved_00_to_3c: [0; VTABLE_RELEASE_EACH_SLOT], release_each: yield_allocation };
        for (enabled, iteration_count) in [(0, 3), (1, 0), (1, -1)] {
            let object = HostReleaseEachObject { vtable: &vtable, iteration_count, enabled };
            unsafe { CALLS = 0; FREE_CALLS = 0; vtable_slot_40_release_each(ptr::addr_of!(object).cast_mut().cast()); assert_eq!(CALLS, 0); assert_eq!(FREE_CALLS, 0); }
        }
    }
}
