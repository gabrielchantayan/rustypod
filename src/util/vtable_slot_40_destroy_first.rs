//! Vtable-slot-0x40 first-result destroy loop.
//!
//! `vtable_slot_40_destroy_first` — original: `FUN_0839c610` @
//! **0x0839c610** (88 bytes; true extent `0x0839c610..0x0839c668`, with the
//! next distinct function beginning at `0x0839c668`). Raw A32 decoding finds
//! two direct incoming calls, both unconditional plain `bl` (at `0x0839c6b4`
//! and `0x0839c6d8`); there are no predicated direct `bl` calls. The body
//! skips disabled objects, scans signed indices `0..object.+0x04` through
//! vtable slot `+0x40`, then destroys and deletes only the first non-null
//! result word.
//!
//! The body has two unconditional direct `bl` calls and no predicated direct
//! `bl`: the first reaches unported `FUN_0826fd10` at `0x0826fd10`; its
//! returned pointer feeds ported `operator_delete` at `0x082aad24`. Deliberate
//! deviation: host fixtures use native-width vtable pointers and semantic
//! fields, while target builds retain the firmware's 32-bit word offsets.

use crate::heap::veneers::operator_delete;

const RETAIL_DESTROY_RESULT: usize = 0x0826_fd10;
const VTABLE_DESTROY_FIRST_SLOT: usize = 0x40 / 4;
type DestroyFirstMethod = unsafe extern "C" fn(*mut u8, u32) -> *mut *mut u8;
type DestroyResult = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_destroy_first(object: *mut u8, index: u32) -> *mut *mut u8 {
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let method: DestroyFirstMethod = core::mem::transmute(vtable.add(VTABLE_DESTROY_FIRST_SLOT).read_volatile() as usize);
    method(object, index)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_result(value: *mut u8) -> *mut u8 {
    let destroy: DestroyResult = core::mem::transmute(RETAIL_DESTROY_RESULT);
    destroy(value)
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostDestroyFirstVtable {
    pub unresolved_00_to_3c: [usize; VTABLE_DESTROY_FIRST_SLOT],
    pub destroy_first: DestroyFirstMethod,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostDestroyFirstObject {
    pub vtable: *const HostDestroyFirstVtable,
    pub iteration_count: i32,
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct DestroyFirstOps {
    pub destroy_result: DestroyResult,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_result(_: *mut u8) -> *mut u8 {
    panic!("vtable_slot_40_destroy_first requires a FUN_0826fd10 fixture")
}

/// Host replacement for unported `FUN_0826fd10` at `0x0826fd10`.
#[cfg(not(target_os = "none"))]
pub static mut DESTROY_FIRST_OPS: DestroyFirstOps = DestroyFirstOps {
    destroy_result: missing_destroy_result,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_destroy_first(object: *mut u8, index: u32) -> *mut *mut u8 {
    let object = &*object.cast::<HostDestroyFirstObject>();
    ((*object.vtable).destroy_first)(object as *const _ as *mut u8, index)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_result(value: *mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(DESTROY_FIRST_OPS.destroy_result))(value)
}

/// Destroys and deletes the first non-null result from `object`'s vtable slot `+0x40`.
///
/// # Safety
///
/// `object`, its vtable, and every returned result word must be valid. retailOS
/// performs no null checks on the returned result pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_40_destroy_first(object: *mut u8) {
    #[cfg(target_os = "none")]
    let enabled = object.add(0x28).read_volatile();
    #[cfg(not(target_os = "none"))]
    let enabled = (*object.cast::<HostDestroyFirstObject>()).enabled;
    if enabled == 0 {
        return;
    }
    #[cfg(target_os = "none")]
    let count = object.add(4).cast::<i32>().read_volatile();
    #[cfg(not(target_os = "none"))]
    let count = (*object.cast::<HostDestroyFirstObject>()).iteration_count;
    let mut index = 0;
    while index < count {
        let value = dispatch_destroy_first(object, index as u32).read_volatile();
        if !value.is_null() {
            operator_delete(destroy_result(value));
            return;
        }
        index += 1;
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
    static mut RESULTS: [*mut u8; 4] = [ptr::null_mut(); 4];
    static mut CALLS: usize = 0;
    static mut DESTROYED: *mut u8 = ptr::null_mut();
    static mut FREED: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn yield_result(_: *mut u8, index: u32) -> *mut *mut u8 {
        INDICES[CALLS] = index;
        let result = ptr::addr_of_mut!(RESULTS[CALLS]);
        CALLS += 1;
        result
    }

    unsafe extern "C" fn destroy_to_shifted_pointer(value: *mut u8) -> *mut u8 {
        DESTROYED = value;
        value.wrapping_add(4)
    }

    unsafe extern "C" fn record_free(_: *mut HeapDescriptorDescriptor, pointer: *mut u8, _: usize) { FREED = pointer; }

    struct Restore { heap_ops: HeapVeneerOps, heap: *mut HeapDescriptorDescriptor, destroy: DestroyFirstOps }
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), self.heap_ops); ptr::write_volatile(ptr::addr_of_mut!(DEFAULT_HEAP), self.heap); ptr::write_volatile(ptr::addr_of_mut!(DESTROY_FIRST_OPS), self.destroy); } }
    }

    unsafe fn install() -> Restore {
        let heap_ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
        let heap = ptr::read_volatile(ptr::addr_of!(DEFAULT_HEAP));
        let destroy = ptr::read_volatile(ptr::addr_of!(DESTROY_FIRST_OPS));
        let mut mock = DEFAULT_HEAP_OPS;
        mock.free = record_free;
        ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), mock);
        ptr::write_volatile(ptr::addr_of_mut!(DEFAULT_HEAP), 1usize as *mut _);
        ptr::write_volatile(ptr::addr_of_mut!(DESTROY_FIRST_OPS), DestroyFirstOps { destroy_result: destroy_to_shifted_pointer });
        Restore { heap_ops, heap, destroy }
    }

    #[test]
    fn destroys_and_deletes_only_the_first_non_null_vtable_result() {
        let _lock = TEST_LOCK.lock();
        let _restore = unsafe { install() };
        let vtable = HostDestroyFirstVtable { unresolved_00_to_3c: [0; VTABLE_DESTROY_FIRST_SLOT], destroy_first: yield_result };
        let object = HostDestroyFirstObject { vtable: &vtable, iteration_count: 4, enabled: 1 };
        unsafe {
            CALLS = 0; INDICES = [0; 4]; RESULTS = [ptr::null_mut(), 0x20usize as *mut u8, 0x30usize as *mut u8, ptr::null_mut()]; DESTROYED = ptr::null_mut(); FREED = ptr::null_mut();
            vtable_slot_40_destroy_first(ptr::addr_of!(object).cast_mut().cast());
            assert_eq!(CALLS, 2); assert_eq!(INDICES[..2], [0, 1]);
            assert_eq!(DESTROYED, 0x20usize as *mut u8); assert_eq!(FREED, 0x24usize as *mut u8);
        }
    }

    #[test]
    fn skips_disabled_non_positive_and_all_null_ranges() {
        let _lock = TEST_LOCK.lock();
        let _restore = unsafe { install() };
        let vtable = HostDestroyFirstVtable { unresolved_00_to_3c: [0; VTABLE_DESTROY_FIRST_SLOT], destroy_first: yield_result };
        for (enabled, iteration_count) in [(0, 3), (1, 0), (1, -1), (1, 3)] {
            let object = HostDestroyFirstObject { vtable: &vtable, iteration_count, enabled };
            unsafe {
                CALLS = 0; RESULTS = [ptr::null_mut(); 4]; DESTROYED = ptr::null_mut(); FREED = ptr::null_mut();
                vtable_slot_40_destroy_first(ptr::addr_of!(object).cast_mut().cast());
                assert_eq!(CALLS, if enabled == 1 && iteration_count > 0 { iteration_count as usize } else { 0 });
                assert!(DESTROYED.is_null()); assert!(FREED.is_null());
            }
        }
    }
}
