//! `object_layout_construct` — original: `FUN_08153140` @ 0x08153140 (208
//! instruction bytes, 0x08153140..0x0815320f). The five literal-pool words
//! occupy 0x08153210..0x08153223; the next real function begins at 0x08153224.
//! Raw A32 decoding finds 15 outbound plain `bl` instructions and no predicated
//! `bl`; whole-image decoding finds three inbound plain `bl` instructions and
//! no predicated forms.
//!
//! # Algorithm
//!
//! Initializes a 0x274-byte caller allocation as a nested object layout. Four
//! opaque base constructors establish the outer hierarchy. A supplied shared
//! object is stored at the hierarchy's +0x128 slot; when absent, a 0xdc-byte
//! object is allocated and passed to its opaque default constructor. Six
//! embedded animation defaults follow, then three refcounted subobjects receive
//! their derived vtables and cleared value words. The third subobject's base is
//! the returned object at -0x254.
//!
//! # Deliberate deviations
//!
//! The four hierarchy constructors and shared-object default constructor have
//! no recovered semantic identities. Target builds call their verified retailOS
//! addresses. Host builds expose narrow seams; the already ported animation and
//! refcounted-base constructors are called directly.

use crate::app::animation::animation_default_init;
use crate::app::fixed_value::refcounted_base_init;
use crate::heap::veneers::operator_new;

const OUTER_VTABLE: u32 = 0x0898_69b0;
const INNER_VTABLE: u32 = 0x0898_69c0;
const FIRST_VALUE_VTABLE: u32 = 0x0898_806c;
const SECOND_VALUE_VTABLE: u32 = 0x0898_9b48;
const THIRD_VALUE_VTABLE: u32 = 0x0898_00f8;
const SHARED_OBJECT_SIZE: usize = 0xdc;

type OpaqueConstruct = unsafe extern "C" fn(*mut u32) -> *mut u32;
type SharedAllocate = unsafe extern "C" fn(usize) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn outer_base_construct(storage: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueConstruct>(0x0828_0fc0)(storage)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_outer_base_construct(storage: *mut u32) -> *mut u32 { storage }
#[cfg(not(target_os = "none"))]
pub static mut OUTER_BASE_CONSTRUCT: OpaqueConstruct = missing_outer_base_construct;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn outer_base_construct(storage: *mut u32) -> *mut u32 { OUTER_BASE_CONSTRUCT(storage) }

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shared_object_default_construct(storage: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueConstruct>(0x0827_bc9c)(storage)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_shared_object_default_construct(storage: *mut u32) -> *mut u32 { storage }
#[cfg(not(target_os = "none"))]
pub static mut SHARED_OBJECT_DEFAULT_CONSTRUCT: OpaqueConstruct = missing_shared_object_default_construct;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shared_object_default_construct(storage: *mut u32) -> *mut u32 { SHARED_OBJECT_DEFAULT_CONSTRUCT(storage) }

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn allocate_shared_object(size: usize) -> *mut u32 { operator_new(size).cast() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_allocate_shared_object(size: usize) -> *mut u32 { operator_new(size).cast() }
#[cfg(not(target_os = "none"))]
pub static mut ALLOCATE_SHARED_OBJECT: SharedAllocate = default_allocate_shared_object;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn allocate_shared_object(size: usize) -> *mut u32 { ALLOCATE_SHARED_OBJECT(size) }

/// Constructs the nested object layout in caller-owned storage.
///
/// # Safety
/// The caller must provide the retail allocation's writable 0x274-byte extent.
/// The retail implementation has no null or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_layout_construct(storage: *mut u32, shared: *mut u32) -> *mut u32 {
    storage.write_volatile(OUTER_VTABLE);
    let mut hierarchy = outer_base_construct(storage.add(2));
    hierarchy = outer_base_construct(hierarchy.add(0x12));
    hierarchy = outer_base_construct(hierarchy.add(0x12));
    hierarchy = outer_base_construct(hierarchy.add(0x12));
    let object = hierarchy.sub(0x38);
    let shared = if shared.is_null() {
        shared_object_default_construct(allocate_shared_object(SHARED_OBJECT_SIZE))
    } else { shared };
    object.add(0x4a).write_volatile(shared as usize as u32);
    object.write_volatile(INNER_VTABLE);
    let mut value = animation_default_init(object.add(0x4f).cast()).cast::<u32>();
    for _ in 0..5 { value = animation_default_init(value.add(9).cast()).cast::<u32>(); }
    value = value.add(9);
    refcounted_base_init(value.cast());
    value.write_volatile(FIRST_VALUE_VTABLE);
    value.add(6).write_volatile(0);
    value.add(7).write_volatile(0);
    value = value.add(8);
    refcounted_base_init(value.cast());
    value.write_volatile(SECOND_VALUE_VTABLE);
    value.add(6).write_volatile(0);
    value.add(7).write_volatile(0);
    value = value.add(8);
    refcounted_base_init(value.cast());
    value.add(7).write_volatile(0);
    value.write_volatile(THIRD_VALUE_VTABLE);
    value.sub(0x95)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut HIERARCHY_CALLS: usize = 0;
    static mut TERMINAL_HIERARCHY: *mut u32 = core::ptr::null_mut();
    static mut ALLOCATED_SHARED: *mut u32 = core::ptr::null_mut();
    static mut DEFAULT_SHARED_CALL: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_hierarchy(_storage: *mut u32) -> *mut u32 {
        HIERARCHY_CALLS += 1;
        TERMINAL_HIERARCHY
    }
    unsafe extern "C" fn record_allocate_shared(_size: usize) -> *mut u32 { ALLOCATED_SHARED }
    unsafe extern "C" fn record_shared_default(storage: *mut u32) -> *mut u32 {
        DEFAULT_SHARED_CALL = storage;
        storage
    }

    #[test]
    fn constructs_the_layout_and_allocates_only_for_a_null_shared_object() {
        let _guard = SEAM_LOCK.lock();
        let mut storage = [0xfeed_faceu32; 0x274 / 4];
        let mut shared_allocation = [0u32; SHARED_OBJECT_SIZE / 4];
        let supplied_shared = 0x1234_5678usize as *mut u32;
        unsafe {
            HIERARCHY_CALLS = 0;
            TERMINAL_HIERARCHY = storage.as_mut_ptr().add(0x38);
            ALLOCATED_SHARED = shared_allocation.as_mut_ptr();
            DEFAULT_SHARED_CALL = core::ptr::null_mut();
            OUTER_BASE_CONSTRUCT = record_hierarchy;
            ALLOCATE_SHARED_OBJECT = record_allocate_shared;
            SHARED_OBJECT_DEFAULT_CONSTRUCT = record_shared_default;
            let result = object_layout_construct(storage.as_mut_ptr(), supplied_shared);
            assert_eq!(result, storage.as_mut_ptr());
            assert_eq!(HIERARCHY_CALLS, 4);
            assert_eq!(DEFAULT_SHARED_CALL, core::ptr::null_mut());
            assert_eq!(storage[0], INNER_VTABLE);
            assert_eq!(storage[0x4a], supplied_shared as usize as u32);
            assert_eq!(storage[0x85], FIRST_VALUE_VTABLE);
            assert_eq!(storage[0x8d], SECOND_VALUE_VTABLE);
            assert_eq!(storage[0x95], THIRD_VALUE_VTABLE);
            assert_eq!(storage[0x9c], 0);
            let result = object_layout_construct(storage.as_mut_ptr(), core::ptr::null_mut());
            assert_eq!(result, storage.as_mut_ptr());
            assert_eq!(DEFAULT_SHARED_CALL, ALLOCATED_SHARED);
            assert_eq!(storage[0x4a], ALLOCATED_SHARED as usize as u32);
            OUTER_BASE_CONSTRUCT = missing_outer_base_construct;
            ALLOCATE_SHARED_OBJECT = default_allocate_shared_object;
            SHARED_OBJECT_DEFAULT_CONSTRUCT = missing_shared_object_default_construct;
        }
    }
}
