//! Opaque indexed element-array disposal.
//!
//! `opaque_indexed_element_array_dispose` — original: `FUN_083cfbf4` @
//! **0x083cfbf4** (96 bytes; true extent `0x083cfbf4..0x083cfc53`, with the
//! next real function beginning at `0x083cfc54`). Raw ARM decoding finds two
//! incoming direct plain `bl` calls (at `0x083cfcac` and `0x083cfcd4`) and no
//! predicated direct `bl` calls. The body makes two plain direct `bl` calls:
//! the unidentified element destructor `FUN_0810b3e4`, then
//! [`operator_delete`]; it has no predicated direct calls. It also makes an
//! indirect `blx` through vtable slot `+0x40`.
//!
//! # Algorithm
//!
//! When `enabled` is nonzero, visits indices `[0, count)`. It retrieves each
//! element through vtable slot `+0x40`; every non-NULL element is passed first
//! to the observed destructor and then tag-2 deleted.
//!
//! # Deliberate deviations
//!
//! `FUN_0810b3e4` has no established class identity, so the host build exposes
//! it as a test seam while target builds invoke its recovered address directly.
//! Host fixtures widen the vtable pointer while preserving target field meanings.

use crate::cxx::container_element_at_083d6818::container_element_at_083d6818;
use crate::heap::veneers::operator_delete;

const OPAQUE_ELEMENT_DESTROY_ADDRESS: usize = 0x0810_b3e4;

#[cfg(target_os = "none")]
unsafe extern "C" fn destroy_opaque_element(element: *mut u8) -> *mut u8 {
    let destroy: unsafe extern "C" fn(*mut u8) -> *mut u8 = core::mem::transmute(OPAQUE_ELEMENT_DESTROY_ADDRESS);
    destroy(element)
}

#[cfg(not(target_os = "none"))]
pub type OpaqueElementDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_element_destroy(_element: *mut u8) -> *mut u8 {
    panic!("opaque_indexed_element_array_dispose requires unresolved FUN_0810b3e4")
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_ELEMENT_DESTROY: OpaqueElementDestroy = missing_opaque_element_destroy;

#[cfg(not(target_os = "none"))]
pub type OpaqueElementDelete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_ELEMENT_DELETE: OpaqueElementDelete = operator_delete;

/// Host representation of the fields observed by this routine.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOpaqueIndexedElementArray {
    pub vtable: *const usize,
    pub count: i32,
    pub unresolved_0c: u32,
    pub enabled: u8,
}

#[inline(always)]
unsafe fn element_count(array: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    { array.add(4).cast::<i32>().read_volatile() }
    #[cfg(not(target_os = "none"))]
    { (*array.cast::<HostOpaqueIndexedElementArray>()).count }
}

#[inline(always)]
unsafe fn is_enabled(array: *mut u8) -> bool {
    #[cfg(target_os = "none")]
    { array.add(0x10).read_volatile() != 0 }
    #[cfg(not(target_os = "none"))]
    { (*array.cast::<HostOpaqueIndexedElementArray>()).enabled != 0 }
}

/// Destroys and deletes every occupied element when the array is enabled.
///
/// # Safety
///
/// `array` must identify the observed target layout and every non-NULL element
/// returned by vtable slot `+0x40` must be accepted by the destructor and heap.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_indexed_element_array_dispose(array: *mut u8) {
    if !is_enabled(array) {
        return;
    }

    let count = element_count(array);
    let mut index = 0i32;
    while index < count {
        let element = container_element_at_083d6818(array, index as u32);
        if !element.is_null() {
            #[cfg(target_os = "none")]
            {
                destroy_opaque_element(element);
                operator_delete(element);
            }
            #[cfg(not(target_os = "none"))]
            {
                OPAQUE_ELEMENT_DESTROY(element);
                OPAQUE_ELEMENT_DELETE(element);
            }
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::container_element_at_083d6818::HostElementVtable;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOTS: [*mut u8; 3] = [ptr::null_mut(); 3];
    static mut INDEXES: [u32; 3] = [0; 3];
    static mut INDEX_COUNT: usize = 0;
    static mut DESTROYED: [usize; 3] = [0; 3];
    static mut DESTROY_COUNT: usize = 0;
    static mut DELETED: [usize; 3] = [0; 3];
    static mut DELETE_COUNT: usize = 0;

    unsafe extern "C" fn element_slot(_: *mut u8, index: u32) -> *mut *mut u8 {
        INDEXES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        SLOTS.as_mut_ptr().add(index as usize)
    }

    unsafe extern "C" fn record_destroy(element: *mut u8) -> *mut u8 {
        DESTROYED[DESTROY_COUNT] = element as usize;
        DESTROY_COUNT += 1;
        element
    }

    unsafe extern "C" fn record_delete(element: *mut u8) {
        DELETED[DELETE_COUNT] = element as usize;
        DELETE_COUNT += 1;
    }

    fn fixture(count: i32, enabled: u8) -> (HostOpaqueIndexedElementArray, HostElementVtable) {
        (HostOpaqueIndexedElementArray { vtable: ptr::null(), count, unresolved_0c: 0, enabled },
         HostElementVtable { unresolved_00_to_3c: [0; 0x40 / 4], element_slot })
    }

    #[test]
    fn disabled_and_nonpositive_arrays_do_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            OPAQUE_ELEMENT_DESTROY = record_destroy;
            OPAQUE_ELEMENT_DELETE = record_delete;
            for (count, enabled) in [(2, 0), (0, 1), (-1, 1)] {
                let (mut array, vtable) = fixture(count, enabled);
                array.vtable = (&vtable as *const HostElementVtable).cast();
                INDEX_COUNT = 0;
                opaque_indexed_element_array_dispose(ptr::addr_of_mut!(array).cast());
                assert_eq!(INDEX_COUNT, 0);
            }
        }
    }

    #[test]
    fn destroys_then_deletes_nonnull_elements_in_index_order() {
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(3, 1);
        let mut first = [0u8; 8];
        let mut third = [0u8; 8];
        unsafe {
            array.vtable = (&vtable as *const HostElementVtable).cast();
            SLOTS = [first.as_mut_ptr(), ptr::null_mut(), third.as_mut_ptr()];
            INDEX_COUNT = 0; DESTROY_COUNT = 0; DELETE_COUNT = 0;
            OPAQUE_ELEMENT_DESTROY = record_destroy;
            OPAQUE_ELEMENT_DELETE = record_delete;
            opaque_indexed_element_array_dispose(ptr::addr_of_mut!(array).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DESTROYED[..DESTROY_COUNT], &[first.as_mut_ptr() as usize, third.as_mut_ptr() as usize]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[first.as_mut_ptr() as usize, third.as_mut_ptr() as usize]);
        }
    }
}
