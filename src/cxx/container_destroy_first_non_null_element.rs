//! Destroy and delete the first non-NULL element of an enabled container.
//!
//! `container_destroy_first_non_null_element` — original: `FUN_0839bfdc` @
//! `0x0839bfdc`.
//!
//! **76 bytes** (`0x0839bfdc..0x0839c028`): nineteen A32 words from `push
//! {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}`; `0x0839c028` starts the next
//! independently entered function. Raw decoding verifies three unconditional
//! plain direct `bl` instructions (at `0x0839c004`, `0x0839c010`, and
//! `0x0839c014`) and no predicated direct `bl`; the two inbound calls at
//! `0x0839c074` and `0x0839c0d8` are also plain `bl`.
//!
//! # Algorithm
//!
//! If byte `+0x28` is clear, return. Otherwise scan signed indices
//! `[0, *(i32 *)(this + 4))` through `container_element_at_alias_5f14`. For
//! the first non-NULL element, call the direct opaque destructor at
//! `0x0812bc8c`, then tag-2 `operator_delete` on its return value.
//!
//! # Deliberate deviations
//!
//! The opaque direct callee remains an address-named operation seam on host;
//! target builds call its verified retailOS address. The ported element accessor
//! and `operator_delete` remain direct target calls. Host callbacks use
//! native-width pointers, while target accesses retain the original word ABI.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const COUNT_OFFSET: usize = 4;
const ENABLED_OFFSET: usize = 0x28;
const RETAIL_DESTROY_ELEMENT: usize = 0x0812_bc8c;

type DestroyElement = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
pub struct ContainerDestroyFirstNonNullElementOps {
    pub element_at: unsafe extern "C" fn(*mut u8, i32) -> *mut u8,
    pub destroy: DestroyElement,
    pub delete: unsafe extern "C" fn(*mut u8),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_at(_container: *mut u8, _index: i32) -> *mut u8 {
    panic!("install container destruction host operations before calling")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_element: *mut u8) -> *mut u8 {
    panic!("install container destruction host operations before calling")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_delete(_element: *mut u8) {
    panic!("install container destruction host operations before calling")
}

#[cfg(not(target_os = "none"))]
pub static mut CONTAINER_DESTROY_FIRST_NON_NULL_ELEMENT_OPS: ContainerDestroyFirstNonNullElementOps = ContainerDestroyFirstNonNullElementOps {
    element_at: missing_element_at,
    destroy: missing_destroy,
    delete: missing_delete,
};

#[cfg(target_os = "none")]
unsafe fn element_at(container: *mut u8, index: i32) -> *mut u8 {
    unsafe { crate::cxx::templates::container_element_at_alias_5f14(container, index as usize) }
}

#[cfg(not(target_os = "none"))]
unsafe fn element_at(container: *mut u8, index: i32) -> *mut u8 {
    let ops = unsafe { core::ptr::read_volatile(addr_of!(CONTAINER_DESTROY_FIRST_NON_NULL_ELEMENT_OPS)) };
    unsafe { (ops.element_at)(container, index) }
}

#[cfg(target_os = "none")]
unsafe fn destroy(element: *mut u8) -> *mut u8 {
    let destroy: DestroyElement = unsafe { core::mem::transmute(RETAIL_DESTROY_ELEMENT) };
    unsafe { destroy(element) }
}

#[cfg(not(target_os = "none"))]
unsafe fn destroy(element: *mut u8) -> *mut u8 {
    let ops = unsafe { core::ptr::read_volatile(addr_of!(CONTAINER_DESTROY_FIRST_NON_NULL_ELEMENT_OPS)) };
    unsafe { (ops.destroy)(element) }
}

#[cfg(target_os = "none")]
unsafe fn delete(element: *mut u8) {
    unsafe { crate::heap::veneers::operator_delete(element) }
}

#[cfg(not(target_os = "none"))]
unsafe fn delete(element: *mut u8) {
    let ops = unsafe { core::ptr::read_volatile(addr_of!(CONTAINER_DESTROY_FIRST_NON_NULL_ELEMENT_OPS)) };
    unsafe { (ops.delete)(element) }
}

/// Scan an enabled container and destroy then delete its first non-NULL element.
///
/// # Safety
///
/// `container` must be readable through `+0x28`. When enabled, its signed count
/// at `+0x04` and every indexed element must be valid as retailOS requires; the
/// original performs no NULL or bounds validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_destroy_first_non_null_element")]
#[inline(never)]
pub unsafe extern "C" fn container_destroy_first_non_null_element(container: *mut u8) {
    if unsafe { container.add(ENABLED_OFFSET).read_volatile() } == 0 {
        return;
    }
    let count = unsafe { container.add(COUNT_OFFSET).cast::<i32>().read_volatile() };
    let mut index = 0;
    while index < count {
        let element = unsafe { element_at(container, index) };
        if !element.is_null() {
            unsafe { delete(destroy(element)) };
            return;
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ELEMENTS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut INDICES: [i32; 3] = [0; 3];
    static mut INDEX_COUNT: usize = 0;
    static mut DESTROYED: *mut u8 = core::ptr::null_mut();
    static mut DELETED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn element_at(_container: *mut u8, index: i32) -> *mut u8 {
        unsafe {
            INDICES[INDEX_COUNT] = index;
            INDEX_COUNT += 1;
            ELEMENTS[index as usize]
        }
    }

    unsafe extern "C" fn destroy(element: *mut u8) -> *mut u8 {
        unsafe {
            DESTROYED = element;
            element.add(1)
        }
    }

    unsafe extern "C" fn delete(element: *mut u8) {
        unsafe { DELETED = element }
    }

    unsafe fn reset(elements: [*mut u8; 3]) {
        unsafe {
            ELEMENTS = elements;
            INDEX_COUNT = 0;
            DESTROYED = core::ptr::null_mut();
            DELETED = core::ptr::null_mut();
            CONTAINER_DESTROY_FIRST_NON_NULL_ELEMENT_OPS = ContainerDestroyFirstNonNullElementOps { element_at, destroy, delete };
        }
    }

    #[test]
    fn disabled_container_skips_all_calls() {
        let _guard = TEST_LOCK.lock();
        let mut container = [0u32; 11];
        unsafe {
            reset([core::ptr::null_mut(); 3]);
            container_destroy_first_non_null_element(container.as_mut_ptr().cast());
            assert_eq!(INDEX_COUNT, 0);
            assert!(DESTROYED.is_null());
            assert!(DELETED.is_null());
        }
    }

    #[test]
    fn non_positive_count_skips_indexing() {
        let _guard = TEST_LOCK.lock();
        let mut container = [0u32; 11];
        container[1] = (-1i32) as u32;
        unsafe {
            container.as_mut_ptr().cast::<u8>().add(ENABLED_OFFSET).write(1);
            reset([core::ptr::null_mut(); 3]);
            container_destroy_first_non_null_element(container.as_mut_ptr().cast());
            assert_eq!(INDEX_COUNT, 0);
        }
    }

    #[test]
    fn destroys_and_deletes_first_non_null_element() {
        let _guard = TEST_LOCK.lock();
        let mut container = [0u32; 11];
        let mut first = [0u8; 2];
        let mut second = [0u8; 2];
        container[1] = 3;
        unsafe {
            container.as_mut_ptr().cast::<u8>().add(ENABLED_OFFSET).write(1);
            reset([core::ptr::null_mut(), first.as_mut_ptr(), second.as_mut_ptr()]);
            container_destroy_first_non_null_element(container.as_mut_ptr().cast());
            assert_eq!(&INDICES[..INDEX_COUNT], &[0, 1]);
            assert_eq!(DESTROYED, first.as_mut_ptr());
            assert_eq!(DELETED, first.as_mut_ptr().add(1));
        }
    }
}
