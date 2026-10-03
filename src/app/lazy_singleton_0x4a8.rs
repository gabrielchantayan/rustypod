//! Lazy getter @ 0x08257ff4 (`FUN_08257ff4`), true extent 52 bytes:
//! 44 instruction bytes and eight literal bytes before the next function
//! at 0x08258028. Raw A32 decoding verifies two inbound plain BL calls,
//! zero predicated BL calls, and two outbound plain BL instructions.
//!
//! Read cache 0x08a09e7c; if NULL, allocate 0x4a8 bytes with tag-2
//! operator_new, construct at 0x0825b56c, store the constructor's return,
//! and reload the cache. NULL is not remembered as a completed attempt.
//! The class is unidentified; callers use virtual dispatch (including +0x64).
//! Deliberate deviations: volatile cache accesses preserve the final reload;
//! the resident constructor is called through its verified ARM address.
//! Host builds use a separate cache and reject an unwired constructor rather
//! than pretending to initialize this complex C++ object. No locking or NULL
//! allocation guard is added.

use core::ptr::{read_volatile, write_volatile};
use crate::heap::veneers::operator_new;

const OBJECT_SIZE: usize = 0x4a8;

#[cfg(not(target_os = "none"))]
static mut HOST_CACHE: *mut u8 = core::ptr::null_mut();

#[inline(always)]
unsafe fn construct_object(object: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let construct: unsafe extern "C" fn(*mut u8) -> *mut u8 =
            core::mem::transmute(0x0825_b56cusize);
        construct(object)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = object;
        panic!("resident singleton constructor 0x0825b56c requires firmware");
    }
}

#[inline(always)]
unsafe fn get_or_construct(
    cache: *mut *mut u8,
    allocate: impl FnOnce(usize) -> *mut u8,
    construct: impl FnOnce(*mut u8) -> *mut u8,
) -> *mut u8 {
    if read_volatile(cache).is_null() {
        let object = construct(allocate(OBJECT_SIZE));
        write_volatile(cache, object);
    }
    read_volatile(cache)
}

/// Return the lazily constructed 0x4a8-byte singleton; see module evidence.
///
/// # Safety
/// Firmware heap and constructor must be initialized. As in retailOS,
/// callers must serialize initialization of the shared cache themselves.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_singleton_0x4a8_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    let cache = 0x08a0_9e7c as *mut *mut u8;
    #[cfg(not(target_os = "none"))]
    let cache = core::ptr::addr_of_mut!(HOST_CACHE);
    get_or_construct(cache, |size| operator_new(size), |object| construct_object(object))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    #[test]
    fn cached_object_bypasses_allocation_and_construction() {
        let mut storage = [0u8; OBJECT_SIZE];
        let expected = storage.as_mut_ptr();
        let mut cache = expected;
        unsafe {
            assert_eq!(get_or_construct(&mut cache,
                |_| panic!("cached getter allocated"),
                |_| panic!("cached getter constructed")), expected);
        }
    }

    #[test]
    fn adjusted_constructor_return_overwrites_constructor_cache_write() {
        let mut storage = [0u8; OBJECT_SIZE];
        let allocation = storage.as_mut_ptr();
        let adjusted = unsafe { allocation.add(32) };
        let mut cache = null_mut();
        let slot = &mut cache as *mut *mut u8;
        unsafe {
            let result = get_or_construct(slot, |size| {
                assert_eq!(size, OBJECT_SIZE);
                allocation
            }, |object| {
                assert_eq!(object, allocation);
                write_volatile(slot, allocation);
                adjusted
            });
            assert_eq!(result, adjusted);
            assert_eq!(cache, adjusted);
        }
    }

    #[test]
    fn null_constructor_result_retries_and_null_allocation_is_forwarded() {
        let mut cache = null_mut();
        let mut attempts = 0;
        for _ in 0..2 {
            unsafe {
                assert!(get_or_construct(&mut cache, |size| {
                    assert_eq!(size, OBJECT_SIZE);
                    attempts += 1;
                    null_mut()
                }, |object| {
                    assert!(object.is_null());
                    null_mut()
                }).is_null());
            }
            assert!(cache.is_null());
        }
        assert_eq!(attempts, 2);
    }
}
