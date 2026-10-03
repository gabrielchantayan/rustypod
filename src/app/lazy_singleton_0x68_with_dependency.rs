//! Lazy singleton getter @ 0x08257f34 (`FUN_08257f34`), true size 76 bytes:
//! 68 code bytes plus literals at 0x08257f78/7c, next function 0x08257f80.
//! Raw A32 words verify two inbound plain BL calls, zero predicated inbound
//! BL calls, four outbound plain BL instructions, and zero predicated calls.
//!
//! Read cache 0x089d02a0. On NULL allocate 0x68 bytes, allocate 0x898 bytes,
//! construct the latter at 0x0825a5c4, then pass its return as the dependency
//! to constructor 0x0825b318 for the first allocation. Store that constructor's
//! return and reload the cache. NULL results retry on the next call.
//! Callers use virtual dispatch and boot-time readiness checking; no concrete
//! class identity is established. Deliberate deviations: volatile cache access
//! preserves the final reload; unported constructors use exact-address ARM
//! calls, with host-only replacement closures and a separate host cache.
//! No locking, allocation guard, or invented constructor behavior is added.

use core::ptr::{read_volatile, write_volatile};
use crate::heap::veneers::operator_new;

#[cfg(not(target_os = "none"))]
static mut HOST_CACHE: *mut u8 = core::ptr::null_mut();

#[inline(always)]
unsafe fn construct_dependency(object: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let construct: unsafe extern "C" fn(*mut u8) -> *mut u8 =
            core::mem::transmute(0x0825_a5c4usize);
        construct(object)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = object;
        panic!("resident dependency constructor 0x0825a5c4 requires firmware");
    }
}

#[inline(always)]
unsafe fn construct_singleton(object: *mut u8, dependency: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let construct: unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8 =
            core::mem::transmute(0x0825_b318usize);
        construct(object, dependency)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (object, dependency);
        panic!("resident singleton constructor 0x0825b318 requires firmware");
    }
}

#[inline(always)]
unsafe fn get_or_construct(
    cache: *mut *mut u8,
    mut allocate: impl FnMut(usize) -> *mut u8,
    dependency_construct: impl FnOnce(*mut u8) -> *mut u8,
    singleton_construct: impl FnOnce(*mut u8, *mut u8) -> *mut u8,
) -> *mut u8 {
    if read_volatile(cache).is_null() {
        let object = allocate(0x68);
        let dependency = dependency_construct(allocate(0x898));
        let result = singleton_construct(object, dependency);
        write_volatile(cache, result);
    }
    read_volatile(cache)
}

/// Return the cached singleton, constructing its dependency first when absent.
///
/// # Safety
/// The firmware allocator and both resident constructors must be initialized.
/// Callers must serialize access to the shared cache, as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_singleton_0x68_with_dependency_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    let cache = 0x089d_02a0 as *mut *mut u8;
    #[cfg(not(target_os = "none"))]
    let cache = core::ptr::addr_of_mut!(HOST_CACHE);
    get_or_construct(cache, |size| operator_new(size),
        |object| construct_dependency(object),
        |object, dependency| construct_singleton(object, dependency))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    #[test]
    fn cached_public_getter_bypasses_resident_calls() {
        let mut object = [0u8; 0x68];
        unsafe {
            HOST_CACHE = object.as_mut_ptr();
            assert_eq!(lazy_singleton_0x68_with_dependency_get(), object.as_mut_ptr());
            HOST_CACHE = null_mut();
        }
    }

    #[test]
    fn construction_orders_allocations_and_caches_adjusted_result() {
        let mut object = [0u8; 0x68];
        let mut dependency = [0u8; 0x898];
        let raw_object = object.as_mut_ptr();
        let raw_dependency = dependency.as_mut_ptr();
        let adjusted_dependency = unsafe { raw_dependency.add(32) };
        let adjusted_object = unsafe { raw_object.add(4) };
        let mut cache = null_mut();
        let slot = &mut cache as *mut *mut u8;
        let phase = core::cell::Cell::new(0);
        unsafe {
            let result = get_or_construct(slot, |size| {
                let step = phase.get();
                phase.set(step + 1);
                match step {
                    0 => { assert_eq!(size, 0x68); raw_object }
                    1 => { assert_eq!(size, 0x898); raw_dependency }
                    _ => panic!("unexpected allocation"),
                }
            }, |allocation| {
                assert_eq!(phase.get(), 2);
                assert_eq!(allocation, raw_dependency);
                phase.set(3);
                adjusted_dependency
            }, |allocation, dependency| {
                assert_eq!(phase.get(), 3);
                assert_eq!(allocation, raw_object);
                assert_eq!(dependency, adjusted_dependency);
                write_volatile(slot, raw_object);
                adjusted_object
            });
            assert_eq!(result, adjusted_object);
            assert_eq!(cache, adjusted_object);
            assert_eq!(get_or_construct(slot, |_| panic!("cached allocation"),
                |_| panic!("cached dependency"), |_, _| panic!("cached singleton")),
                adjusted_object);
        }
    }

    #[test]
    fn null_result_retries_and_null_inputs_are_not_guarded() {
        let mut cache = null_mut();
        let mut allocations = 0;
        for _ in 0..2 {
            unsafe {
                assert!(get_or_construct(&mut cache, |_| {
                    allocations += 1;
                    null_mut()
                }, |dependency| {
                    assert!(dependency.is_null());
                    null_mut()
                }, |object, dependency| {
                    assert!(object.is_null());
                    assert!(dependency.is_null());
                    null_mut()
                }).is_null());
            }
            assert!(cache.is_null());
        }
        assert_eq!(allocations, 4);
    }
}
