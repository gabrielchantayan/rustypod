//! Allocator-registry buffer release veneer.
//!
//! `allocator_registry_release` — original: `FUN_0807f234` @ `0x0807f234`
//! (32 bytes, `0x0807f234..0x0807f254`; **2 plain `bl` callers, 1 predicated
//! `bl` caller**). Raw words are `e3500000 e1a03001 e1a00003 e3a01038
//! 0a01a1c9 e3a02038 e1a01003 1a04f3a9`: a NULL allocator moves `buffer` to
//! r0, sets tag 0x38, and tail-branches to `free_wrapper` @ `0x080e7970`;
//! otherwise it passes `(allocator, buffer, 0x38)` to the separately linked
//! custom-allocator entry @ `0x081bc0fc`.
//!
//! Deliberate deviations: Rust uses return-position calls rather than tail
//! branches. The custom entry has no names.yaml identity yet, so target builds
//! retain its exact address as a private ABI boundary. Host builds have no
//! target-width allocator-registry representation and use `free_wrapper` for
//! either path, matching the prior cell-destruction host model.

use crate::heap::veneers::free_wrapper;

const ALLOCATOR_REGISTRY_FREE_TAG: usize = 0x38;

/// Releases `buffer` through the default heap when `allocator` is NULL, or
/// through the allocator-registry custom-release ABI otherwise.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn allocator_registry_release(allocator: *mut u8, buffer: *mut u8) {
    if allocator.is_null() {
        free_wrapper(buffer, ALLOCATOR_REGISTRY_FREE_TAG);
        return;
    }

    release_from_custom_allocator(allocator, buffer);
}

#[cfg(target_os = "none")]
#[inline(never)]
unsafe fn release_from_custom_allocator(allocator: *mut u8, buffer: *mut u8) {
    let release: unsafe extern "C" fn(*mut u8, *mut u8, usize) =
        core::mem::transmute(0x081b_c0fcusize);
    release(allocator, buffer, ALLOCATOR_REGISTRY_FREE_TAG);
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
unsafe fn release_from_custom_allocator(_allocator: *mut u8, buffer: *mut u8) {
    free_wrapper(buffer, ALLOCATOR_REGISTRY_FREE_TAG);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::allocator_registry_release;
    use crate::heap::veneers;

    #[test]
    fn null_allocator_releases_through_default_heap_with_tag_38() {
        let _lock = veneers::tests::mock_heap();
        let buffer = 0x1234usize as *mut u8;
        unsafe { allocator_registry_release(core::ptr::null_mut(), buffer) };
        assert_eq!(veneers::tests::free_log(), (1, buffer, 0x38));
    }

    #[test]
    fn host_custom_allocator_model_releases_the_requested_buffer() {
        let _lock = veneers::tests::mock_heap();
        let buffer = 0x5678usize as *mut u8;
        unsafe { allocator_registry_release(0x9abcusize as *mut u8, buffer) };
        assert_eq!(veneers::tests::free_log(), (1, buffer, 0x38));
    }
}
