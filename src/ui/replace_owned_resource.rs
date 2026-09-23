//! Replaces an owned opaque resource when its selector changes.
//!
//! `replace_owned_resource` — original: `FUN_081ca6f8` @ **0x081ca6f8**.
//! Raw `osos.dec` establishes the true **100-byte** extent
//! `0x081ca6f8..0x081ca75b`; the next independently entered function starts
//! at `0x081ca75c`. It has four plain unconditional `bl` calls and no
//! predicated `bl` calls. Whole-image inbound-call decoding finds three plain
//! `bl` call sites and no predicated direct calls.
//!
//! # Algorithm
//!
//! If `selector_slot` already equals `selector`, return. Otherwise destroy
//! and clear the old resource when present, store the new selector, then, for
//! nonzero selectors, allocate 68 bytes and pass that allocation, `context`,
//! and the stored selector to the resident resource initializer. Store its
//! result in `resource_slot`.
//!
//! # Deliberate deviations
//!
//! `FUN_082646ac` is raw `bx lr`, so its call is omitted. The initializer at
//! `0x082645a0` has no recovered name in `names.yaml`; its verified three-word
//! ABI is retained as a volatile seam rather than asserting an identity.

use core::ptr;

const RESOURCE_SIZE: usize = 0x44;

pub type OpaqueResourceInitialize = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_opaque_resource_initialize(
    allocation: *mut u8,
    context: *mut u8,
    selector: u32,
) -> *mut u8 {
    core::mem::transmute::<usize, OpaqueResourceInitialize>(0x0826_45a0usize)(allocation, context, selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_resource_initialize(_: *mut u8, _: *mut u8, _: u32) -> *mut u8 {
    panic!("replace_owned_resource requires FUN_082645a0")
}

#[cfg(target_os = "none")]
pub static mut OPAQUE_RESOURCE_INITIALIZE: OpaqueResourceInitialize = retail_opaque_resource_initialize;
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_RESOURCE_INITIALIZE: OpaqueResourceInitialize = missing_opaque_resource_initialize;

/// # Safety
/// `resource_slot` and `selector_slot` must be valid writable slots. A non-NULL
/// resource slot must hold a tag-2 allocation suitable for `operator_delete`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn replace_owned_resource(
    _owner: *mut u8,
    resource_slot: *mut *mut u8,
    context: *mut u8,
    selector_slot: *mut u32,
    selector: u32,
) {
    if selector_slot.read() == selector {
        return;
    }
    let previous = resource_slot.read();
    if !previous.is_null() {
        crate::heap::veneers::operator_delete(previous);
        resource_slot.write(ptr::null_mut());
    }
    selector_slot.write(selector);
    if selector != 0 {
        let allocation = crate::heap::veneers::operator_new(RESOURCE_SIZE);
        let initialize = ptr::read_volatile(ptr::addr_of!(OPAQUE_RESOURCE_INITIALIZE));
        resource_slot.write(initialize(allocation, context, selector_slot.read()));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;

    static mut INITIALIZE_CALLS: u32 = 0;
    static mut INITIALIZE_ARGS: (*mut u8, *mut u8, u32) = (ptr::null_mut(), ptr::null_mut(), 0);
    static mut OBSERVED_SELECTOR: u32 = 0;

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(OPAQUE_RESOURCE_INITIALIZE).write_volatile(missing_opaque_resource_initialize) };
        }
    }

    unsafe extern "C" fn initialize(allocation: *mut u8, context: *mut u8, selector: u32) -> *mut u8 {
        INITIALIZE_CALLS += 1;
        INITIALIZE_ARGS = (allocation, context, selector);
        OBSERVED_SELECTOR = selector;
        allocation.add(4)
    }

    #[test]
    fn replaces_old_resource_and_initializes_new_selector() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _restore = Restore;
        let mut resource = crate::heap::veneers::tests::mock_block();
        let mut selector = 3u32;
        let context = 0x1234usize as *mut u8;
        unsafe {
            crate::heap::veneers::tests::set_alloc_ret(crate::heap::veneers::tests::mock_block());
            INITIALIZE_CALLS = 0;
            ptr::addr_of_mut!(OPAQUE_RESOURCE_INITIALIZE).write_volatile(initialize);
            replace_owned_resource(ptr::null_mut(), &mut resource, context, &mut selector, 9);
            assert_eq!(crate::heap::veneers::tests::free_log(), (1, crate::heap::veneers::tests::mock_block(), 2));
            assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, RESOURCE_SIZE, 2));
            assert_eq!(INITIALIZE_CALLS, 1);
            assert_eq!(INITIALIZE_ARGS, (crate::heap::veneers::tests::mock_block(), context, 9));
            assert_eq!(OBSERVED_SELECTOR, 9);
            assert_eq!(resource, crate::heap::veneers::tests::mock_block().add(4));
        }
    }

    #[test]
    fn unchanged_selector_does_not_touch_resource() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _restore = Restore;
        let mut resource = crate::heap::veneers::tests::mock_block();
        let mut selector = 9u32;
        unsafe {
            INITIALIZE_CALLS = 0;
            replace_owned_resource(ptr::null_mut(), &mut resource, ptr::null_mut(), &mut selector, 9);
            assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 0);
            assert_eq!(INITIALIZE_CALLS, 0);
            assert_eq!(resource, crate::heap::veneers::tests::mock_block());
        }
    }

    #[test]
    fn zero_selector_releases_without_reallocating() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _restore = Restore;
        let mut resource = crate::heap::veneers::tests::mock_block();
        let mut selector = 4u32;
        unsafe {
            replace_owned_resource(ptr::null_mut(), &mut resource, ptr::null_mut(), &mut selector, 0);
            assert_eq!(crate::heap::veneers::tests::free_log(), (1, crate::heap::veneers::tests::mock_block(), 2));
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 0);
            assert_eq!(resource, ptr::null_mut());
            assert_eq!(selector, 0);
        }
    }
}
