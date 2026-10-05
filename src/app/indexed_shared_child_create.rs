//! Indexed shared-child factory, `FUN_081c048c` @ load address 0x081c048c.
//! Raw extent [0x081c048c, 0x081c0504): 120 bytes; the next function
//! starts with push {r4,r5,r6,lr}. Whole-image A32 decoding verifies two
//! inbound plain BLs (0x08280a64, 0x08280c48), six outbound plain BLs,
//! and no predicated BLs in either direction.
//!
//! Reject index >= count by constructing an empty handle. Otherwise allocate
//! 88 bytes, retain the owner's shared body in a temporary handle, construct
//! the child with that handle, selector and index, wrap the returned child
//! without a mutex, then release the temporary. Allocation is unchecked.
//! Deliberate deviations: native-pointer repr(C) fields on hosts; the resident
//! child constructor at 0x081375e8 is an indirect ABI seam, not a guessed
//! concrete class identity. Entry r3 is dead, not a fourth argument.

use crate::cxx::handle::{RefcountedBody, refcounted_body_attach_slot1,
    refcounted_body_release_slot1, refcounted_handle_construct_variant};
use crate::heap::veneers::operator_new;

#[repr(C)]
pub struct IndexedSharedOwner {
    pub vtable: usize,
    pub body: *mut RefcountedBody,
    pub count: u32,
    pub selector: u32,
}

pub type SharedChildConstruct = unsafe extern "C" fn(
    *mut u8, *mut *mut RefcountedBody, u32, u32,
) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_child(_: *mut u8, _: *mut *mut RefcountedBody,
    _: u32, _: u32) -> *mut u8 {
    panic!("install resident shared-child constructor at 0x081375e8")
}

#[cfg(not(target_os = "none"))]
pub static mut SHARED_CHILD_CONSTRUCT: SharedChildConstruct = missing_child;

/// Construct a child handle for an unsigned index.
///
/// # Safety
/// `out` is writable and `owner` is readable. Its body must satisfy the
/// slot-1 retain/release contracts; the selector and index must satisfy the
/// resident constructor. On hosts, install SHARED_CHILD_CONSTRUCT first.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_shared_child_create(
    out: *mut *mut RefcountedBody, owner: *const IndexedSharedOwner, index: u32,
) {
    #[cfg(target_os = "none")]
    let constructor: SharedChildConstruct = core::mem::transmute(0x0813_75e8usize);
    #[cfg(not(target_os = "none"))]
    let constructor = core::ptr::addr_of!(SHARED_CHILD_CONSTRUCT).read();
    create(out, owner, index, operator_new, constructor);
}

unsafe fn create(out: *mut *mut RefcountedBody, owner: *const IndexedSharedOwner,
    index: u32, allocate: unsafe extern "C" fn(usize) -> *mut u8,
    constructor: SharedChildConstruct) {
    if (*owner).count <= index {
        refcounted_handle_construct_variant(out, 0, 0);
        return;
    }
    let allocation = allocate(0x58);
    let mut temporary = core::ptr::null_mut();
    refcounted_body_attach_slot1(&mut temporary, (*owner).body);
    let child = constructor(allocation, &mut temporary, (*owner).selector, index);
    refcounted_handle_construct_variant(out, child as usize, 0);
    refcounted_body_release_slot1(&mut temporary);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn rejects_empty_equal_and_unsigned_max_without_touching_body() {
        for (count, index) in [(0, 0), (3, 3), (3, 4), (3, u32::MAX)] {
            let owner = IndexedSharedOwner { vtable: 0,
                body: core::ptr::dangling_mut(), count, selector: 9 };
            let mut out = core::ptr::dangling_mut();
            unsafe { indexed_shared_child_create(&mut out, &owner, index); }
            assert!(out.is_null());
        }
    }

    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        std::alloc::alloc(std::alloc::Layout::from_size_align(size, 8).unwrap())
    }

    // Model a constructor that keeps no child. Check the temporary ownership
    // while it is live, then let the real slot-1 release balance the retain.
    unsafe extern "C" fn no_child(allocation: *mut u8,
        slot: *mut *mut RefcountedBody, selector: u32, index: u32) -> *mut u8 {
        let body = slot.read();
        if !body.is_null() {
            assert_eq!((*body).refcount, 8);
        }
        assert_eq!(selector, 0xdead_beef);
        assert!(index == 0 || index == u32::MAX - 1);
        std::alloc::dealloc(allocation,
            std::alloc::Layout::from_size_align(88, 8).unwrap());
        core::ptr::null_mut()
    }

    #[test]
    fn valid_extreme_indices_balance_temporary_ownership_even_for_null_child() {
        let mut body = RefcountedBody { opaque0: 0, refcount: 7,
            mutex: core::ptr::null_mut() };
        for shared in [&mut body as *mut RefcountedBody, core::ptr::null_mut()] {
            for index in [0, u32::MAX - 1] {
                let owner = IndexedSharedOwner { vtable: 0, body: shared,
                    count: u32::MAX, selector: 0xdead_beef };
                let mut out = core::ptr::dangling_mut();
                unsafe { create(&mut out, &owner, index, allocate, no_child); }
                assert!(out.is_null());
                assert_eq!(body.refcount, 7);
            }
        }
    }
}
