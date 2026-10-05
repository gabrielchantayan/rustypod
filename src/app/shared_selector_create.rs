//! Shared selector factory, FUN_081c02c0 @ load address 0x081c02c0.
//! True extent [0x081c02c0, 0x081c0370): 176 bytes, ending in pop;
//! the next function is an independent field getter. Raw A32 decoding finds
//! two inbound plain BLs, eight outbound plain BLs and two outbound BLNEs.
//! Clear out, allocate 16 bytes, temporarily retain owner+4, construct a
//! selector wrapper, wrap it without a mutex, copy its shared body into out,
//! then release both temporaries. Allocation failures are unchecked.
//! Deviations: native repr(C) pointer fields on hosts; the unported wrapper
//! constructor at 0x081c0504 is an address-verified ABI seam. The inline
//! retain sequence reuses the equivalent slot-1 attach port. Entry r3 is dead.

use crate::app::indexed_shared_child_create::IndexedSharedOwner;
use crate::cxx::handle::{RefcountedBody, refcounted_ptr_construct_slot7,
    refcounted_body_attach_slot1, refcounted_body_release_dtor_slot1_copy,
    refcounted_body_release_slot1};
use crate::heap::veneers::operator_new;

pub type SelectorConstruct = unsafe extern "C" fn(
    *mut u8, *mut *mut RefcountedBody, u32,
) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_constructor(_: *mut u8,
    _: *mut *mut RefcountedBody, _: u32) -> *mut u8 {
    panic!("install resident selector constructor at 0x081c0504")
}

#[cfg(not(target_os = "none"))]
pub static mut SELECTOR_CONSTRUCT: SelectorConstruct = missing_constructor;

/// Construct a shared selector wrapper from the owner's body.
///
/// # Safety
/// `out` is a writable pointer slot; `owner` has a readable body field.
/// Its body must satisfy slot-1 retain/release contracts, and selector must
/// satisfy the resident constructor. Hosts must install SELECTOR_CONSTRUCT.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_selector_create(
    out: *mut *mut RefcountedBody, owner: *const IndexedSharedOwner, selector: u32,
) {
    #[cfg(target_os = "none")]
    let constructor: SelectorConstruct = core::mem::transmute(0x081c_0504usize);
    #[cfg(not(target_os = "none"))]
    let constructor = core::ptr::addr_of!(SELECTOR_CONSTRUCT).read();
    create(out, owner, selector, operator_new, constructor);
}

unsafe fn create(out: *mut *mut RefcountedBody, owner: *const IndexedSharedOwner,
    selector: u32, allocate: unsafe extern "C" fn(usize) -> *mut u8,
    constructor: SelectorConstruct) {
    let destination = refcounted_ptr_construct_slot7(out, 0, 0);
    let allocation = allocate(16);
    let mut source = core::ptr::null_mut();
    refcounted_body_attach_slot1(&mut source, (*owner).body);
    let implementation = constructor(allocation, &mut source, selector);
    let mut temporary = core::ptr::null_mut();
    let wrapped = refcounted_ptr_construct_slot7(&mut temporary, implementation as usize, 0);
    if destination != wrapped {
        refcounted_body_release_dtor_slot1_copy(destination);
        refcounted_body_attach_slot1(destination, wrapped.read());
    }
    refcounted_body_release_dtor_slot1_copy(&mut temporary);
    refcounted_body_release_slot1(&mut source);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        std::alloc::alloc(std::alloc::Layout::from_size_align(size, 8).unwrap())
    }

    unsafe extern "C" fn no_wrapper(allocation: *mut u8,
        source: *mut *mut RefcountedBody, selector: u32) -> *mut u8 {
        let body = source.read();
        if !body.is_null() {
            // Includes signed overflow: retaining MAX wraps to MIN.
            assert_eq!((*body).refcount as u32, selector.wrapping_add(1));
        }
        std::alloc::dealloc(allocation,
            std::alloc::Layout::from_size_align(16, 8).unwrap());
        core::ptr::null_mut()
    }

    #[test]
    fn null_wrapper_balances_null_live_and_wrapping_source_ownership() {
        for count in [7, i32::MAX, i32::MIN, -1] {
            let mut body = RefcountedBody { opaque0: 0, refcount: count,
                mutex: core::ptr::null_mut() };
            for source in [core::ptr::null_mut(), &mut body as *mut RefcountedBody] {
                let owner = IndexedSharedOwner { vtable: 0, body: source,
                    count: 0, selector: 0 };
                let mut out = core::ptr::dangling_mut();
                unsafe { create(&mut out, &owner, count as u32, allocate, no_wrapper); }
                assert!(out.is_null());
                assert_eq!(body.refcount, count);
            }
        }
    }
}
