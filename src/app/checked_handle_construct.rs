//! Checked handle constructor, FUN_081c0378 @ load address 0x081c0378.
//! True extent [0x081c0378, 0x081c042c): 180 bytes including the four-byte
//! vtable literal (176 instruction bytes). Raw A32 words verify two inbound
//! plain BLs, eight outbound plain BLs, zero predicated BLs, and two BLX calls.
//!
//! Install the wrapper vtable, construct and copy its slot-1 shared handle,
//! invoke implementation vtable slot 4 with both request words, then re-read
//! the implementation status. Nonzero status clears the shared handle through
//! empty-handle assignment and caches zero; zero status caches virtual slot 6's
//! return value. Return the wrapper. Concrete implementation class and request
//! meanings remain unknown. Deliberate deviation: repr(C) native pointer fields
//! and native vtable slots on hosts; target fields retain four-byte spacing.

use crate::cxx::handle::{RefcountedBody, handle_deref_or_null,
    refcounted_ptr_construct_slot1, refcounted_ptr_copy_assign_slot1,
    refcounted_body_release_slot1};

#[repr(C)]
pub struct CheckedHandle {
    pub vtable: usize,
    pub body: *mut RefcountedBody,
    pub cached: u32,
}

#[repr(C)]
pub struct CheckedImplementation {
    pub vtable: *const usize,
    pub status: u32,
}

unsafe fn implementation(slot: *mut *mut RefcountedBody) -> *mut CheckedImplementation {
    handle_deref_or_null(slot.cast()).cast()
}

/// # Safety
/// `out` is writable; `source` is a readable slot satisfying slot-1 ownership
/// contracts. Its implementation must be non-NULL, with readable status and
/// vtable slots 4 and 6 having the ABIs below. Virtual calls must leave a valid
/// implementation in the handle. Final releases require the slot-1 destructor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn checked_handle_construct(
    out: *mut CheckedHandle, source: *const *mut RefcountedBody,
    request: u32, selector: u32,
) -> *mut CheckedHandle {
    (*out).vtable = 0x0898_ccc8;
    let slot = core::ptr::addr_of_mut!((*out).body);
    refcounted_ptr_construct_slot1(slot, 0, 0);
    refcounted_ptr_copy_assign_slot1(slot, source);
    let object = implementation(slot);
    let process: unsafe extern "C" fn(*mut CheckedImplementation, u32, u32) =
        core::mem::transmute((*object).vtable.add(4).read());
    process(object, request, selector);
    let object = implementation(slot);
    let cached = if (*object).status != 0 {
        let mut empty = core::ptr::null_mut();
        refcounted_ptr_construct_slot1(&mut empty, 0, 0);
        refcounted_ptr_copy_assign_slot1(slot, &empty);
        refcounted_body_release_slot1(&mut empty);
        0
    } else {
        let object = implementation(slot);
        let value: unsafe extern "C" fn(*mut CheckedImplementation) -> u32 =
            core::mem::transmute((*object).vtable.add(6).read());
        value(object)
    };
    (*out).cached = cached;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn process(object: *mut CheckedImplementation, request: u32, selector: u32) {
        assert_eq!(request, u32::MAX);
        (*object).status = selector;
    }
    unsafe extern "C" fn value(object: *mut CheckedImplementation) -> u32 {
        assert_eq!((*object).status, 0);
        0xdead_beef
    }

    #[test]
    fn observes_post_dispatch_status_and_balances_failed_handle_ownership() {
        let table = [0, 0, 0, 0, process as *const () as usize, 0, value as *const () as usize];
        for status in [0, 1, u32::MAX] {
            let mut object = CheckedImplementation { vtable: table.as_ptr(), status: !status };
            let mut body = RefcountedBody { opaque0: (&mut object as *mut _) as usize,
                refcount: 7, mutex: core::ptr::null_mut() };
            let source = &mut body as *mut RefcountedBody;
            let mut out = CheckedHandle { vtable: 0, body: core::ptr::dangling_mut(), cached: 17 };
            unsafe {
                assert_eq!(checked_handle_construct(&mut out, &source, u32::MAX, status), &mut out as *mut _);
                assert_eq!(out.vtable, 0x0898_ccc8);
                assert_eq!(object.status, status);
                if status == 0 {
                    assert_eq!(out.body, source);
                    assert_eq!(out.cached, 0xdead_beef);
                    assert_eq!(body.refcount, 8);
                    refcounted_body_release_slot1(&mut out.body);
                } else {
                    assert!(out.body.is_null());
                    assert_eq!(out.cached, 0);
                }
                assert_eq!(body.refcount, 7);
            }
        }
    }
}
