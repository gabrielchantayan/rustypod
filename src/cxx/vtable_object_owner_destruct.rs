//! Vtable-bearing object-owner destructor @ 0x08161a48 (FUN_08161a48).
//!
//! True extent: 48 bytes [0x08161a48,0x08161a78): 44 instruction bytes
//! followed by the vtable literal 0x08987da0. The next function loads a
//! handle and tail-branches. Whole-image A32 decoding finds two inbound
//! plain BLs (0x0814932c, 0x0827de98), no predicated inbound BLs, no
//! outgoing plain/predicated BLs, and one BLXNE at 0x08161a68.
//!
//! Restore the owner's vtable, then dispatch its non-NULL owned object
//! through virtual slot 1 with the object as receiver. Ignore the method
//! result and return the original owner. Neither clear the object slot nor
//! free the owner. Both callers subtract their embedded-member offset from
//! the returned owner (8 and 16 respectively). The virtual method's concrete
//! identity is unknown; no retail-call seam is introduced.
//!
//! Deliberate deviation: host pointer/vtable fields use native-width words,
//! matching owned_object_handle_release; target fields remain four bytes.
//! No target algorithm deviation.

/// Prefix touched by the destructor; further owner fields are untouched.
#[repr(C)]
pub struct VtableObjectOwner {
    pub vtable: usize,
    pub object: *mut u8,
}

/// # Safety
/// `owner` must be aligned, readable and writable. Its non-NULL object must
/// begin with a readable vtable pointer whose second word is a callable
/// `unsafe extern "C" fn(*mut u8)`. The callback may mutate either object;
/// neither is accessed again after dispatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_object_owner_destruct(
    owner: *mut VtableObjectOwner,
) -> *mut VtableObjectOwner {
    unsafe { core::ptr::addr_of_mut!((*owner).vtable).write(0x0898_7da0) };
    let object = unsafe { core::ptr::addr_of!((*owner).object).read() };
    if !object.is_null() {
        let vtable = unsafe { object.cast::<*const usize>().read() };
        let method: unsafe extern "C" fn(*mut u8) = unsafe {
            core::mem::transmute(vtable.add(1).read())
        };
        unsafe { method(object) };
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        owner: *mut VtableObjectOwner,
        calls: usize,
        mutate: bool,
    }

    unsafe extern "C" fn release(receiver: *mut u8) {
        let object = unsafe { &mut *receiver.cast::<Object>() };
        assert_eq!(unsafe { (*object.owner).vtable }, 0x0898_7da0);
        assert_eq!(unsafe { (*object.owner).object }, receiver);
        object.calls += 1;
        if object.mutate {
            unsafe {
                (*object.owner).object = ptr::null_mut();
                (*object.owner).vtable = 17;
            }
        }
    }

    #[test]
    fn null_object_restores_vtable_and_preserves_surrounding_words() {
        #[repr(C)]
        struct Fixture { before: usize, owner: VtableObjectOwner, after: usize }
        let mut fixture = Fixture {
            before: 31, owner: VtableObjectOwner { vtable: 9, object: ptr::null_mut() }, after: 47,
        };
        let owner = &mut fixture.owner as *mut VtableObjectOwner;
        assert_eq!(unsafe { vtable_object_owner_destruct(owner) }, owner);
        assert_eq!(fixture.owner.vtable, 0x0898_7da0);
        assert!(fixture.owner.object.is_null());
        assert_eq!((fixture.before, fixture.after), (31, 47));
    }

    #[test]
    fn dispatch_observes_restored_vtable_and_retains_callback_mutation() {
        for mutate in [false, true] {
            let vtable = [0usize, release as *const () as usize];
            let mut owner = VtableObjectOwner { vtable: 9, object: ptr::null_mut() };
            let owner_ptr = &mut owner as *mut VtableObjectOwner;
            let mut object = Object { vtable: vtable.as_ptr(), owner: owner_ptr, calls: 0, mutate };
            let receiver = (&mut object as *mut Object).cast::<u8>();
            owner.object = receiver;
            assert_eq!(unsafe { vtable_object_owner_destruct(owner_ptr) }, owner_ptr);
            assert_eq!(object.calls, 1);
            assert_eq!(owner.object, if mutate { ptr::null_mut() } else { receiver });
            assert_eq!(owner.vtable, if mutate { 17 } else { 0x0898_7da0 });
            assert_eq!(unsafe { vtable_object_owner_destruct(owner_ptr) }, owner_ptr);
            assert_eq!(object.calls, if mutate { 1 } else { 2 });
            assert_eq!(owner.vtable, 0x0898_7da0);
        }
    }
}
