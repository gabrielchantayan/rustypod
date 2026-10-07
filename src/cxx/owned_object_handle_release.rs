//! Owned-object handle release, `FUN_08161b04` @ `0x08161b04`.
//!
//! True extent: 36 bytes [0x08161b04,0x08161b28), ending in POP {r4,pc};
//! the next real function begins with PUSH {r4,lr}. Independent raw A32
//! decoding finds two inbound plain BLs (0x082369d4, 0x08236b3c), zero
//! predicated inbound BLs, zero outgoing plain/predicated BLs, and one
//! outgoing BLXNE at 0x08161b1c through virtual slot +0x04.
//!
//! Load the handle's object, dispatch vtable word 1 if non-NULL, discard
//! the method result, and return the original handle. Do not clear the slot
//! or free the handle. The constructor at 0x08161abc stores an allocated
//! object's pointer here; the caller at 0x082368b8 releases it on failure
//! before separately deleting the handle. The concrete method is unknown.
//!
//! Deliberate deviations: native-width host pointers and vtable words,
//! following owned_object_handle_replace; target words remain four bytes.
//! No target behavioral deviations or new retail-call seams.

/// Dispatches a non-NULL owned object through virtual slot 1, returning `slot`.
///
/// # Safety
/// `slot` must be aligned and readable. Its non-NULL object must begin with
/// a readable vtable pointer whose second word is a callable
/// `unsafe extern "C" fn(*mut u8)`. The callback may change the slot or
/// destroy the object; neither is accessed again after dispatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_object_handle_release(slot: *mut *mut u8) -> *mut *mut u8 {
    let object = unsafe { slot.read() };
    if !object.is_null() {
        let vtable = unsafe { object.cast::<*const usize>().read() };
        let method: unsafe extern "C" fn(*mut u8) = unsafe {
            core::mem::transmute(vtable.add(1).read())
        };
        unsafe { method(object) };
    }
    slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        slot: *mut *mut u8,
        calls: u32,
        clear_slot: bool,
        observed_object: bool,
    }

    unsafe extern "C" fn release(object: *mut u8) {
        let state = unsafe { &mut *object.cast::<Object>() };
        state.calls += 1;
        state.observed_object = unsafe { state.slot.read() } == object;
        if state.clear_slot {
            unsafe { state.slot.write(ptr::null_mut()) };
        }
    }

    #[test]
    fn null_object_returns_handle_without_touching_neighbor_slots() {
        let sentinel = ptr::without_provenance_mut::<u8>(1);
        let mut slots = [sentinel, ptr::null_mut(), sentinel];
        let slot = unsafe { slots.as_mut_ptr().add(1) };
        assert_eq!(unsafe { owned_object_handle_release(slot) }, slot);
        assert_eq!(slots, [sentinel, ptr::null_mut(), sentinel]);
    }

    #[test]
    fn dispatch_preserves_slot_unless_callback_changes_it() {
        for clear_slot in [false, true] {
            let vtable = [0usize, release as *const () as usize];
            let mut slot = ptr::null_mut();
            let mut object = Object {
                vtable: vtable.as_ptr(), slot: &mut slot, calls: 0,
                clear_slot, observed_object: false,
            };
            let object_ptr = (&mut object as *mut Object).cast::<u8>();
            slot = object_ptr;
            let handle = &mut slot as *mut *mut u8;
            assert_eq!(unsafe { owned_object_handle_release(handle) }, handle);
            assert_eq!(object.calls, 1);
            assert!(object.observed_object);
            assert_eq!(slot, if clear_slot { ptr::null_mut() } else { object_ptr });
            if !clear_slot {
                assert_eq!(unsafe { owned_object_handle_release(handle) }, handle);
                assert_eq!(object.calls, 2);
            }
        }
    }
}
