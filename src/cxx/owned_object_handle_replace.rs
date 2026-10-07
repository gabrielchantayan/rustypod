//! Owned-object handle replacement, `FUN_081573c8` @ **0x081573c8**.
//!
//! True size: 48 bytes, twelve A32 words ending at 0x081573f8, where
//! the next independent function starts with push {r2,r3,r4,lr}.
//! Verified outgoing calls: zero plain BL, zero predicated BL, one BLXNE
//! at 0x081573ec through the old object's vtable slot +0x04. Full-image
//! aligned decoding finds two incoming plain BLs at 0x081245d4 and
//! 0x0815fb94, and zero predicated BLs.
//!
//! Compare the handle's object with the replacement. Equal pointers cause
//! no access to the object or store. Otherwise dispatch the non-NULL old
//! object through vtable word 1, discard its result, then store replacement.
//! The callback observes the old pointer still in the handle; its changes
//! to the handle are overwritten. The concrete virtual method is unknown.
//!
//! Deliberate deviations: host pointers and vtable entries are native-width,
//! as in the neighboring guarded dispatcher; target words remain four bytes.
//! The function has no meaningful return value (r0 is path/callback-dependent).

/// Replaces the handle's object after dispatching the previous object's slot +0x04.
///
/// # Safety
/// `slot` must be aligned, readable and writable. A non-NULL, different old
/// object must begin with a readable vtable pointer whose second entry is a
/// callable `unsafe extern "C" fn(*mut u8)`. The callback must leave `slot`
/// writable. The replacement is stored without being dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_object_handle_replace(slot: *mut *mut u8, replacement: *mut u8) {
    let old = unsafe { slot.read() };
    if old == replacement {
        return;
    }
    if !old.is_null() {
        let vtable = unsafe { old.cast::<*const usize>().read() };
        let method: unsafe extern "C" fn(*mut u8) = unsafe {
            core::mem::transmute(vtable.add(1).read())
        };
        unsafe { method(old) };
    }
    unsafe { slot.write(replacement) };
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
        observed_old: bool,
    }

    unsafe extern "C" fn release(object: *mut u8) {
        let object = object.cast::<Object>();
        unsafe {
            (*object).calls += 1;
            (*object).observed_old = (*object).slot.read() == object.cast();
            (*object).slot.write(ptr::null_mut());
        }
    }

    #[test]
    fn equal_pointers_never_dereference_object() {
        for object in [ptr::null_mut(), ptr::without_provenance_mut::<u8>(1)] {
            let mut slot = object;
            unsafe { owned_object_handle_replace(&mut slot, object) };
            assert_eq!(slot, object);
        }
    }

    #[test]
    fn empty_handle_accepts_opaque_replacement_and_preserves_neighbors() {
        let replacement = ptr::without_provenance_mut::<u8>(0x1234);
        let mut words = [replacement, ptr::null_mut(), replacement];
        unsafe { owned_object_handle_replace(words.as_mut_ptr().add(1), replacement) };
        assert_eq!(words, [replacement; 3]);
    }

    #[test]
    fn replacement_occurs_after_callback_even_when_callback_changes_slot() {
        for replacement in [ptr::null_mut(), ptr::without_provenance_mut::<u8>(0x1234)] {
            let vtable = [0usize, release as *const () as usize];
            let mut slot = ptr::null_mut();
            let mut object = Object { vtable: vtable.as_ptr(), slot: &mut slot, calls: 0, observed_old: false };
            slot = (&mut object as *mut Object).cast();
            unsafe { owned_object_handle_replace(&mut slot, replacement) };
            assert_eq!(object.calls, 1);
            assert!(object.observed_old);
            assert_eq!(slot, replacement);
        }
    }
}
