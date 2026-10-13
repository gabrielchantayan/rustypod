//! Owned error-object assignment, `FUN_083e74f0` @ **0x083e74f0**.
//!
//! True extent: 48 bytes, ending with pop at 0x083e751c; the next real
//! function starts at 0x083e7520. Full-image aligned A32 decoding verifies
//! one inbound plain BL at 0x081d1774 and zero predicated BLs. The body has
//! zero plain or predicated BLs and one BLXNE through vtable slot +0x04.
//!
//! Equal pointers are a no-op. Otherwise invoke the non-NULL old object's
//! unresolved virtual slot +0x04, then store the replacement. The callback
//! sees the old slot value; any callback change to it is overwritten.
//! Deliberate deviations: native-width host pointers preserve word indices;
//! the path-dependent stock r0 is not a meaningful return value. The raw
//! body is byte-identical to owned_object_handle_replace @ 0x081573c8;
//! LLVM may intentionally fold their exported symbols into one body.

/// Assigns an owned error object without dereferencing the replacement.
///
/// # Safety
/// `slot` must be readable, aligned and writable, including after the callback.
/// A different non-NULL old object must contain a readable vtable pointer
/// whose second entry is callable as `unsafe extern "C" fn(*mut u8)`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn error_object_assign(slot: *mut *mut u8, replacement: *mut u8) {
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
    fn identity_skips_invalid_object_and_null() {
        for object in [ptr::null_mut(), ptr::without_provenance_mut::<u8>(1)] {
            let mut slot = object;
            unsafe { error_object_assign(&mut slot, object) };
            assert_eq!(slot, object);
        }
    }

    #[test]
    fn empty_slot_stores_opaque_pointer_without_touching_neighbors() {
        let replacement = ptr::without_provenance_mut::<u8>(0x1234);
        let mut slots = [replacement, ptr::null_mut(), replacement];
        unsafe { error_object_assign(slots.as_mut_ptr().add(1), replacement) };
        assert_eq!(slots, [replacement; 3]);
    }

    #[test]
    fn release_observes_old_slot_and_its_write_is_overwritten() {
        for replacement in [ptr::null_mut(), ptr::without_provenance_mut::<u8>(0x1234)] {
            let vtable = [0usize, release as *const () as usize];
            let mut slot = ptr::null_mut();
            let mut object = Object { vtable: vtable.as_ptr(), slot: &mut slot, calls: 0, observed_old: false };
            slot = (&mut object as *mut Object).cast();
            unsafe { error_object_assign(&mut slot, replacement) };
            assert_eq!(object.calls, 1);
            assert!(object.observed_old);
            assert_eq!(slot, replacement);
        }
    }
}
