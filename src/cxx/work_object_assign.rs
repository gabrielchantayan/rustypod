//! Owned work-object assignment, `FUN_083e74c0` @ **0x083e74c0**.
//!
//! True extent: 48 bytes through pop at 0x083e74ec; the next independently
//! entered function starts at 0x083e74f0. Whole-image aligned A32 decoding
//! verifies one incoming plain BL at 0x081e1690 and zero predicated BLs.
//! The body has zero plain or predicated BLs and one BLXNE at 0x083e74e4.
//!
//! Equal pointers are a no-op. Otherwise call the non-NULL old object's
//! unresolved virtual slot +0x04 before storing replacement. Callback writes
//! to the slot are overwritten. No concrete virtual callee identity is assumed.
//! Deliberate deviations: native-width host pointers preserve word indices;
//! return void because the sole caller does not consume the path-dependent
//! stock r0. Raw bytes match error_object_assign at 0x083e74f0; LLVM may
//! intentionally fold identical exported bodies.

/// Replaces an owned object returned by the work-object factory.
///
/// # Safety
/// `slot` must be aligned, readable and writable, including after the callback.
/// A different non-NULL old object must start with a readable vtable pointer
/// whose second entry is callable as `unsafe extern "C" fn(*mut u8)`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn work_object_assign(slot: *mut *mut u8, replacement: *mut u8) {
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
    fn identity_skips_null_and_unreadable_object() {
        for object in [ptr::null_mut(), ptr::without_provenance_mut::<u8>(1)] {
            let mut slot = object;
            unsafe { work_object_assign(&mut slot, object) };
            assert_eq!(slot, object);
        }
    }

    #[test]
    fn empty_adoption_does_not_read_replacement_or_write_neighbors() {
        let replacement = ptr::without_provenance_mut::<u8>(0x1234);
        let mut slots = [replacement, ptr::null_mut(), replacement];
        unsafe { work_object_assign(slots.as_mut_ptr().add(1), replacement) };
        assert_eq!(slots, [replacement; 3]);
    }

    #[test]
    fn replacement_and_clear_release_before_overwriting_callback_write() {
        for replacement in [ptr::null_mut(), ptr::without_provenance_mut::<u8>(0x1234)] {
            let vtable = [0usize, release as *const () as usize];
            let mut slot = ptr::null_mut();
            let mut object = Object { vtable: vtable.as_ptr(), slot: &mut slot, calls: 0, observed_old: false };
            slot = (&mut object as *mut Object).cast();
            unsafe { work_object_assign(&mut slot, replacement) };
            assert_eq!(object.calls, 1);
            assert!(object.observed_old);
            assert_eq!(slot, replacement);
        }
    }
}
