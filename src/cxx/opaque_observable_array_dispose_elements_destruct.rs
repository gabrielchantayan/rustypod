//! `opaque_observable_array_dispose_elements_destruct` — retailOS
//! `FUN_083d09e4` @ `0x083d09e4`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes fourteen A32 words from `push {r4,lr}` at
//! `0x083d09e4` through the vtable literal at `0x083d0a1c`; the `push` at
//! `0x083d0a20` begins the next independently entered function. The true size
//! is **56 bytes**. The body has one plain direct `bl` to
//! [`opaque_observable_array_dispose_elements`], no predicated direct `bl`, and
//! one predicated `blxne` through the attached object's vtable slot `+0x1c`.
//! Raw whole-image branch decoding finds two inbound plain `bl` sites and no
//! predicated direct `bl` sites.
//!
//! ## Algorithm
//!
//! Re-plants the derived vtable, conditionally invokes the attached object's
//! virtual release, disposes array elements, then tail-chains into
//! [`crate::cxx::observable_array::observable_array_destruct`].
//!
//! Deliberate deviations: host builds replace the target-width virtual call
//! with a seam. Rust models the final tail branch as a direct call and cannot
//! preserve the ARM predicate on the virtual call.

const VTABLE_WORD: u32 = 0x089a_4560;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install opaque observable-array dispose-elements destructor host seam before calling this port")
}

/// Host replacement for the target-width virtual release call.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ELEMENTS_DESTRUCT_RELEASE: ReleaseAttachedObject =
    missing_release_attached_object;

/// Destroys an observable array whose elements require pre-base disposal.
///
/// # Safety
///
/// `this` must point to writable target-layout storage through `+0x14`. A
/// nonzero word at `+0x14` must name an attached object valid for its vtable
/// release slot. Its observable-array prefix must satisfy
/// [`crate::cxx::observable_array::observable_array_destruct`]'s requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_dispose_elements_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        if !attached.is_null() {
            #[cfg(target_os = "none")]
            release_attached_object(attached);
            #[cfg(not(target_os = "none"))]
            core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ELEMENTS_DESTRUCT_RELEASE))(attached);
        }
        crate::cxx::opaque_observable_array_dispose_elements::opaque_observable_array_dispose_elements(this.cast());
        crate::cxx::observable_array::observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(object: *mut u8) {
        RELEASED.store(object as usize, Ordering::SeqCst);
    }

    #[test]
    fn releases_attached_object_then_returns_base_array() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ELEMENTS_DESTRUCT_RELEASE)) };
        unsafe { core::ptr::addr_of_mut!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ELEMENTS_DESTRUCT_RELEASE).write(record_release); }
        let mut object = [0xfeed_face; 6];
        object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        object[4] = 0;
        object[3] = 0;
        object[2] = 0;
        RELEASED.store(0, Ordering::SeqCst);
        let result = unsafe { opaque_observable_array_dispose_elements_destruct(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(object[1], 0);
        assert_eq!(object[2], 0);
        assert_eq!(object[ATTACHED_OBJECT_WORD], 0x1234_5000);
        unsafe { core::ptr::addr_of_mut!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ELEMENTS_DESTRUCT_RELEASE).write(old); }
    }

    #[test]
    fn null_attached_object_skips_virtual_release() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ELEMENTS_DESTRUCT_RELEASE)) };
        unsafe { core::ptr::addr_of_mut!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ELEMENTS_DESTRUCT_RELEASE).write(record_release); }
        let mut object = [0; 6];
        RELEASED.store(0, Ordering::SeqCst);
        unsafe { opaque_observable_array_dispose_elements_destruct(object.as_mut_ptr()); }
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
        assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        unsafe { core::ptr::addr_of_mut!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_ELEMENTS_DESTRUCT_RELEASE).write(old); }
    }
}
