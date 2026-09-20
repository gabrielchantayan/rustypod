//! **0x083d0e84** (60 bytes: 56 bytes of code plus the vtable literal).
//!
//! Raw `osos.dec` decodes from `0x083d0e84` through the tail branch at
//! `0x083d0eb8`; `0x083d0ebc` is vtable literal `0x089a48c0`, and the next
//! real function begins at `0x083d0ec0`. There are two inbound plain `bl`
//! sites (`0x0812b3ac`, `0x0812b608`) and no predicated inbound `bl` sites.
//! The body has one plain `bl` to `0x083d0db4` and one predicated indirect
//! `blxne` through the attached object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Re-plants its derived vtable, conditionally invokes the attached object's
//! virtual release at `this+0x14`, destroys tracked items through
//! `0x083d0db4`, then tail-chains into `observable_array_destruct`.
//!
//! Deliberate deviations: host builds use explicit seams for the two unported
//! / dynamic calls. Target builds invoke their recovered absolute addresses;
//! Rust does not preserve the predicated `blx` or the tail branch.

const VTABLE_WORD: u32 = 0x089a_48c0;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type DestroyTrackedItems = unsafe extern "C" fn(*mut u32);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn destroy_tracked_items(this: *mut u32) {
    let destroy: DestroyTrackedItems = unsafe { core::mem::transmute(0x083d_0db4usize) };
    unsafe { destroy(this) };
}

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_tracked_items(_this: *mut u32) {
    panic!("install observable-array tracked destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array tracked destructor host seams before calling this port")
}

/// Host replacements for `0x083d0db4` and the attached object's vtable slot
/// `+0x1c`; neither callee has a Rust port.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_TRACKED_DESTRUCT_OPS: (DestroyTrackedItems, ReleaseAttachedObject) =
    (missing_destroy_tracked_items, missing_release_attached_object);

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_tracked_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        if !attached.is_null() {
            release_attached_object(attached);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (destroy, release) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_TRACKED_DESTRUCT_OPS));
            if !attached.is_null() {
                release(attached);
            }
            destroy(this);
        }
        #[cfg(target_os = "none")]
        destroy_tracked_items(this);
        crate::cxx::observable_array::observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static DESTROYED: AtomicUsize = AtomicUsize::new(0);
    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_destroy(this: *mut u32) { DESTROYED.store(this as usize, Ordering::SeqCst); }
    unsafe extern "C" fn record_release(object: *mut u8) { RELEASED.store(object as usize, Ordering::SeqCst); }

    #[test]
    fn releases_attached_object_before_destroying_items_and_base() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_TRACKED_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_TRACKED_DESTRUCT_OPS).write((record_destroy, record_release)); }
        let mut object = [0xfeed_face; 6];
        object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        object[3] = 0;
        object[2] = 0;
        DESTROYED.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        let result = unsafe { observable_array_tracked_destruct(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(object[1], 0);
        assert_eq!(object[2], 0);
        assert_eq!(object[ATTACHED_OBJECT_WORD], 0x1234_5000);
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(DESTROYED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_TRACKED_DESTRUCT_OPS).write(old); }
    }

    #[test]
    fn null_attached_object_skips_virtual_release() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_TRACKED_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_TRACKED_DESTRUCT_OPS).write((record_destroy, record_release)); }
        let mut object = [0; 6];
        DESTROYED.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        unsafe { observable_array_tracked_destruct(object.as_mut_ptr()); }
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
        assert_eq!(DESTROYED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_TRACKED_DESTRUCT_OPS).write(old); }
    }
}
