//! `observable_array_attached_release_cleanup_destruct` — retailOS
//! `FUN_083d0d78` @ **0x083d0d78**.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes fourteen A32 words from `push {r4,lr}` at
//! `0x083d0d78` through the tail branch at `0x083d0dac`: **56 code bytes**.
//! `0x083d0db0` is the derived-vtable literal `0x089a47e8`, and `push
//! {r4-r6,lr}` at `0x083d0db4` begins the next real function. The body has
//! one plain direct `bl`, to `FUN_083d0c90`, and one predicated indirect
//! `blxne` through the attached object's vtable slot `+0x1c`.
//!
//! ## Algorithm
//!
//! Installs its derived vtable, releases the non-null attached object, runs
//! the derived cleanup stage, then tail-chains to `observable_array_destruct`.
//!
//! Deliberate deviations: host builds use explicit seams for the unported
//! cleanup stage and target-width virtual call. Rust uses ordinary branches
//! and a normal base-destructor call rather than the predicated `blx` and tail
//! branch.

const VTABLE_WORD: u32 = 0x089a_47e8;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type Cleanup = unsafe extern "C" fn(*mut u32);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn cleanup(this: *mut u32) {
    let cleanup: Cleanup = unsafe { core::mem::transmute(0x083d_0c90usize) };
    unsafe { cleanup(this) };
}

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cleanup(_this: *mut u32) {
    panic!("install observable-array attached-release cleanup destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array attached-release cleanup destructor host seams before calling this port")
}

/// Host replacements for `FUN_083d0c90` and the attached object's vtable slot
/// `+0x1c`; neither callee has a Rust port.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ATTACHED_RELEASE_CLEANUP_DESTRUCT_OPS: (Cleanup, ReleaseAttachedObject) =
    (missing_cleanup, missing_release_attached_object);

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_attached_release_cleanup_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            cleanup(this);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (cleanup, release) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CLEANUP_DESTRUCT_OPS));
            if !attached.is_null() {
                release(attached);
            }
            cleanup(this);
        }
        crate::cxx::observable_array::observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static CLEANED: AtomicUsize = AtomicUsize::new(0);
    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_cleanup(this: *mut u32) { CLEANED.store(this as usize, Ordering::SeqCst); }
    unsafe extern "C" fn record_release(object: *mut u8) { RELEASED.store(object as usize, Ordering::SeqCst); }

    #[test]
    fn releases_attached_object_before_cleanup_and_base_destruction() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CLEANUP_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CLEANUP_DESTRUCT_OPS).write((record_cleanup, record_release)); }
        let mut object = [0xfeed_face; 6];
        object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        object[3] = 0;
        object[2] = 0;
        CLEANED.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        let result = unsafe { observable_array_attached_release_cleanup_destruct(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(CLEANED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CLEANUP_DESTRUCT_OPS).write(old); }
    }

    #[test]
    fn null_attached_object_skips_virtual_release_but_runs_cleanup() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CLEANUP_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CLEANUP_DESTRUCT_OPS).write((record_cleanup, record_release)); }
        let mut object = [0; 6];
        CLEANED.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        unsafe { observable_array_attached_release_cleanup_destruct(object.as_mut_ptr()); }
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
        assert_eq!(CLEANED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CLEANUP_DESTRUCT_OPS).write(old); }
    }
}
