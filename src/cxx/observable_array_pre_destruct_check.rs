//! **0x083d1918** (60 bytes: 56 bytes of code plus the vtable literal).
//!
//! Raw `osos.dec` decodes fourteen A32 instructions from `0x083d1918` through
//! the tail branch at `0x083d194c`; `0x083d1950` is vtable literal
//! `0x089a5208`, and the next real function starts at `0x083d1954`. There are
//! two inbound plain `bl` sites (`0x0810e414` and `0x081f6714`) and no
//! predicated inbound `bl` sites. The body has one plain direct `bl` to
//! `0x083d1870` and one predicated indirect `blxne` through the attached
//! object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Re-plants its derived vtable, conditionally invokes the attached object's
//! virtual release at `this+0x14`, runs the unresolved pre-destruction check
//! at `0x083d1870`, then tail-chains into `observable_array_destruct`.
//!
//! Deliberate deviations: host builds use explicit seams for the unresolved
//! direct and dynamic calls. Target builds invoke their recovered absolute
//! addresses; Rust does not preserve the predicated `blx` or tail branch.

const VTABLE_WORD: u32 = 0x089a_5208;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type PreDestructCheck = unsafe extern "C" fn(*mut u32);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn pre_destruct_check(this: *mut u32) {
    let check: PreDestructCheck = unsafe { core::mem::transmute(0x083d_1870usize) };
    unsafe { check(this) };
}

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pre_destruct_check(_this: *mut u32) {
    panic!("install observable-array pre-destruct-check host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array pre-destruct-check host seams before calling this port")
}

/// Host replacements for `0x083d1870` and the attached object's vtable slot
/// `+0x1c`; neither callee has a Rust port.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_OPS: (PreDestructCheck, ReleaseAttachedObject) =
    (missing_pre_destruct_check, missing_release_attached_object);

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_pre_destruct_check(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        if !attached.is_null() {
            release_attached_object(attached);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (check, release) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_OPS));
            if !attached.is_null() {
                release(attached);
            }
            check(this);
        }
        #[cfg(target_os = "none")]
        pre_destruct_check(this);
        crate::cxx::observable_array::observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static CHECKED: AtomicUsize = AtomicUsize::new(0);
    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_check(this: *mut u32) { CHECKED.store(this as usize, Ordering::SeqCst); }
    unsafe extern "C" fn record_release(object: *mut u8) { RELEASED.store(object as usize, Ordering::SeqCst); }

    #[test]
    fn releases_attached_object_before_checking_and_destroying_base() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_OPS).write((record_check, record_release)); }
        let mut object = [0xfeed_face; 6];
        object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        object[3] = 0;
        object[2] = 0;
        CHECKED.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        let result = unsafe { observable_array_pre_destruct_check(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(object[1], 0);
        assert_eq!(object[2], 0);
        assert_eq!(object[ATTACHED_OBJECT_WORD], 0x1234_5000);
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(CHECKED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_OPS).write(old); }
    }

    #[test]
    fn null_attached_object_skips_virtual_release() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_OPS).write((record_check, record_release)); }
        let mut object = [0; 6];
        CHECKED.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        unsafe { observable_array_pre_destruct_check(object.as_mut_ptr()); }
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
        assert_eq!(CHECKED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_OPS).write(old); }
    }
}
