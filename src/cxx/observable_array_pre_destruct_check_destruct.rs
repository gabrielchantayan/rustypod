//! `observable_array_pre_destruct_check_destruct` — retailOS `FUN_083d052c`
//! at `0x083d052c`.
//!
//! Raw `osos.dec` establishes 56 bytes: fourteen A32 words from `0x083d052c`
//! through the tail branch at `0x083d0560`, followed by vtable literal
//! `0x089a4128` at `0x083d0564`; `0x083d0568` begins the next real function.
//! Whole-image decoding finds two inbound plain `bl` sites (`0x0826b4d8` and
//! `0x08284a90`) and no predicated inbound `bl` sites. The body has one plain
//! direct `bl` to the unported `FUN_083d046c` and one predicated indirect
//! `blxne` through the attached object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Re-plants its derived vtable, conditionally invokes the attached object's
//! virtual release at `this+0x14`, runs the pre-destruction check at
//! `0x083d046c`, then tail-chains into `observable_array_destruct`.
//!
//! Deliberate deviations: host builds use explicit seams for the unresolved
//! direct and virtual calls. Rust does not preserve the predicated `blx` or
//! tail branch; the direct helper is called at its verified load address on
//! target builds.

const VTABLE_WORD: u32 = 0x089a_4128;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);
type PreDestructCheck = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pre_destruct_check_target() -> PreDestructCheck {
    unsafe { core::mem::transmute(0x083d_046cusize) }
}

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array pre-destruct destructor host release seam before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pre_destruct_check(_this: *mut u32) {
    panic!("install observable-array pre-destruct destructor host check seam before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_RELEASE: ReleaseAttachedObject = missing_release_attached_object;
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_CHECK: PreDestructCheck = missing_pre_destruct_check;

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_pre_destruct_check_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            pre_destruct_check_target()(this);
        }
        #[cfg(not(target_os = "none"))]
        {
            let release = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_RELEASE));
            if !attached.is_null() {
                release(attached);
            }
            let check = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_CHECK));
            check(this);
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
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static EVENT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(object: *mut u8) {
        RELEASED.store(object as usize, Ordering::SeqCst);
        assert_eq!(EVENT.fetch_add(1, Ordering::SeqCst), 0);
    }

    unsafe extern "C" fn record_check(object: *mut u32) {
        assert_eq!(object.read_volatile(), VTABLE_WORD);
        assert_eq!(EVENT.fetch_add(1, Ordering::SeqCst), 1);
    }

    #[test]
    fn releases_attachment_before_check_and_base_destruction() {
        let _lock = LOCK.lock();
        unsafe {
            let old_release = OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_RELEASE;
            let old_check = OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_CHECK;
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_RELEASE = record_release;
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_CHECK = record_check;
            let mut object = [0; 6];
            object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
            RELEASED.store(0, Ordering::SeqCst);
            EVENT.store(0, Ordering::SeqCst);
            let result = observable_array_pre_destruct_check_destruct(object.as_mut_ptr());
            assert_eq!(result, object.as_mut_ptr());
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
            assert_eq!(EVENT.load(Ordering::SeqCst), 2);
            assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(object[1], 0);
            assert_eq!(object[2], 0);
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_CHECK = old_check;
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_RELEASE = old_release;
        }
    }

    #[test]
    fn null_attachment_skips_release_but_runs_check() {
        let _lock = LOCK.lock();
        unsafe {
            let old_release = OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_RELEASE;
            let old_check = OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_CHECK;
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_RELEASE = record_release;
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_CHECK = record_check;
            let mut object = [0; 6];
            RELEASED.store(0, Ordering::SeqCst);
            EVENT.store(1, Ordering::SeqCst);
            observable_array_pre_destruct_check_destruct(object.as_mut_ptr());
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
            assert_eq!(EVENT.load(Ordering::SeqCst), 2);
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_CHECK = old_check;
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CHECK_DESTRUCT_RELEASE = old_release;
        }
    }
}
