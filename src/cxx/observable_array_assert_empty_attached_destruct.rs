//! `observable_array_assert_empty_attached_destruct` — retailOS `FUN_083d15a0`
//! at `0x083d15a0`.
//!
//! Raw `osos.dec` establishes 56 bytes: thirteen A32 words from `0x083d15a0`
//! through the tail branch at `0x083d15d4`, followed by vtable literal
//! `0x089a4ea8` at `0x083d15d8`; `0x083d15dc` begins the next real function.
//! Whole-image decoding finds two inbound plain `bl` sites (`0x08101bd4` and
//! `0x0826b658`) and no predicated inbound `bl` sites. The body has one plain
//! direct `bl` to the unported `FUN_083d14a0` and one predicated indirect
//! `blxne` through the attached object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Re-plants its derived vtable, conditionally invokes the attached object's
//! virtual release at `this+0x14`, runs the unported pre-destruction check at
//! `0x083d14a0`, then tail-chains into `observable_array_destruct`.
//!
//! Deliberate deviations: host builds use explicit seams for the unresolved
//! direct and virtual calls. Rust does not preserve the predicated `blx` or
//! tail branch; the direct helper is called at its verified load address on
//! target builds.

const VTABLE_WORD: u32 = 0x089a_4ea8;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);
type AssertEmpty = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn assert_empty_target() -> AssertEmpty {
    unsafe { core::mem::transmute(0x083d_14a0usize) }
}

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array attached destructor host release seam before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_assert_empty(_this: *mut u32) {
    panic!("install observable-array attached destructor host assertion seam before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_RELEASE: ReleaseAttachedObject = missing_release_attached_object;
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_ASSERT: AssertEmpty = missing_assert_empty;

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_assert_empty_attached_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            assert_empty_target()(this);
        }
        #[cfg(not(target_os = "none"))]
        {
            let release = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_RELEASE));
            if !attached.is_null() {
                release(attached);
            }
            let assert_empty = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_ASSERT));
            assert_empty(this);
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

    unsafe extern "C" fn record_assert_empty(object: *mut u32) {
        assert_eq!(object.read_volatile(), VTABLE_WORD);
        assert_eq!(EVENT.fetch_add(1, Ordering::SeqCst), 1);
    }

    #[test]
    fn releases_attachment_before_checking_and_base_destruction() {
        let _lock = LOCK.lock();
        unsafe {
            let old_release = OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_RELEASE;
            let old_assert = OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_ASSERT;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_RELEASE = record_release;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_ASSERT = record_assert_empty;
            let mut object = [0; 6];
            object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
            RELEASED.store(0, Ordering::SeqCst);
            EVENT.store(0, Ordering::SeqCst);
            let result = observable_array_assert_empty_attached_destruct(object.as_mut_ptr());
            assert_eq!(result, object.as_mut_ptr());
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
            assert_eq!(EVENT.load(Ordering::SeqCst), 2);
            assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(object[1], 0);
            assert_eq!(object[2], 0);
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_ASSERT = old_assert;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_RELEASE = old_release;
        }
    }

    #[test]
    fn null_attachment_skips_release_but_runs_check() {
        let _lock = LOCK.lock();
        unsafe {
            let old_release = OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_RELEASE;
            let old_assert = OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_ASSERT;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_RELEASE = record_release;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_ASSERT = record_assert_empty;
            let mut object = [0; 6];
            RELEASED.store(0, Ordering::SeqCst);
            EVENT.store(1, Ordering::SeqCst);
            observable_array_assert_empty_attached_destruct(object.as_mut_ptr());
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
            assert_eq!(EVENT.load(Ordering::SeqCst), 2);
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_ASSERT = old_assert;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_RELEASE = old_release;
        }
    }
}
