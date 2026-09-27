//! Observable-array derived destructor at retailOS `FUN_083d1160`.
//!
//! Load address: **0x083d1160**. Raw `osos.dec` establishes the true
//! 56-byte extent: thirteen A32 words from `0x083d1160` through the tail
//! `b` at `0x083d1194`, then vtable literal `0x089a4b48` at `0x083d1198`;
//! `push {r4,lr}` at `0x083d119c` opens the next real function. Whole-image
//! ARM branch decoding finds two inbound plain `bl` sites (`0x08130530` and
//! `0x0826b5f8`) and no predicated inbound `bl` sites. The body has one plain direct `bl` to the unported
//! object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Plants its derived vtable, conditionally dispatches the object stored at
//! `this+0x14` through virtual slot `+0x1c`, calls the unported direct
//! predecessor at `0x083d10b8`, then tail-chains to `observable_array_destruct`.
//! Deliberate deviations: host builds use seams for target-width virtual and
//! unported direct calls; Rust expresses the predicated `blxne` and tail branch
//! as ordinary control flow.

const VTABLE_WORD: u32 = 0x089a_4b48;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;
#[cfg(target_os = "none")]
const PRE_DESTRUCT_ADDRESS: usize = 0x083d_10b8;

type PreDestruct = unsafe extern "C" fn(*mut u32);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_pre_destruct(this: *mut u32) {
    unsafe { core::mem::transmute::<usize, PreDestruct>(PRE_DESTRUCT_ADDRESS)(this) };
}

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pre_destruct(_this: *mut u32) {
    panic!("install observable-array attached-release destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array attached-release destructor host seams before calling this port")
}

/// Host replacements for the target-width virtual call and unported direct
/// call. Target builds dispatch to their verified retailOS addresses.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ATTACHED_RELEASE_DESTRUCT_083D1160_OPS: (PreDestruct, ReleaseAttachedObject) =
    (missing_pre_destruct, missing_release_attached_object);

/// Destroys an observable-array-derived object with an attached virtual-release object.
///
/// # Safety
///
/// `this` must point to writable target-layout storage through `+0x14`. A
/// nonzero word at `+0x14` must name an attached object valid for its vtable
/// release slot, and the direct pre-destructor's input requirements apply.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_attached_release_destruct_083d1160(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            firmware_pre_destruct(this);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (pre_destruct, release) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_DESTRUCT_083D1160_OPS));
            if !attached.is_null() {
                release(attached);
            }
            pre_destruct(this);
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
    static PRE_DESTRUCT_THIS: AtomicUsize = AtomicUsize::new(0);
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static EXPECT_RELEASE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_pre_destruct(this: *mut u32) {
        if EXPECT_RELEASE.load(Ordering::SeqCst) != 0 {
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        }
        PRE_DESTRUCT_THIS.store(this as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn record_release(object: *mut u8) { RELEASED.store(object as usize, Ordering::SeqCst); }

    #[test]
    fn releases_attached_object_before_pre_destructor_and_base() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_DESTRUCT_083D1160_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_DESTRUCT_083D1160_OPS).write((record_pre_destruct, record_release)); }
        let mut object = [0xfeed_face; 6];
        object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        object[3] = 0;
        object[2] = 0;
        PRE_DESTRUCT_THIS.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        EXPECT_RELEASE.store(1, Ordering::SeqCst);
        let result = unsafe { observable_array_attached_release_destruct_083d1160(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(object[1], 0);
        assert_eq!(object[2], 0);
        assert_eq!(object[ATTACHED_OBJECT_WORD], 0x1234_5000);
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(PRE_DESTRUCT_THIS.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_DESTRUCT_083D1160_OPS).write(old); }
    }

    #[test]
    fn null_attached_object_skips_virtual_release() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_DESTRUCT_083D1160_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_DESTRUCT_083D1160_OPS).write((record_pre_destruct, record_release)); }
        let mut object = [0; 6];
        PRE_DESTRUCT_THIS.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        EXPECT_RELEASE.store(0, Ordering::SeqCst);
        unsafe { observable_array_attached_release_destruct_083d1160(object.as_mut_ptr()); }
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
        assert_eq!(PRE_DESTRUCT_THIS.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_DESTRUCT_083D1160_OPS).write(old); }
    }
}
