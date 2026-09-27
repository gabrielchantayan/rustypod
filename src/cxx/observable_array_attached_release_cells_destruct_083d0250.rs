//! `observable_array_attached_release_cells_destruct_083d0250` — retailOS
//! `FUN_083d0250` @ **0x083d0250**.
//!
//! Raw `osos.dec` establishes the true 56-byte extent: thirteen A32 instruction
//! words from `0x083d0250` through the tail `b` at `0x083d0284`, followed by
//! vtable literal `0x089a3ea0` at `0x083d0288`; `push {r4,r5,r6,lr}` at
//! `0x083d028c` begins the next real function. Whole-image A32 branch decoding
//! finds two inbound plain `bl` sites and no predicated inbound `bl` sites. The
//! body has one plain direct `bl` to `FUN_083d019c` and one predicated indirect
//! `blxne` through the attached object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Plant the derived vtable, conditionally release the attached object at
//! `+0x14` through vtable slot `+0x1c`, run the predecessor's enabled-cell
//! release, then tail-chain into `observable_array_destruct`. Deliberate
//! deviations: host builds use seams for target-width virtual and direct calls;
//! target Rust calls the ported enabled-cell release directly. Rust expresses
//! the predicated `blxne` and tail branch as ordinary control flow while
//! preserving their effects and ordering.

const VTABLE_WORD: u32 = 0x089a_3ea0;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;
type ReleaseEnabledCells = unsafe extern "C" fn(*mut u32);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_enabled_cells(_this: *mut u32) {
    panic!("install observable-array attached-release cells destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array attached-release cells destructor host seams before calling this port")
}

/// Host replacements for the target-width virtual call and direct ported call.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ATTACHED_RELEASE_CELLS_DESTRUCT_083D0250_OPS: (ReleaseEnabledCells, ReleaseAttachedObject) =
    (missing_release_enabled_cells, missing_release_attached_object);

/// Destroys an observable-array-derived object with attached-object release
/// and enabled-cell disposal.
///
/// # Safety
///
/// `this` must point to writable target-layout storage through `+0x14`. A
/// nonzero word at `+0x14` must name an attached object valid for its vtable
/// release slot, and the direct predecessor's input requirements apply.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_attached_release_cells_destruct_083d0250(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            crate::cxx::observable_array_release_enabled_cells::observable_array_release_enabled_cells(this.cast());
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release_enabled_cells, release) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CELLS_DESTRUCT_083D0250_OPS));
            if !attached.is_null() {
                release(attached);
            }
            release_enabled_cells(this);
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
    static CELLS_THIS: AtomicUsize = AtomicUsize::new(0);
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static EXPECT_RELEASE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release_enabled_cells(this: *mut u32) {
        if EXPECT_RELEASE.load(Ordering::SeqCst) != 0 {
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        }
        CELLS_THIS.store(this as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_release_attached_object(object: *mut u8) {
        RELEASED.store(object as usize, Ordering::SeqCst);
    }

    #[test]
    fn releases_attached_object_before_enabled_cells_and_base_teardown() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CELLS_DESTRUCT_083D0250_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CELLS_DESTRUCT_083D0250_OPS).write((record_release_enabled_cells, record_release_attached_object)); }
        let mut object = [0xfeed_face; 6];
        object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        object[3] = 0;
        object[2] = 0;
        CELLS_THIS.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        EXPECT_RELEASE.store(1, Ordering::SeqCst);
        let result = unsafe { observable_array_attached_release_cells_destruct_083d0250(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(object[1], 0);
        assert_eq!(object[2], 0);
        assert_eq!(object[ATTACHED_OBJECT_WORD], 0x1234_5000);
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(CELLS_THIS.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CELLS_DESTRUCT_083D0250_OPS).write(old); }
    }

    #[test]
    fn null_attached_object_skips_virtual_release() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CELLS_DESTRUCT_083D0250_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CELLS_DESTRUCT_083D0250_OPS).write((record_release_enabled_cells, record_release_attached_object)); }
        let mut object = [0; 6];
        CELLS_THIS.store(0, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        EXPECT_RELEASE.store(0, Ordering::SeqCst);
        unsafe { observable_array_attached_release_cells_destruct_083d0250(object.as_mut_ptr()); }
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
        assert_eq!(CELLS_THIS.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ATTACHED_RELEASE_CELLS_DESTRUCT_083D0250_OPS).write(old); }
    }
}
