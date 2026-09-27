//! `indexed_element_array_attached_destruct` — retailOS `FUN_083d0160` @
//! **0x083d0160**.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes fourteen A32 words from `push {r4,lr}` at
//! `0x083d0160` through the tail branch at `0x083d0194`: **56 code bytes**.
//! `0x083d0198` is the derived-vtable literal `0x089a3dc8`; `push {r4-r6,lr}`
//! at `0x083d019c` begins the next real function. The body has one plain
//! direct `bl`, to [`indexed_element_array_release`], and one predicated
//! indirect `blxne` through the attached object's vtable slot `+0x1c`.
//!
//! ## Algorithm
//!
//! Installs its derived vtable, releases the non-null attached object, releases
//! enabled indexed elements, then tail-chains to `observable_array_destruct`.
//!
//! Deliberate deviations: host builds use an explicit seam for the target-width
//! virtual call. Rust expresses the predicated `blxne` and tail branch as
//! ordinary control flow and a normal base-destructor call.

use crate::cxx::indexed_element_array_release::{indexed_element_array_release, IndexedElementArrayRelease};
use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};

const VTABLE_WORD: u32 = 0x089a_3dc8;
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
    panic!("install indexed element array attached destructor host operations before calling this port")
}

/// Host replacement for the attached object's vtable slot `+0x1c`.
#[cfg(not(target_os = "none"))]
pub static mut INDEXED_ELEMENT_ARRAY_ATTACHED_DESTRUCT_RELEASE: ReleaseAttachedObject = missing_release_attached_object;

/// # Safety
///
/// `this` must point to a writable target-layout derived indexed-element array.
/// Its word at `+0x14`, when nonzero, must identify an object releasable via
/// vtable slot `+0x1c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_element_array_attached_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        if !attached.is_null() {
            #[cfg(target_os = "none")]
            release_attached_object(attached);
            #[cfg(not(target_os = "none"))]
            core::ptr::addr_of!(INDEXED_ELEMENT_ARRAY_ATTACHED_DESTRUCT_RELEASE).read_volatile()(attached);
        }
        indexed_element_array_release(this.cast::<IndexedElementArrayRelease>());
        observable_array_destruct(this.cast::<ObservableArray>()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(object: *mut u8) { RELEASED.store(object as usize, Ordering::SeqCst); }

    #[test]
    fn releases_attached_object_and_returns_array() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::addr_of!(INDEXED_ELEMENT_ARRAY_ATTACHED_DESTRUCT_RELEASE).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(INDEXED_ELEMENT_ARRAY_ATTACHED_DESTRUCT_RELEASE).write(record_release); }
        let mut array = [0u32; 6];
        array[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        RELEASED.store(0, Ordering::SeqCst);
        let result = unsafe { indexed_element_array_attached_destruct(array.as_mut_ptr()) };
        assert_eq!(result, array.as_mut_ptr());
        assert_eq!(array[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        unsafe { core::ptr::addr_of_mut!(INDEXED_ELEMENT_ARRAY_ATTACHED_DESTRUCT_RELEASE).write(old); }
    }

    #[test]
    fn null_attached_object_skips_virtual_release() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::addr_of!(INDEXED_ELEMENT_ARRAY_ATTACHED_DESTRUCT_RELEASE).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(INDEXED_ELEMENT_ARRAY_ATTACHED_DESTRUCT_RELEASE).write(record_release); }
        let mut array = [0u32; 6];
        RELEASED.store(0, Ordering::SeqCst);
        unsafe { indexed_element_array_attached_destruct(array.as_mut_ptr()); }
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
        unsafe { core::ptr::addr_of_mut!(INDEXED_ELEMENT_ARRAY_ATTACHED_DESTRUCT_RELEASE).write(old); }
    }
}
