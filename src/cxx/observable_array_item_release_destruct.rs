//! **0x083d1684** (64 bytes: 56 bytes of code plus the vtable literal).
//!
//! Raw `osos.dec` decodes fourteen A32 instruction words from `0x083d1684`
//! through the tail branch at `0x083d16b8`; `0x083d16bc` is vtable literal
//! `0x089a4f80`, and the next real function starts at `0x083d16c0`. Decoding
//! every ARM `bl` immediate in the image finds two inbound plain sites
//! (`0x08236214`, `0x0826b670`) and no predicated inbound sites. The body has
//! one plain direct `bl` to `0x083d15dc` and one predicated indirect `blxne`
//! through the attached object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Re-plants its derived vtable, conditionally invokes the attached object's
//! virtual release at `this+0x14`, releases its items through `0x083d15dc`,
//! then tail-chains into `observable_array_destruct`.
//!
//! Deliberate deviations: host builds use explicit seams for the unported
//! direct and dynamic calls. Target builds invoke their recovered absolute
//! addresses; Rust does not preserve the predicated `blx` or tail branch.

const VTABLE_WORD: u32 = 0x089a_4f80;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type ReleaseItems = unsafe extern "C" fn(*mut u32);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn release_items(this: *mut u32) {
    let release: ReleaseItems = unsafe { core::mem::transmute(0x083d_15dcusize) };
    unsafe { release(this) };
}

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_items(_this: *mut u32) {
    panic!("install observable-array item-release destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array item-release destructor host seams before calling this port")
}

/// Host replacements for `0x083d15dc` and the attached object's vtable slot
/// `+0x1c`; neither callee has a Rust port.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ITEM_RELEASE_DESTRUCT_OPS: (ReleaseItems, ReleaseAttachedObject) =
    (missing_release_items, missing_release_attached_object);

/// Destroys an observable-array-derived object after releasing its items.
///
/// # Safety
///
/// `this` must point to writable target-layout storage through `+0x14`. A
/// nonzero word at `+0x14` must name an attached object valid for its vtable
/// release slot, and the direct item-release helper's input requirements apply.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_item_release_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        if !attached.is_null() {
            release_attached_object(attached);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release_items, release_attached) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ITEM_RELEASE_DESTRUCT_OPS));
            if !attached.is_null() {
                release_attached(attached);
            }
            release_items(this);
        }
        #[cfg(target_os = "none")]
        release_items(this);
        crate::cxx::observable_array::observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static ITEMS_RELEASED: AtomicUsize = AtomicUsize::new(0);
    static ATTACHED_RELEASED: AtomicUsize = AtomicUsize::new(0);
    static EXPECT_ATTACHED_RELEASE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release_items(this: *mut u32) {
        if EXPECT_ATTACHED_RELEASE.load(Ordering::SeqCst) != 0 {
            assert_eq!(ATTACHED_RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        }
        ITEMS_RELEASED.store(this as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn record_release_attached(object: *mut u8) {
        ATTACHED_RELEASED.store(object as usize, Ordering::SeqCst);
    }

    #[test]
    fn releases_attached_object_then_items_before_base_destructor() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ITEM_RELEASE_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ITEM_RELEASE_DESTRUCT_OPS).write((record_release_items, record_release_attached)); }
        let mut object = [0xfeed_face; 6];
        object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        object[3] = 0;
        object[2] = 0;
        ITEMS_RELEASED.store(0, Ordering::SeqCst);
        ATTACHED_RELEASED.store(0, Ordering::SeqCst);
        EXPECT_ATTACHED_RELEASE.store(1, Ordering::SeqCst);
        let result = unsafe { observable_array_item_release_destruct(object.as_mut_ptr()) };
        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(object[1], 0);
        assert_eq!(object[2], 0);
        assert_eq!(object[ATTACHED_OBJECT_WORD], 0x1234_5000);
        assert_eq!(ATTACHED_RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(ITEMS_RELEASED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ITEM_RELEASE_DESTRUCT_OPS).write(old); }
    }

    #[test]
    fn null_attached_object_skips_virtual_release() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ITEM_RELEASE_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ITEM_RELEASE_DESTRUCT_OPS).write((record_release_items, record_release_attached)); }
        let mut object = [0; 6];
        ITEMS_RELEASED.store(0, Ordering::SeqCst);
        ATTACHED_RELEASED.store(0, Ordering::SeqCst);
        EXPECT_ATTACHED_RELEASE.store(0, Ordering::SeqCst);
        unsafe { observable_array_item_release_destruct(object.as_mut_ptr()); }
        assert_eq!(ATTACHED_RELEASED.load(Ordering::SeqCst), 0);
        assert_eq!(ITEMS_RELEASED.load(Ordering::SeqCst), object.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_ITEM_RELEASE_DESTRUCT_OPS).write(old); }
    }
}
