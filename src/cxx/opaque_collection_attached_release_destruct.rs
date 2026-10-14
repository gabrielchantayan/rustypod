//! Attached collection destructor — `FUN_083d07f8` @ **0x083d07f8**.
//!
//! True extent: 60 bytes, thirteen A32 instructions through the tail B at
//! 0x083d082c, then vtable literal 0x089a43b0 at 0x083d0830. The next real
//! function starts with push at 0x083d0834. Raw whole-image decoding finds
//! one inbound plain BL (0x0826b520), zero predicated BL callers. The body
//! has one plain BL (0x083d0820 -> 0x083d0738), zero predicated BLs, and
//! one BLXNE (0x083d0818) through the attached object's vtable +0x1c.
//!
//! Install the derived vtable, release a non-null attached object at +0x14,
//! run opaque_collection_release_allocation, then tail-chain to
//! observable_array_destruct and return its result. Deliberate deviations:
//! Rust expresses predication and the tail branch as ordinary control flow;
//! host builds inject virtual/direct-call seams because the collection port
//! uses widened host pointers, while this wrapper retains target word layout.

const VTABLE_WORD: u32 = 0x089a_43b0;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;
type ReleaseAllocation = unsafe extern "C" fn(*mut u8);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_allocation(_this: *mut u8) {
    panic!("install attached collection destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install attached collection destructor host seams before calling this port")
}

/// Host replacements for target-layout allocation release and virtual release.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_COLLECTION_ATTACHED_RELEASE_DESTRUCT_OPS: (ReleaseAllocation, ReleaseAttachedObject) =
    (missing_release_allocation, missing_release_attached_object);

/// Release the attached object and collection allocation, then destroy the base.
///
/// # Safety
/// `this` must be writable target-layout storage through +0x14, valid for
/// both direct destructors. Its nonzero attached word must designate an
/// object whose vtable +0x1c is callable with that object as receiver.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_collection_attached_release_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            crate::cxx::opaque_collection_release_allocation::opaque_collection_release_allocation(this.cast());
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release_allocation, release) = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_COLLECTION_ATTACHED_RELEASE_DESTRUCT_OPS));
            if !attached.is_null() {
                release(attached);
            }
            release_allocation(this.cast());
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
    static RECEIVER: AtomicUsize = AtomicUsize::new(0);
    static STAGE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release_attached(object: *mut u8) {
        let this = RECEIVER.load(Ordering::SeqCst) as *mut u32;
        assert_eq!(object as usize, 0x1234_5000);
        assert_eq!(unsafe { this.read() }, VTABLE_WORD);
        assert_eq!(STAGE.swap(1, Ordering::SeqCst), 0);
        // Side effects of virtual release must be visible to allocation release.
        unsafe { this.add(4).write(0); }
    }

    unsafe extern "C" fn release_allocation(object: *mut u8) {
        let this = object.cast::<u32>();
        assert_eq!(this as usize, RECEIVER.load(Ordering::SeqCst));
        assert_eq!(unsafe { this.read() }, VTABLE_WORD);
        if unsafe { this.add(5).read() } != 0 {
            assert_eq!(STAGE.load(Ordering::SeqCst), 1);
            assert_eq!(unsafe { this.add(4).read() }, 0);
        } else {
            assert_eq!(STAGE.load(Ordering::SeqCst), 0);
        }
        // Base teardown must run after this mutation, not before it.
        unsafe { this.add(1).write(17); }
        STAGE.store(2, Ordering::SeqCst);
    }

    #[test]
    fn optional_attachment_preserves_release_order_and_base_teardown() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_COLLECTION_ATTACHED_RELEASE_DESTRUCT_OPS)) };
        unsafe { core::ptr::addr_of_mut!(OPAQUE_COLLECTION_ATTACHED_RELEASE_DESTRUCT_OPS).write((release_allocation, release_attached)); }
        for attached in [0, 0x1234_5000] {
            let mut object = [0xfeed_face, 3, 0, 0, 1, attached, 0xcafe_babe];
            RECEIVER.store(object.as_mut_ptr() as usize, Ordering::SeqCst);
            STAGE.store(0, Ordering::SeqCst);
            let result = unsafe { opaque_collection_attached_release_destruct(object.as_mut_ptr()) };
            assert_eq!(result, object.as_mut_ptr());
            assert_eq!(STAGE.load(Ordering::SeqCst), 2);
            assert_eq!(object, [crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE,
                0, 0, 0, if attached == 0 { 1 } else { 0 }, attached, 0xcafe_babe]);
        }
        unsafe { core::ptr::addr_of_mut!(OPAQUE_COLLECTION_ATTACHED_RELEASE_DESTRUCT_OPS).write(old); }
    }
}
