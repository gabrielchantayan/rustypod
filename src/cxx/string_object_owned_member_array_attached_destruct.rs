//! Attached owned-string-member array destructor — `FUN_083d1834` @ 0x083d1834.
//!
//! Raw firmware establishes **60 bytes**: 56 instruction bytes through the tail
//! branch at 0x083d1868, then vtable literal 0x089a5130 at 0x083d186c. The next
//! real function starts at 0x083d1870. The body has one plain direct BL to
//! 0x083d178c, zero predicated direct BLs, and one indirect BLXNE at 0x083d1854.
//! Whole-image word decoding finds one inbound plain BL at 0x0826b6a0 and zero
//! predicated inbound BLs.
//!
//! Install the derived vtable, release the optional attachment at +0x14 through
//! its vtable slot +0x1c, destroy enabled owned-string-member elements, then
//! tail-chain to the observable-array base destructor, returning the same object.
//! Deliberate deviations: Rust uses normal control flow for the conditional BLX
//! and tail branch. Host builds substitute only the target-width virtual call;
//! the two established cleanup ports are called directly.
//! ARM codegen retains the vtable store, optional virtual release, direct
//! cleanup call and base tail branch; LLVM uses BEQ plus BLX instead of BLXNE.

use super::observable_array::{observable_array_destruct, ObservableArray};
use super::templates::{string_object_owned_member_container_destroy, ContainerDeleteEnabledElements};

const VTABLE: u32 = 0x089a_5130;
type ReleaseAttached = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn release_attached(object: *mut u8) {
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let release: ReleaseAttached = core::mem::transmute(vtable.add(7).read_volatile() as usize);
    release(object);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_object: *mut u8) {
    panic!("install owned member array attached release host operation");
}

/// Host replacement for the attachment's target-width virtual release slot.
#[cfg(not(target_os = "none"))]
pub static mut OWNED_MEMBER_ARRAY_ATTACHED_RELEASE: ReleaseAttached = missing_release;

/// # Safety
/// `this` must be a writable target-layout derived observable array. Enabled
/// elements must satisfy `string_object_owned_member_container_destroy`'s
/// contract; the nonzero attachment must support virtual release at +0x1c.
/// Host callers must also provide the cleanup head's native-pointer layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_object_owned_member_array_attached_destruct(this: *mut u32) -> *mut u32 {
    this.write_volatile(VTABLE);
    let attached = this.add(5).read_volatile() as usize as *mut u8;
    if !attached.is_null() {
        #[cfg(target_os = "none")]
        release_attached(attached);
        #[cfg(not(target_os = "none"))]
        core::ptr::addr_of!(OWNED_MEMBER_ARRAY_ATTACHED_RELEASE).read_volatile()(attached);
    }
    string_object_owned_member_container_destroy(this.cast::<ContainerDeleteEnabledElements>());
    observable_array_destruct(this.cast::<ObservableArray>()).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static LOCK: Mutex<()> = Mutex::new(());
    static ARRAY: AtomicUsize = AtomicUsize::new(0);
    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    #[repr(C, align(8))]
    struct Fixture([u32; 8]);

    unsafe extern "C" fn release(object: *mut u8) {
        let array = ARRAY.load(Ordering::SeqCst) as *mut u32;
        assert_eq!(array.read(), VTABLE);
        assert_eq!(array.add(1).read(), 7);
        RELEASED.store(object as usize, Ordering::SeqCst);
        // Real release callbacks may mutate the owner before derived cleanup.
        // Disable both the target flag and native-host cleanup flag.
        array.add(4).write(0);
        array.add(5).write(0);
    }

    #[test]
    fn attachment_release_precedes_base_teardown_and_preserves_identity() {
        let _lock = LOCK.lock();
        let old = unsafe { core::ptr::addr_of!(OWNED_MEMBER_ARRAY_ATTACHED_RELEASE).read() };
        unsafe { core::ptr::addr_of_mut!(OWNED_MEMBER_ARRAY_ATTACHED_RELEASE).write(release); }
        let mut fixture = Fixture([0u32; 8]);
        let array = &mut fixture.0;
        array[1] = 7;
        array[5] = 0x1234_5000;
        ARRAY.store(array.as_mut_ptr() as usize, Ordering::SeqCst);
        RELEASED.store(0, Ordering::SeqCst);
        let result = unsafe { string_object_owned_member_array_attached_destruct(array.as_mut_ptr()) };
        unsafe { core::ptr::addr_of_mut!(OWNED_MEMBER_ARRAY_ATTACHED_RELEASE).write(old); }
        assert_eq!(result, array.as_mut_ptr());
        assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(array[0], super::super::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(&array[1..4], &[0, 0, 0]);
    }

    #[test]
    fn null_attachment_and_disabled_empty_elements_need_no_virtual_dispatch() {
        let _lock = LOCK.lock();
        let mut fixture = Fixture([0u32; 8]);
        let array = &mut fixture.0;
        array[6] = 0xfeed_beef;
        let result = unsafe { string_object_owned_member_array_attached_destruct(array.as_mut_ptr()) };
        assert_eq!(result, array.as_mut_ptr());
        assert_eq!(array[0], super::super::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(array[6], 0xfeed_beef);
    }
}
