//! `object_owner_set` — original: `FUN_0825679c` @ **0x0825679c**.
//!
//! **44 bytes exactly**, eleven ARM words at `0x0825679c..0x082567c7`.
//! The next real function starts with `push {r4, r5, r6, lr}` at
//! `0x082567c8`; Ghidra's fall-through C has incorrectly absorbed the
//! deletion body beginning at `0x082aad24`. Five direct callers reach this
//! function: **one plain `bl`** and **four predicated `bl`**. Its verified
//! body contains one plain `bl` (`0x08256b50`) and no predicated calls.
//!
//! # Algorithm
//!
//! Stores `owner` in the object's `+0x9c` owner word. A non-NULL owner ends
//! the operation. If it has no owner and its `+0xa0` disposal byte is nonzero,
//! it destroys the object's two owned resources through `object_resources_destroy` and
//! tail-branches to tag-2 `operator_delete` (`0x082aad24`).
//!
//! # Deliberate deviations
//!
//! The resource destructor is the Rust port below. Host builds retain recording
//! seams for owner-set tests; the retail tail branch is an ordinary Rust call.

use core::ptr::addr_of_mut;
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const OWNER_OFFSET: usize = 0x9c;
const DISPOSE_ON_ORPHAN_OFFSET: usize = 0xa0;

/// Prefix of the opaque retail object consumed by [`object_owner_set`]. Wire
/// pointer fields are `u32`, retaining the target's four-byte offsets on hosts.
#[repr(C)]
pub struct OwnedObject {
    _before_owner: [u8; OWNER_OFFSET],
    owner: u32,
    dispose_on_orphan: u8,
}

const _: [u8; OWNER_OFFSET] = [0; core::mem::offset_of!(OwnedObject, owner)];
const _: [u8; DISPOSE_ON_ORPHAN_OFFSET] = [0; core::mem::offset_of!(OwnedObject, dispose_on_orphan)];

pub type ObjectResourcesDestroy = unsafe extern "C" fn(*mut OwnedObject) -> *mut OwnedObject;
pub type ObjectDelete = unsafe extern "C" fn(*mut u8);


/// External operations reached only for an orphaned disposable object.
#[derive(Clone, Copy)]
pub struct ObjectOwnerSetOps {
    pub destroy_resources: ObjectResourcesDestroy,
    pub delete: ObjectDelete,
}

#[cfg(not(target_os = "none"))]
pub static mut OBJECT_OWNER_SET_OPS: ObjectOwnerSetOps = ObjectOwnerSetOps {
    destroy_resources: object_resources_destroy,
    delete: crate::heap::veneers::operator_delete,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ops() -> ObjectOwnerSetOps {
    unsafe { core::ptr::read_volatile(addr_of!(OBJECT_OWNER_SET_OPS)) }
}

/// Updates an object's owner link and destroys an orphan marked disposable.
///
/// # Safety
/// `object` must designate at least `0xa1` writable bytes. This is the stock
/// function's unconditional `str r1, [r0, #0x9c]` precondition.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.object_owner_set"))]
pub unsafe extern "C" fn object_owner_set(object: *mut OwnedObject, owner: *mut u8) {
    unsafe { addr_of_mut!((*object).owner).write(owner as usize as u32) };
    if !owner.is_null() || unsafe { (*object).dispose_on_orphan } == 0 {
        return;
    }

    #[cfg(target_os = "none")]
    let object = unsafe { object_resources_destroy(object) };
    #[cfg(not(target_os = "none"))]
    let object = unsafe { (ops().destroy_resources)(object) };

    #[cfg(target_os = "none")]
    unsafe { crate::heap::veneers::operator_delete(object.cast()) };
    #[cfg(not(target_os = "none"))]
    unsafe { (ops().delete)(object.cast()) };
}

/// Releases an object's resources — `FUN_08256b50` @ **0x08256b50**.
///
/// True extent: **76 bytes**, `0x08256b50..0x08256b9c`, ending in
/// `pop {r4,pc}` before the next function's `push {r4-r8,lr}`.
/// Raw words contain one plain direct BL (tag-3 delete), zero predicated
/// direct BL, and two predicated indirect BLXNE calls through vtable slot 1.
/// Whole-image A32 branch decoding finds two inbound plain BLs at
/// 0x082567bc and 0x0825692c, with no predicated inbound BLs.
/// Release the nullable +0x7c object, reload and release +0x80, clear both
/// slots, delete the allocation at +0x70, then return the original object.
/// The allocation word is deliberately not cleared.
///
/// Deviations: virtual tables use native-width entries on hosts; the object's
/// pointer words remain u32. Volatile accesses preserve callback-visible
/// ordering. The delete uses the existing Rust tag-3 veneer.
/// Host suite: 13734 passed. ARM release build passed. match.py reports
/// 22 versus 19 instructions: frame-pointer setup and explicit conditional
/// branches replace predication; resource reloads, clearing, delete and
/// pointer return retain the original order. Standalone production-entry
/// smoke verifies the NULL-resource path with a modeled delete boundary.
///
/// # Safety
/// `object` must be aligned and writable through +0x83. Nonzero resource
/// words must designate objects with a valid vtable and slot-1 destructor.
/// The +0x70 allocation must satisfy the tag-3 delete contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resources_destroy(object: *mut OwnedObject) -> *mut OwnedObject {
    let words = object.cast::<u32>();
    for slot in [0x7c / 4, 0x80 / 4] {
        let resource = words.add(slot).read_volatile() as usize as *mut u8;
        if !resource.is_null() {
            #[cfg(target_os = "none")]
            let method = {
                let vtable = resource.cast::<u32>().read_volatile() as usize as *const u32;
                vtable.add(1).read_volatile() as usize
            };
            #[cfg(not(target_os = "none"))]
            let method = {
                let vtable = resource.cast::<*const usize>().read_volatile();
                vtable.add(1).read_volatile()
            };
            let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(method);
            release(resource);
        }
    }
    words.add(0x7c / 4).write_volatile(0);
    words.add(0x80 / 4).write_volatile(0);
    let allocation = words.add(0x70 / 4).read_volatile() as usize as *mut u8;
    crate::heap::veneers::operator_delete_tag3(allocation);
    object
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, free_log};
    use crate::testing::{hints, try_map_u32_slab};

    static mut OBJECT: *mut u32 = core::ptr::null_mut();
    static mut REPLACEMENT: u32 = 0;
    static mut CALLS: [usize; 2] = [0; 2];
    static mut COUNT: usize = 0;

    unsafe extern "C" fn release(resource: *mut u8) {
        let words = OBJECT;
        assert_ne!(words.add(31).read(), 0);
        assert_ne!(words.add(32).read(), 0);
        CALLS[COUNT] = resource as usize;
        COUNT += 1;
        if COUNT == 1 {
            // The second resource and allocation must be reloaded after callbacks.
            words.add(32).write(REPLACEMENT);
            words.add(28).write(0x1234);
        }
    }

    #[test]
    fn callbacks_observe_live_slots_and_can_replace_later_resources() {
        let _lock = mock_heap();
        let Some(slab) = try_map_u32_slab(hints::OBJECT_RESOURCES_DESTROY, 0x1000) else {
            assert!(crate::testing::note_missing_u32_fixture("object_resources_destroy"));
            return;
        };
        let vtable = [0usize, release as *const () as usize];
        unsafe {
            let first = slab.add(0x200);
            let second = slab.add(0x220);
            let replacement = slab.add(0x240);
            for resource in [first, second, replacement] {
                resource.cast::<*const usize>().write(vtable.as_ptr());
            }
            let mut words = [0xa5a5_a5a5u32; 41];
            words[31] = first as usize as u32;
            words[32] = second as usize as u32;
            OBJECT = words.as_mut_ptr();
            REPLACEMENT = replacement as usize as u32;
            COUNT = 0;
            let object = words.as_mut_ptr().cast::<OwnedObject>();
            assert_eq!(object_resources_destroy(object), object);
            assert_eq!(CALLS, [first as usize, replacement as usize]);
            assert_eq!(COUNT, 2);
            assert_eq!(words[31..33], [0, 0]);
            assert_eq!(words[28], 0x1234);
            assert_eq!(free_log(), (1, 0x1234usize as *mut u8, 3));
            for (index, word) in words.iter().enumerate() {
                if ![28, 31, 32].contains(&index) { assert_eq!(*word, 0xa5a5_a5a5); }
            }
        }
    }

    #[test]
    fn null_resources_skip_dispatch_and_null_allocation_skips_free() {
        let _lock = mock_heap();
        let mut words = [0u32; 41];
        unsafe {
            let object = words.as_mut_ptr().cast::<OwnedObject>();
            assert_eq!(object_resources_destroy(object), object);
            assert_eq!(free_log().0, 0);
            words[28] = 0x5678;
            assert_eq!(object_resources_destroy(object), object);
            assert_eq!(free_log(), (1, 0x5678usize as *mut u8, 3));
            assert_eq!(words[28], 0x5678);
            assert_eq!(words[31..33], [0, 0]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE: AtomicUsize = AtomicUsize::new(0);
    static mut DESTROYED: *mut OwnedObject = core::ptr::null_mut();
    static mut DELETED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_destroy(object: *mut OwnedObject) -> *mut OwnedObject {
        unsafe { DESTROYED = object };
        object
    }

    unsafe extern "C" fn record_delete(object: *mut u8) {
        unsafe { DELETED = object };
    }

    unsafe fn install_ops() -> ObjectOwnerSetOps {
        unsafe {
            let previous = core::ptr::read_volatile(addr_of!(OBJECT_OWNER_SET_OPS));
            OBJECT_OWNER_SET_OPS = ObjectOwnerSetOps { destroy_resources: record_destroy, delete: record_delete };
            DESTROYED = core::ptr::null_mut();
            DELETED = core::ptr::null_mut();
            previous
        }
    }

    unsafe fn restore_ops(previous: ObjectOwnerSetOps) {
        unsafe { OBJECT_OWNER_SET_OPS = previous };
    }

    fn object() -> Option<*mut OwnedObject> {
        let fixture = FIXTURE.load(Ordering::Relaxed);
        if fixture != 0 {
            return Some(fixture as *mut OwnedObject);
        }
        let mapped = try_map_u32_slab(hints::OBJECT_OWNER_SET, 0x1000)? as usize;
        let _ = FIXTURE.compare_exchange(0, mapped, Ordering::Relaxed, Ordering::Relaxed);
        Some(FIXTURE.load(Ordering::Relaxed) as *mut OwnedObject)
    }

    #[test]
    fn setting_an_owner_stores_its_target_width_address_without_destroying() {
        let _lock = OPS_LOCK.lock();
        let Some(object) = object() else { return };
        unsafe {
            let previous = install_ops();
            (*object).dispose_on_orphan = 1;
            object_owner_set(object, 0x1234_5678usize as *mut u8);
            assert_eq!((*object).owner, 0x1234_5678);
            assert!(DESTROYED.is_null());
            assert!(DELETED.is_null());
            restore_ops(previous);
        }
    }

    #[test]
    fn orphaned_disposable_object_destroys_resources_then_deletes_it() {
        let _lock = OPS_LOCK.lock();
        let Some(object) = object() else { return };
        unsafe {
            let previous = install_ops();
            (*object).dispose_on_orphan = 1;
            object_owner_set(object, core::ptr::null_mut());
            assert_eq!((*object).owner, 0);
            assert_eq!(DESTROYED, object);
            assert_eq!(DELETED, object.cast());
            restore_ops(previous);
        }
    }

    #[test]
    fn orphaned_object_without_dispose_byte_is_retained() {
        let _lock = OPS_LOCK.lock();
        let Some(object) = object() else { return };
        unsafe {
            let previous = install_ops();
            (*object).dispose_on_orphan = 0;
            object_owner_set(object, core::ptr::null_mut());
            assert_eq!((*object).owner, 0);
            assert!(DESTROYED.is_null());
            assert!(DELETED.is_null());
            restore_ops(previous);
        }
    }
}
