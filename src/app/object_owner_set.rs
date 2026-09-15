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
//! it destroys the object's two owned resources through `FUN_08256b50` and
//! tail-branches to tag-2 `operator_delete` (`0x082aad24`).
//!
//! # Deliberate deviations
//!
//! The target calls the unported resource destructor at its verified load
//! address. Host builds route it and the final delete through recording seams;
//! the retail tail branch is represented by an ordinary Rust call.

use core::ptr::addr_of_mut;
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const OWNER_OFFSET: usize = 0x9c;
const DISPOSE_ON_ORPHAN_OFFSET: usize = 0xa0;
const OBJECT_RESOURCES_DESTROY_ADDRESS: usize = 0x0825_6b50;

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

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_object_resources_destroy(object: *mut OwnedObject) -> *mut OwnedObject {
    let destroy: ObjectResourcesDestroy = unsafe { core::mem::transmute(OBJECT_RESOURCES_DESTROY_ADDRESS) };
    unsafe { destroy(object) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_resources_destroy(_object: *mut OwnedObject) -> *mut OwnedObject {
    panic!("object_owner_set requires resource destructor 0x08256b50")
}

/// External operations reached only for an orphaned disposable object.
#[derive(Clone, Copy)]
pub struct ObjectOwnerSetOps {
    pub destroy_resources: ObjectResourcesDestroy,
    pub delete: ObjectDelete,
}

#[cfg(not(target_os = "none"))]
pub static mut OBJECT_OWNER_SET_OPS: ObjectOwnerSetOps = ObjectOwnerSetOps {
    destroy_resources: missing_object_resources_destroy,
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
    let object = unsafe { retail_object_resources_destroy(object) };
    #[cfg(not(target_os = "none"))]
    let object = unsafe { (ops().destroy_resources)(object) };

    #[cfg(target_os = "none")]
    unsafe { crate::heap::veneers::operator_delete(object.cast()) };
    #[cfg(not(target_os = "none"))]
    unsafe { (ops().delete)(object.cast()) };
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
