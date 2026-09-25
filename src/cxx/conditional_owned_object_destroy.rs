//! Conditionally destroys and deallocates an owned opaque object.
//!
//! `conditional_owned_object_destroy` — original: `FUN_083e7520` at load
//! address `0x083e7520` (36 bytes). Raw `osos.dec` establishes nine ARM words
//! from `push {r4,lr}` through `pop {r4,pc}` at `0x083e7540`; the next
//! independently entered function starts with `push {r4,r5,r6,lr}` at
//! `0x083e7544`. Full-image ARM branch decoding finds two inbound direct `bl`
//! call sites, both plain unconditional (`0x08291f08` and `0x08291f88`), and no
//! predicated `bl` calls. The body has two plain unconditional `bl` calls:
//! the unported opaque-object destructor @ `0x081d2914` and
//! [`operator_delete`] @ `0x082aad24`.
//!
//! # Algorithm
//!
//! Loads the owned pointer from `slot`. If it is non-NULL, destroys the opaque
//! object, deallocates it with tag-2 `operator_delete`, and returns `slot`.
//! The slot itself is not modified.
//!
//! # Deliberate deviations
//!
//! The target slot is one 32-bit pointer word; this Rust interface uses a
//! native-width pointer slot so host fixtures remain valid. The destructor has
//! no recovered semantic identity, so target builds call its verified address
//! and host builds use a narrow callback seam.

use crate::heap::veneers::operator_delete;

/// ABI of the unported opaque-object destructor at `0x081d2914`.
pub type OpaqueObjectDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_object_destroy(object: *mut u8) -> *mut u8 {
    object
}

/// Host seam for the unported opaque-object destructor.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBJECT_DESTROY: OpaqueObjectDestroy = missing_opaque_object_destroy;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn opaque_object_destroy_target() -> OpaqueObjectDestroy {
    unsafe { core::mem::transmute(0x081d_2914usize) }
}

/// Destroys and deallocates the non-NULL opaque object owned by `slot`.
///
/// # Safety
///
/// `slot` must name a readable pointer word. Its non-NULL value must satisfy
/// the unported destructor's contract and be valid for [`operator_delete`].
/// Stock code neither checks `slot` for NULL nor clears it.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.conditional_owned_object_destroy")]
#[inline(never)]
pub unsafe extern "C" fn conditional_owned_object_destroy(slot: *mut *mut u8) -> *mut *mut u8 {
    let object = unsafe { slot.read() };
    if !object.is_null() {
        #[cfg(target_os = "none")]
        unsafe { opaque_object_destroy_target()(object) };
        #[cfg(not(target_os = "none"))]
        unsafe { OPAQUE_OBJECT_DESTROY(object) };
        unsafe { operator_delete(object) };
    }
    slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{DEFAULT_HEAP_OPS, HEAP_OPS};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DESTROYED_OBJECT: usize = 0;
    static mut FREED_OBJECT: usize = 0;
    static mut FREED_TAG: usize = 0;

    unsafe extern "C" fn record_opaque_object_destroy(object: *mut u8) -> *mut u8 {
        unsafe { DESTROYED_OBJECT = object as usize };
        object
    }

    unsafe extern "C" fn record_free(
        _heap: *mut HeapDescriptorDescriptor,
        object: *mut u8,
        tag: usize,
    ) {
        unsafe {
            FREED_OBJECT = object as usize;
            FREED_TAG = tag;
        }
    }

    fn install_recording_seams() {
        unsafe {
            OPAQUE_OBJECT_DESTROY = record_opaque_object_destroy;
            let mut ops = DEFAULT_HEAP_OPS;
            ops.free = record_free;
            HEAP_OPS = ops;
            crate::heap::types::DEFAULT_HEAP = 1usize as *mut _;
            DESTROYED_OBJECT = 0;
            FREED_OBJECT = 0;
            FREED_TAG = 0;
        }
    }

    fn restore_seams() {
        unsafe {
            OPAQUE_OBJECT_DESTROY = missing_opaque_object_destroy;
            HEAP_OPS = DEFAULT_HEAP_OPS;
            crate::heap::types::DEFAULT_HEAP = core::ptr::null_mut();
        }
    }

    #[test]
    fn null_object_returns_slot_without_calling_either_operation() {
        let _lock = TEST_LOCK.lock();
        install_recording_seams();
        let mut slot = core::ptr::null_mut();

        let returned = unsafe { conditional_owned_object_destroy(&mut slot) };

        assert_eq!(returned, core::ptr::addr_of_mut!(slot));
        assert!(slot.is_null());
        assert_eq!(unsafe { DESTROYED_OBJECT }, 0);
        assert_eq!(unsafe { FREED_OBJECT }, 0);
        restore_seams();
    }

    #[test]
    fn non_null_object_is_destroyed_then_deleted_without_clearing_slot() {
        let _lock = TEST_LOCK.lock();
        install_recording_seams();
        let mut storage = [0u8; 0x54];
        let object = storage.as_mut_ptr();
        let mut slot = object;

        let returned = unsafe { conditional_owned_object_destroy(&mut slot) };

        assert_eq!(returned, core::ptr::addr_of_mut!(slot));
        assert_eq!(slot, object);
        assert_eq!(unsafe { DESTROYED_OBJECT }, object as usize);
        assert_eq!(unsafe { FREED_OBJECT }, object as usize);
        assert_eq!(unsafe { FREED_TAG }, 2);
        restore_seams();
    }
}
