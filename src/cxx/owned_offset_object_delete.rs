//! `owned_offset_object_delete` — destroys and releases an optional opaque
//! object whose destructor operates on an interior subobject.
//!
//! Original: `FUN_083e7284` @ `0x083e7284` (44 bytes exactly,
//! `0x083e7284..0x083e72af`). `push {r4,lr}` at `0x083e72b0` begins the next
//! real function. The body has two plain `bl` calls and no predicated `bl`
//! calls: the unported opaque destructor @ `0x0839c888` and tag-2
//! `operator_delete` @ `0x082aad24`. Raw full-image decoding establishes two
//! inbound plain `bl` call sites and no predicated `bl` callers.
//!
//! # Algorithm
//!
//! Read the optional object at `slot+0x00`. If non-NULL, invoke its opaque
//! destructor with `object+0x04`, subtract four from its returned subobject
//! address, and tag-2 free that allocation. Return `slot` without changing it.
//!
//! # Deliberate deviations
//!
//! The destructor at `0x0839c888` is unported and its class identity remains
//! unknown. Target builds call its verified address; host tests replace the
//! narrow operation seam. The host slot uses a native-width pointer rather
//! than the target's four-byte pointer word.

use core::ptr::addr_of_mut;

#[cfg(test)]
extern crate std;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_destruct_0839c888(subobject: *mut u8) -> *mut u8 {
    let destruct: unsafe extern "C" fn(*mut u8) -> *mut u8 = unsafe { core::mem::transmute(0x0839_c888usize) };
    unsafe { destruct(subobject) }
}

#[cfg(not(target_os = "none"))]
pub(crate) unsafe extern "C" fn missing_destruct_0839c888(_subobject: *mut u8) -> *mut u8 {
    panic!("owned_offset_object_delete requires destructor 0x0839c888")
}

/// Opaque destructor @ `0x0839c888`, called on the object's `+0x04` subobject.
#[cfg(target_os = "none")]
pub static mut OWNED_OFFSET_OBJECT_DESTRUCT: unsafe extern "C" fn(*mut u8) -> *mut u8 = firmware_destruct_0839c888;
#[cfg(not(target_os = "none"))]
pub static mut OWNED_OFFSET_OBJECT_DESTRUCT: unsafe extern "C" fn(*mut u8) -> *mut u8 = missing_destruct_0839c888;

#[cfg(test)]
pub(crate) static OWNED_OFFSET_OBJECT_DESTRUCT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Destroys and frees the optional object held by `slot`, returning `slot`.
///
/// # Safety
/// `slot` must point to a valid pointer-sized object slot. A non-NULL object
/// must be a tag-2 heap allocation accepted by destructor `0x0839c888`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_offset_object_delete(slot: *mut *mut u8) -> *mut *mut u8 {
    let object = unsafe { slot.read_volatile() };
    if !object.is_null() {
        let destruct = unsafe { addr_of_mut!(OWNED_OFFSET_OBJECT_DESTRUCT).read_volatile() };
        let allocation = unsafe { destruct(object.add(4)).sub(4) };
        unsafe { crate::heap::veneers::operator_delete(allocation) };
    }
    slot
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use std::sync::MutexGuard;

    static mut DESTRUCT_ARGUMENT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_destruct(subobject: *mut u8) -> *mut u8 {
        unsafe { addr_of_mut!(DESTRUCT_ARGUMENT).write(subobject) };
        subobject
    }

    fn mock() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let destruct_guard = OWNED_OFFSET_OBJECT_DESTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            addr_of_mut!(OWNED_OFFSET_OBJECT_DESTRUCT).write_volatile(recording_destruct);
            addr_of_mut!(DESTRUCT_ARGUMENT).write(core::ptr::null_mut());
        }
        (destruct_guard, heap_guard)
    }

    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe { addr_of_mut!(OWNED_OFFSET_OBJECT_DESTRUCT).write_volatile(missing_destruct_0839c888) };
        drop(guards);
    }

    #[repr(C)]
    struct Slot {
        object: *mut u8,
    }

    #[test]
    fn destroys_the_interior_subobject_then_frees_its_base_without_clearing_slot() {
        let guards = mock();
        let Some(object) = try_map_u32_slab(crate::testing::hints::OWNED_OFFSET_OBJECT_DELETE, 8) else {
            restore(guards);
            assert!(note_missing_u32_fixture("cxx::owned_offset_object_delete"));
            return;
        };
        let mut slot = Slot { object };

        let returned = unsafe { owned_offset_object_delete(addr_of_mut!(slot.object)) };

        assert_eq!(returned, addr_of_mut!(slot.object));
        assert_eq!(slot.object, object, "retailOS leaves the owner slot unchanged");
        assert_eq!(unsafe { DESTRUCT_ARGUMENT }, unsafe { object.add(4) });
        let (frees, freed, tag) = free_log();
        assert_eq!(frees, 1);
        assert_eq!(freed, object);
        assert_eq!(tag, 2);
        restore(guards);
    }

    #[test]
    fn null_slot_returns_without_destructing_or_freeing() {
        let guards = mock();
        let mut slot = Slot { object: core::ptr::null_mut() };

        assert_eq!(unsafe { owned_offset_object_delete(addr_of_mut!(slot.object)) }, addr_of_mut!(slot.object));
        assert!(unsafe { DESTRUCT_ARGUMENT }.is_null());
        assert_eq!(free_log().0, 0);
        restore(guards);
    }
}
