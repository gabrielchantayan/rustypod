//! Deletes the optional polymorphic object stored in an owned slot.
//!
//! `owned_virtual_object_delete` — original: `FUN_083e73d0` at load address
//! `0x083e73d0` (36 bytes). Raw `osos.dec` establishes nine ARM words from
//! `push {r4,lr}` through `pop {r4,pc}` at `0x083e73f0`; the next independently
//! entered function starts at `0x083e73f4`. The body has two direct,
//! unconditional `bl` calls (`FUN_083e7328` @ `0x083e7328` and
//! `operator_delete` @ `0x082aad24`) and no predicated `bl` calls. Full-image
//! decoding finds two inbound plain `bl` call sites (0x08124644 and
//! 0x0815fc30), with no predicated `bl` callers.
//!
//! # Algorithm
//!
//! Load the object from `slot`. If non-NULL, invoke its vtable slot `+4`, then
//! delete that same object. Return `slot` unchanged.
//!
//! # Deliberate deviations
//!
//! `FUN_083e7328` has no recovered semantic identity beyond its verified
//! optional slot-`+4` dispatch. Target builds invoke that retailOS entry at its
//! fixed address; host builds perform the equivalent native-width dispatch so
//! callback pointers are not truncated. A host-only delete seam makes the
//! ownership transition observable; target builds call `operator_delete`.

const CALLBACK_VTABLE_INDEX: usize = 1;
type VtableSlot4Callback = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
static mut DELETE_OBJECT: unsafe extern "C" fn(*mut u8) = crate::heap::veneers::operator_delete;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn delete_object(object: *mut u8) {
    unsafe { crate::heap::veneers::operator_delete(object) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn delete_object(object: *mut u8) {
    unsafe { DELETE_OBJECT(object) };
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_object(object: *mut u8) -> *mut u8 {
    type RetailDispatch = unsafe extern "C" fn(*mut u8) -> *mut u8;

    let dispatch: RetailDispatch = unsafe { core::mem::transmute(0x083e_7328usize) };
    unsafe { dispatch(object) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_object(object: *mut u8) -> *mut u8 {
    let vtable = unsafe { (object as *const *const usize).read() };
    let callback: VtableSlot4Callback = unsafe { core::mem::transmute(vtable.add(CALLBACK_VTABLE_INDEX).read()) };
    unsafe { callback(object) };
    object
}

/// Destroys then deletes the non-NULL object held by `slot`.
///
/// # Safety
///
/// `slot` must be readable. Its non-NULL object must begin with a readable
/// vtable whose slot `+4` is callable with that object. The delete operation
/// owns the object; the slot is not cleared.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.owned_virtual_object_delete")]
#[inline(never)]
pub unsafe extern "C" fn owned_virtual_object_delete(slot: *mut *mut u8) -> *mut *mut u8 {
    let object = unsafe { slot.read() };
    if !object.is_null() {
        let object = unsafe { destroy_object(object) };
        unsafe { delete_object(object) };
    }
    slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK_OBJECT: AtomicUsize = AtomicUsize::new(0);
    static DELETE_OBJECT_ADDRESS: AtomicUsize = AtomicUsize::new(0);

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        payload: u32,
    }

    unsafe extern "C" fn record_callback(object: *mut u8) {
        CALLBACK_CALLS.fetch_add(1, Ordering::SeqCst);
        CALLBACK_OBJECT.store(object as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_delete(object: *mut u8) {
        DELETE_OBJECT_ADDRESS.store(object as usize, Ordering::SeqCst);
    }

    #[test]
    fn null_slot_object_skips_dispatch_and_delete() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        DELETE_OBJECT_ADDRESS.store(0, Ordering::SeqCst);
        let mut slot = core::ptr::null_mut();

        assert_eq!(unsafe { owned_virtual_object_delete(&mut slot) }, core::ptr::addr_of_mut!(slot));
        assert!(slot.is_null());
        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(DELETE_OBJECT_ADDRESS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn destroys_via_second_vtable_entry_then_deletes_without_clearing_slot() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        CALLBACK_OBJECT.store(0, Ordering::SeqCst);
        DELETE_OBJECT_ADDRESS.store(0, Ordering::SeqCst);
        let previous_delete = unsafe { DELETE_OBJECT };
        unsafe { DELETE_OBJECT = record_delete };
        let vtable = [0usize, record_callback as usize];
        let mut object = Object { vtable: vtable.as_ptr(), payload: 0xfeed_face };
        let mut slot = (&mut object as *mut Object).cast::<u8>();

        assert_eq!(unsafe { owned_virtual_object_delete(&mut slot) }, core::ptr::addr_of_mut!(slot));
        unsafe { DELETE_OBJECT = previous_delete };
        assert_eq!(slot, (&mut object as *mut Object).cast::<u8>());
        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CALLBACK_OBJECT.load(Ordering::SeqCst), slot as usize);
        assert_eq!(DELETE_OBJECT_ADDRESS.load(Ordering::SeqCst), slot as usize);
        assert_eq!(object.payload, 0xfeed_face);
    }
}
