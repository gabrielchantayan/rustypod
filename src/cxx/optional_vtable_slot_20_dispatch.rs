//! Dispatches an optional object's vtable slot `+0x20` method.
//!
//! `optional_vtable_slot_20_dispatch` — original: `FUN_082dc290` at load
//! address `0x082dc290`. Raw `osos.dec` establishes the six ARM words from
//! `0x082dc290` through `bx lr` at `0x082dc2a4`, for a true 24-byte extent;
//! the next independently entered function begins at `0x082dc2a8` with
//! `push {r4-r9,sl,fp,lr}`. Complete-image ARM branch decoding finds two
//! inbound plain `bl` sites (`0x082ddbe8`, `0x082de840`), no predicated `bl`
//! sites, and no direct outbound `bl` instructions. The body has one
//! predicated indirect tail dispatch through vtable slot `+0x20`.
//!
//! # Algorithm
//!
//! Returns zero when `object` is NULL. Otherwise loads its vtable and
//! tail-dispatches slot `+0x20`, preserving `object` as that method's argument
//! and returning its result.
//!
//! # Deliberate deviation
//!
//! The virtual method's semantic identity is not recovered. Retail vtable
//! entries are four-byte pointers; host function pointers are wider, so host
//! vtables are indexed by ARM word number rather than host byte offset.

const VTABLE_SLOT_20: usize = 0x20 / 4;
type VtableSlot20Method = unsafe extern "C" fn(*mut u8) -> u32;

/// Calls vtable slot `+0x20` when `object` is non-NULL, otherwise returns zero.
///
/// # Safety
///
/// A non-NULL `object` must begin with a readable vtable pointer whose ninth
/// entry is a callable [`VtableSlot20Method`]. Stock code performs no further
/// validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.optional_vtable_slot_20_dispatch")]
#[inline(never)]
pub unsafe extern "C" fn optional_vtable_slot_20_dispatch(object: *mut u8) -> u32 {
    if object.is_null() {
        return 0;
    }

    let vtable = unsafe { (object as *const *const usize).read() };
    let method: VtableSlot20Method = unsafe { core::mem::transmute(vtable.add(VTABLE_SLOT_20).read()) };
    unsafe { method(object) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static METHOD_CALLS: AtomicUsize = AtomicUsize::new(0);
    static METHOD_OBJECT: AtomicUsize = AtomicUsize::new(0);

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        payload: u32,
    }

    unsafe extern "C" fn record_method(object: *mut u8) -> u32 {
        METHOD_CALLS.fetch_add(1, Ordering::SeqCst);
        METHOD_OBJECT.store(object as usize, Ordering::SeqCst);
        0xfeed_face
    }

    #[test]
    fn null_object_returns_zero_without_vtable_access() {
        let _lock = TEST_LOCK.lock();
        METHOD_CALLS.store(0, Ordering::SeqCst);

        let result = unsafe { optional_vtable_slot_20_dispatch(core::ptr::null_mut()) };

        assert_eq!(result, 0);
        assert_eq!(METHOD_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn non_null_object_calls_ninth_vtable_entry_with_original_object() {
        let _lock = TEST_LOCK.lock();
        METHOD_CALLS.store(0, Ordering::SeqCst);
        METHOD_OBJECT.store(0, Ordering::SeqCst);
        let mut vtable = [0usize; VTABLE_SLOT_20 + 1];
        vtable[VTABLE_SLOT_20] = record_method as usize;
        let mut object = Object { vtable: vtable.as_ptr(), payload: 0x1234_5678 };

        let result = unsafe { optional_vtable_slot_20_dispatch((&mut object as *mut Object).cast()) };

        assert_eq!(result, 0xfeed_face);
        assert_eq!(METHOD_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(METHOD_OBJECT.load(Ordering::SeqCst), (&mut object as *mut Object) as usize);
        assert_eq!(object.payload, 0x1234_5678);
    }
}
