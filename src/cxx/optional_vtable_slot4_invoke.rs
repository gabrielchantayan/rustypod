//! Invokes an optional polymorphic object's vtable slot `+4` callback.
//!
//! `optional_vtable_slot4_invoke` — original: `FUN_083e7424` at load address
//! `0x083e7424` (36 bytes). Raw `osos.dec` establishes nine ARM words from
//! `push {r4,lr}` through `pop {r4,pc}` at `0x083e7444`; the next independently
//! entered function starts at `0x083e7448`. Full-image ARM branch decoding
//! finds two inbound direct `bl` call sites, both plain unconditional
//! (`0x08140714` and `0x0814071c`), and no predicated `bl` calls. The body has
//! no direct `bl` calls and one predicated indirect `blxne` through vtable slot
//! `+4`.
//!
//! # Algorithm
//!
//! Loads the object pointer from `slot`. When it is non-NULL, loads its vtable
//! and calls slot `+4` with the object in `r0`, then returns `slot` unchanged.
//!
//! # Deliberate deviations
//!
//! The callback has no recovered semantic identity, so Rust names and invokes
//! only its verified vtable slot. Target pointer words are four bytes; host
//! fixtures use native-width pointer and vtable entries to avoid truncation.

const CALLBACK_VTABLE_INDEX: usize = 1;
type VtableSlot4Callback = unsafe extern "C" fn(*mut u8);

/// Invokes vtable slot `+4` for the non-NULL object held by `slot`.
///
/// # Safety
///
/// `slot` must name a readable pointer. A non-NULL object must begin with a
/// readable vtable pointer whose second entry is callable with that object.
/// Stock code neither checks `slot` nor modifies it.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.optional_vtable_slot4_invoke")]
#[inline(never)]
pub unsafe extern "C" fn optional_vtable_slot4_invoke(slot: *mut *mut u8) -> *mut *mut u8 {
    let object = unsafe { slot.read() };
    if !object.is_null() {
        let vtable = unsafe { (object as *const *const usize).read() };
        let callback: VtableSlot4Callback = unsafe { core::mem::transmute(vtable.add(CALLBACK_VTABLE_INDEX).read()) };
        unsafe { callback(object) };
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

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        payload: u32,
    }

    unsafe extern "C" fn record_callback(object: *mut u8) {
        CALLBACK_CALLS.fetch_add(1, Ordering::SeqCst);
        CALLBACK_OBJECT.store(object as usize, Ordering::SeqCst);
    }

    #[test]
    fn null_object_returns_slot_without_reading_or_calling_vtable() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        let mut slot = core::ptr::null_mut();

        let result = unsafe { optional_vtable_slot4_invoke(&mut slot) };

        assert_eq!(result, core::ptr::addr_of_mut!(slot));
        assert!(slot.is_null());
        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn non_null_object_calls_second_vtable_entry_and_preserves_slot() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        CALLBACK_OBJECT.store(0, Ordering::SeqCst);
        let vtable = [0usize, record_callback as usize];
        let mut object = Object { vtable: vtable.as_ptr(), payload: 0xfeed_face };
        let mut slot = (&mut object as *mut Object).cast::<u8>();

        let result = unsafe { optional_vtable_slot4_invoke(&mut slot) };

        assert_eq!(result, core::ptr::addr_of_mut!(slot));
        assert_eq!(slot, (&mut object as *mut Object).cast::<u8>());
        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CALLBACK_OBJECT.load(Ordering::SeqCst), (&mut object as *mut Object) as usize);
        assert_eq!(object.payload, 0xfeed_face);
    }
}
