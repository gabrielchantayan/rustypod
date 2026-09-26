//! Replaces an optional polymorphic object pointer — `FUN_083e734c` @
//! 0x083e734c.
//!
//! Raw `osos.dec` establishes the true 48-byte extent from `push
//! {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at 0x083e7378; `push
//! {r4,lr}` at 0x083e737c starts the next real function. The body has zero
//! plain direct `bl` calls and one predicated indirect `blxne` through vtable
//! slot `+4`. Whole-image decoding finds two inbound plain direct `bl` sites
//! (0x081dd1d0 and 0x081e871c), with no predicated direct callers.
//!
//! Algorithm: load `slot`'s old object; if it differs from `replacement`,
//! invoke the old non-NULL object's vtable `+4` callback, then store the
//! replacement. Equal pointers leave the slot unchanged and make no callback.
//! Deliberate deviation: the callback has no recovered semantic identity, so
//! Rust names only its verified vtable role. Host vtable entries use native
//! pointer width rather than retailOS's four-byte words.

const CALLBACK_VTABLE_INDEX: usize = 1;
type VtableSlot4Callback = unsafe extern "C" fn(*mut u8);

/// Replaces `slot` after releasing its distinct, non-NULL polymorphic object.
///
/// # Safety
///
/// `slot` must be writable and contain either NULL or an object beginning with
/// a readable vtable whose second entry is callable with that object. The
/// replacement pointer is stored without validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.polymorphic_slot_replace")]
#[inline(never)]
pub unsafe extern "C" fn polymorphic_slot_replace(slot: *mut *mut u8, replacement: *mut u8) {
    let old_object = unsafe { slot.read() };
    if old_object != replacement {
        if !old_object.is_null() {
            let vtable = unsafe { (old_object as *const *const usize).read() };
            let callback: VtableSlot4Callback = unsafe { core::mem::transmute(vtable.add(CALLBACK_VTABLE_INDEX).read()) };
            unsafe { callback(old_object) };
        }
        unsafe { slot.write(replacement) };
    }
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
    fn replaces_null_slot_without_reading_a_vtable() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        let mut replacement = 0u8;
        let mut slot = core::ptr::null_mut();

        unsafe { polymorphic_slot_replace(&mut slot, core::ptr::addr_of_mut!(replacement)) };

        assert_eq!(slot, core::ptr::addr_of_mut!(replacement));
        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn equal_pointer_skips_callback_and_store() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        let vtable = [0usize, record_callback as usize];
        let mut object = Object { vtable: vtable.as_ptr(), payload: 0xfeed_face };
        let mut slot = (&mut object as *mut Object).cast::<u8>();

        unsafe { polymorphic_slot_replace(&mut slot, slot) };

        assert_eq!(slot, (&mut object as *mut Object).cast::<u8>());
        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn releases_distinct_old_object_before_storing_replacement() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        CALLBACK_OBJECT.store(0, Ordering::SeqCst);
        let vtable = [0usize, record_callback as usize];
        let mut old_object = Object { vtable: vtable.as_ptr(), payload: 0xfeed_face };
        let mut replacement = 0u8;
        let mut slot = (&mut old_object as *mut Object).cast::<u8>();

        unsafe { polymorphic_slot_replace(&mut slot, core::ptr::addr_of_mut!(replacement)) };

        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CALLBACK_OBJECT.load(Ordering::SeqCst), (&mut old_object as *mut Object) as usize);
        assert_eq!(slot, core::ptr::addr_of_mut!(replacement));
        assert_eq!(old_object.payload, 0xfeed_face);
    }
}
