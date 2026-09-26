//! Replaces a polymorphic object member — `FUN_083e72f8` @ **0x083e72f8**.
//!
//! Raw `osos.dec` establishes the true 48-byte extent: twelve ARM words from
//! `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at 0x083e7324; the next
//! function begins with `push {r4,lr}` at 0x083e7328. The body has zero plain
//! direct `bl` calls and one predicated indirect `blxne` through vtable slot
//! `+4`. Whole-image decoding finds two inbound plain direct `bl` sites,
//! 0x0815f14c and 0x0815f198, with no predicated direct callers.
//!
//! # Algorithm
//!
//! Loads the member's old object. If it differs from `replacement`, a non-NULL
//! old object receives its vtable slot `+4` callback, then the member is
//! updated. Equal pointers do not call or write. The callback's concrete
//! identity is unrecovered and deliberately not inferred.
//!
//! # Deliberate deviation
//!
//! RetailOS vtable entries are four-byte target pointers; host tests need
//! native-width function pointers, so this port uses native-width entries.

const CALLBACK_VTABLE_INDEX: usize = 1;
type VtableSlot4Callback = unsafe extern "C" fn(*mut u8);

/// Replaces a polymorphic member after releasing its distinct old object.
///
/// # Safety
///
/// `member` must be writable and contain either NULL or an object beginning
/// with a readable vtable whose second entry is callable with that object.
/// `replacement` is stored without validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.polymorphic_member_replace")]
#[inline(never)]
pub unsafe extern "C" fn polymorphic_member_replace(member: *mut *mut u8, replacement: *mut u8) {
    let old_object = unsafe { member.read() };
    if old_object != replacement {
        if !old_object.is_null() {
            let vtable = unsafe { (old_object as *const *const usize).read() };
            let callback: VtableSlot4Callback = unsafe { core::mem::transmute(vtable.add(CALLBACK_VTABLE_INDEX).read()) };
            unsafe { callback(old_object) };
        }
        unsafe { member.write(replacement) };
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
    fn replaces_null_member_without_reading_a_vtable() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        let mut replacement = 0u8;
        let mut member = core::ptr::null_mut();

        unsafe { polymorphic_member_replace(&mut member, core::ptr::addr_of_mut!(replacement)) };

        assert_eq!(member, core::ptr::addr_of_mut!(replacement));
        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn equal_pointer_skips_callback_and_store() {
        let _lock = TEST_LOCK.lock();
        CALLBACK_CALLS.store(0, Ordering::SeqCst);
        let vtable = [0usize, record_callback as usize];
        let mut object = Object { vtable: vtable.as_ptr(), payload: 0xfeed_face };
        let mut member = (&mut object as *mut Object).cast::<u8>();

        unsafe { polymorphic_member_replace(&mut member, member) };

        assert_eq!(member, (&mut object as *mut Object).cast::<u8>());
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
        let mut member = (&mut old_object as *mut Object).cast::<u8>();

        unsafe { polymorphic_member_replace(&mut member, core::ptr::addr_of_mut!(replacement)) };

        assert_eq!(CALLBACK_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CALLBACK_OBJECT.load(Ordering::SeqCst), (&mut old_object as *mut Object) as usize);
        assert_eq!(member, core::ptr::addr_of_mut!(replacement));
        assert_eq!(old_object.payload, 0xfeed_face);
    }
}
