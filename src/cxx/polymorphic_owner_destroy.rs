//! Destroy a nullable owned polymorphic object.
//!
//! `polymorphic_owner_destroy` — original: `FUN_081fd554` @ `0x081fd554`
//! (36 bytes; nine ARM words). Raw `osos.dec` establishes the exact extent:
//! `stmdb sp!, {r4,lr}` at `0x081fd554` through `ldmia sp!, {r4,pc}` at
//! `0x081fd574`; the next real function starts at `0x081fd578`.
//!
//! Four inbound direct call sites are plain unconditional `bl` instructions;
//! there are no predicated inbound `bl` forms. The body itself has no plain
//! `bl`: its sole call is the predicated `blxne` through the owned object's
//! vtable slot +4.
//!
//! Algorithm: save the owner pointer, load its object word, and when non-null
//! call the object's virtual destructor at vtable slot +4. Return the owner
//! unchanged. Deliberate deviation: the target's two pointer words are native
//! pointers in the host model, so their host offsets widen; `repr(C)` preserves
//! the two consecutive 32-bit words on ARM.

/// A virtual destructor at vtable slot +4.
pub type PolymorphicObjectDestroy = unsafe extern "C" fn(*mut PolymorphicObject);

/// The two decoded vtable words used by this destructor.
#[repr(C)]
pub struct PolymorphicObjectVTable {
    pub unknown_slot_0: usize,
    pub destroy: PolymorphicObjectDestroy,
}

/// The object reached through the owner's first word.
#[repr(C)]
pub struct PolymorphicObject {
    pub vtable: *const PolymorphicObjectVTable,
}

/// The one-word owner whose nullable object is destroyed.
#[repr(C)]
pub struct PolymorphicOwner {
    pub object: *mut PolymorphicObject,
}

/// Calls the nullable owned object's vtable-slot-+4 destructor and returns
/// `owner` unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn polymorphic_owner_destroy(
    owner: *mut PolymorphicOwner,
) -> *mut PolymorphicOwner {
    let object = (*owner).object;
    if !object.is_null() {
        ((*(*object).vtable).destroy)(object);
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static DESTROYED_OBJECT: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());


    unsafe extern "C" fn record_destroy(object: *mut PolymorphicObject) {
        DESTROYED_OBJECT.store(object as usize, Ordering::Relaxed);
    }

    #[test]
    fn null_object_returns_owner_without_dispatch() {
        let _lock = TEST_LOCK.lock();
        let mut owner = PolymorphicOwner { object: core::ptr::null_mut() };
        DESTROYED_OBJECT.store(usize::MAX, Ordering::Relaxed);

        assert!(core::ptr::eq(unsafe { polymorphic_owner_destroy(&mut owner) }, &mut owner));
        assert_eq!(DESTROYED_OBJECT.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn dispatches_slot_four_on_owned_object_and_preserves_owner() {
        let _lock = TEST_LOCK.lock();
        let vtable = PolymorphicObjectVTable { unknown_slot_0: 0, destroy: record_destroy };
        let mut object = PolymorphicObject { vtable: &vtable };
        let mut owner = PolymorphicOwner { object: &mut object };
        DESTROYED_OBJECT.store(0, Ordering::Relaxed);

        assert!(core::ptr::eq(unsafe { polymorphic_owner_destroy(&mut owner) }, &mut owner));
        assert_eq!(DESTROYED_OBJECT.load(Ordering::Relaxed), &mut object as *mut _ as usize);
    }
}
