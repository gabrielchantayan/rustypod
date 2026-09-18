//! Destroy the owned object and observable-array members of a parent object.
//!
//! `owned_object_observable_array_destroy` — original: `FUN_081d2914` @
//! **0x081d2914**.
//!
//! **44 bytes**, `0x081d2914..0x081d2940`: raw `osos.dec` begins with
//! `push {r4,lr}` and ends with `pop {r4,pc}`; the next real function starts
//! at `0x081d2940` with `push {r4,r5,r6,lr}`. The four inbound direct callers
//! are plain `bl` instructions; there are no predicated direct `bl` callers.
//! The body has one direct `bl` to the ported
//! [`observable_array_owned_destroy`] and one predicated `blxne` through the
//! preceding object's vtable slot +4.
//!
//! # Algorithm
//!
//! Destroy and delete the owned observable array at `this + 0x50`, then, when
//! the preceding owned object at `this + 0x4c` is non-NULL, dispatch its
//! virtual destructor at vtable slot +4. Both member words remain untouched;
//! return the enclosing object. No deliberate deviations: host pointer fields
//! widen, but `repr(C)` retains their consecutive-word layout on ARM.

use super::observable_array::ObservableArray;
use super::observable_array_owned_destroy::observable_array_owned_destroy;
use super::polymorphic_owner_destroy::PolymorphicObject;

/// The known tail of the parent object, whose earlier fields are not accessed
/// by this destructor.
#[repr(C)]
pub struct OwnedObjectObservableArray {
    pub opaque_prefix: [u32; 19],
    /// Target offset +0x4c: nullable object dispatched through vtable slot +4.
    pub object: *mut PolymorphicObject,
    /// Target offset +0x50: nullable owned observable array.
    pub array: *mut ObservableArray,
}

/// Destroys the owned array, then the preceding polymorphic object, and
/// returns `this`.
///
/// Original: `FUN_081d2914` @ `0x081d2914` (44 bytes; 4 unconditional `bl`
/// call sites, no predicated direct calls).
///
/// # Safety
///
/// `this` must point to a live parent tail. Its array and object members, when
/// non-NULL, must respectively meet [`observable_array_owned_destroy`]'s and
/// the vtable destructor's safety contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_object_observable_array_destroy(
    this: *mut OwnedObjectObservableArray,
) -> *mut OwnedObjectObservableArray {
    let array_slot = core::ptr::addr_of_mut!((*this).array);
    observable_array_owned_destroy(array_slot);

    let object = (*this).object;
    if !object.is_null() {
        ((*(*object).vtable).destroy)(object);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::polymorphic_owner_destroy::PolymorphicObjectVTable;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use crate::cxx::observable_array::observable_array_construct;
    use parking_lot::Mutex;

    static DESTROYED_OBJECT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn record_destroy(object: *mut PolymorphicObject) {
        DESTROYED_OBJECT.store(object as usize, Ordering::Relaxed);
    }

    fn parent(
        object: *mut PolymorphicObject,
        array: *mut ObservableArray,
    ) -> OwnedObjectObservableArray {
        OwnedObjectObservableArray { opaque_prefix: [0; 19], object, array }
    }

    #[test]
    fn null_members_are_untouched_and_parent_is_returned() {
        let _lock = TEST_LOCK.lock();
        let mut value = parent(core::ptr::null_mut(), core::ptr::null_mut());
        DESTROYED_OBJECT.store(usize::MAX, Ordering::Relaxed);

        let returned = unsafe { owned_object_observable_array_destroy(&mut value) };

        assert!(core::ptr::eq(returned, &mut value));
        assert!(value.object.is_null());
        assert!(value.array.is_null());
        assert_eq!(DESTROYED_OBJECT.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn destroys_preceding_object_after_null_array_slot() {
        let _lock = TEST_LOCK.lock();
        let vtable = PolymorphicObjectVTable { unknown_slot_0: 0, destroy: record_destroy };
        let mut object = PolymorphicObject { vtable: &vtable };
        let mut value = parent(&mut object, core::ptr::null_mut());
        DESTROYED_OBJECT.store(0, Ordering::Relaxed);

        let returned = unsafe { owned_object_observable_array_destroy(&mut value) };

        assert!(core::ptr::eq(returned, &mut value));
        assert_eq!(DESTROYED_OBJECT.load(Ordering::Relaxed), &mut object as *mut _ as usize);
        assert!(core::ptr::eq(value.object, &mut object));
    }

    #[test]
    fn destroys_array_before_dispatching_preceding_object() {
        let _lock = TEST_LOCK.lock();
        let _heap = crate::heap::veneers::tests::mock_heap();
        let vtable = PolymorphicObjectVTable { unknown_slot_0: 0, destroy: record_destroy };
        let mut object = PolymorphicObject { vtable: &vtable };
        let mut array = ObservableArray {
            base: crate::cxx::observable_array::FrameworkObject { vtable: 0 },
            len: 0,
            storage: 0,
            observers: 0,
        };
        unsafe { observable_array_construct(&mut array) };
        let mut value = parent(&mut object, &mut array);
        DESTROYED_OBJECT.store(0, Ordering::Relaxed);

        unsafe { owned_object_observable_array_destroy(&mut value) };

        assert_eq!(DESTROYED_OBJECT.load(Ordering::Relaxed), &mut object as *mut _ as usize);
        assert_eq!(
            crate::heap::veneers::tests::free_log(),
            (1, core::ptr::addr_of_mut!(array).cast::<u8>(), 2),
            "the array is tag-2 deleted before the object dispatch"
        );
        assert!(core::ptr::eq(value.array, &mut array));
    }
}
