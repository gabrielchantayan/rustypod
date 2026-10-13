//! Destroy a half-open range of nullable polymorphic owners.
//!
//! Original: `FUN_083e2a1c` @ `0x083e2a1c`, 40 bytes, ending with the
//! pop at `0x083e2a40` before the next function's push at `0x083e2a44`.
//! Verified raw A32 calls: one outgoing plain BL to `0x081fd554`, zero
//! predicated BLs; one inbound plain BL at `0x083e2bd4`, zero predicated BLs.
//! Walk first to last in ascending order, calling polymorphic_owner_destroy
//! for every owner, including null objects. The context in r0 is unused.
//! Deliberate deviation: native-pointer owner fields widen the host stride;
//! on ARM each owner and each loop increment remain exactly four bytes.

use super::polymorphic_owner_destroy::{polymorphic_owner_destroy, PolymorphicOwner};

/// Destroy each owner in `[first, last)` without modifying the owner slots.
///
/// # Safety
/// The endpoints must delimit one valid owner array in ascending order.
/// Each non-null object must satisfy `polymorphic_owner_destroy`'s virtual
/// dispatch requirements. Destructors must leave the remaining range valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn polymorphic_owner_range_destroy(
    _context: *mut core::ffi::c_void,
    mut first: *mut PolymorphicOwner,
    last: *mut PolymorphicOwner,
) {
    while first != last {
        polymorphic_owner_destroy(first);
        first = first.add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::polymorphic_owner_destroy::{PolymorphicObject, PolymorphicObjectVTable};
    use parking_lot::Mutex;

    static DESTROYED: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn record_destroy(object: *mut PolymorphicObject) {
        DESTROYED.lock().push(object as usize);
    }

    #[test]
    fn empty_null_range_does_not_access_memory() {
        unsafe {
            polymorphic_owner_range_destroy(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
        }
    }

    #[test]
    fn mixed_range_dispatches_in_order_and_excludes_endpoints() {
        let _lock = TEST_LOCK.lock();
        DESTROYED.lock().clear();
        let vtable = PolymorphicObjectVTable { unknown_slot_0: 0, destroy: record_destroy };
        let mut objects = [
            PolymorphicObject { vtable: &vtable },
            PolymorphicObject { vtable: &vtable },
            PolymorphicObject { vtable: &vtable },
            PolymorphicObject { vtable: &vtable },
        ];
        let mut owners = [
            PolymorphicOwner { object: &mut objects[0] },
            PolymorphicOwner { object: &mut objects[1] },
            PolymorphicOwner { object: core::ptr::null_mut() },
            PolymorphicOwner { object: &mut objects[2] },
            PolymorphicOwner { object: &mut objects[3] },
        ];
        let before = owners.each_ref().map(|owner| owner.object);
        unsafe {
            let begin = owners.as_mut_ptr();
            polymorphic_owner_range_destroy(core::ptr::null_mut(), begin.add(1), begin.add(4));
        }
        assert_eq!(*DESTROYED.lock(), [before[1] as usize, before[3] as usize]);
        assert_eq!(owners.each_ref().map(|owner| owner.object), before);
    }

    #[test]
    fn singleton_range_destroys_exactly_one_owner() {
        let _lock = TEST_LOCK.lock();
        DESTROYED.lock().clear();
        let vtable = PolymorphicObjectVTable { unknown_slot_0: 0, destroy: record_destroy };
        let mut object = PolymorphicObject { vtable: &vtable };
        let mut owner = PolymorphicOwner { object: &mut object };
        unsafe {
            let first = &mut owner as *mut PolymorphicOwner;
            polymorphic_owner_range_destroy(core::ptr::null_mut(), first, first.add(1));
        }
        assert_eq!(*DESTROYED.lock(), [&mut object as *mut _ as usize]);
    }
}
