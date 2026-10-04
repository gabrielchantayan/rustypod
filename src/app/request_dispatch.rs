use core::ptr::{addr_of_mut, read_volatile};
use crate::app::registry::{registry_lookup_by_id, object_cast_to_class, FrameworkObject};
use crate::kernel::sync_mutex::{CountedMutex, mutex_lock_counted, mutex_unlock_counted};
use crate::util::table_find::{RequestSlot, table6_find_by_key, table6_request_state};

#[repr(C)]
pub struct RequestOwner {
    pub prefix: [u32; 10],
    pub data: *mut RequestData,
}

#[repr(C)]
pub struct RequestData {
    pub prefix: [u32; 15],
    pub slots: *mut RequestSlot,
    pub lock: CountedMutex,
}

#[repr(C)]
pub struct RequestTargetVtable {
    pub prefix: [usize; 40],
    pub dispatch: unsafe extern "C" fn(*mut RequestTarget, *mut RequestOwner, u32),
}

#[repr(C)]
pub struct RequestTarget {
    pub vtable: *const RequestTargetVtable,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(RequestOwner, data) == 0x28);
    assert!(core::mem::offset_of!(RequestData, slots) == 0x3c);
    assert!(core::mem::offset_of!(RequestData, lock) == 0x40);
    assert!(core::mem::offset_of!(RequestTargetVtable, dispatch) == 0xa0);
};

/// Dispatch an idle registered request — FUN_08202694 @ 0x08202694.
/// True extent: 192 bytes, next function at 0x08202754. Raw-image counts:
/// two inbound plain BLs, eight outgoing plain BLs, zero predicated BLs,
/// one virtual BLX and a tail B to mutex_unlock_counted.
///
/// Under the owner's counted lock, skip nonzero request states; otherwise
/// mark a matching slot running (1), unlock, resolve the key in the class
/// registry and cast to class 0x2480. A successful target receives owner
/// and payload at vtable +0xa0. Reacquire the freshly loaded owner's lock,
/// but search the original slot-table handle, and mark a matching slot done
/// (2). Failed resolution leaves state 1; missing slots still dispatch.
/// Deviation: repr(C) pointer fields widen on hosts; LLVM inlines counted
/// acquisition and unrolls both six-slot lookups (101 vs 48 instructions).
/// No extra null checks, state validation, or retry semantics.
///
/// # Safety
/// Owner, data and six-slot table must remain valid across the callback.
/// Registry objects and their vtables must satisfy the existing registry
/// contracts; the callback may replace owner.data, but not destroy the old
/// data while this operation retains its table handle.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn request_dispatch(owner: *mut RequestOwner, key: u32, payload: u32) {
    let data = read_volatile(addr_of_mut!((*owner).data));
    let table = addr_of_mut!((*data).slots);
    let mut lock = addr_of_mut!((*data).lock);
    mutex_lock_counted(lock);
    if table6_request_state(table, key) == 0 {
        let slot = table6_find_by_key(table, key);
        if !slot.is_null() { (*slot).state = 1; }
        mutex_unlock_counted(lock);
        let object = registry_lookup_by_id(key);
        if object.is_null() { return; }
        let target = object_cast_to_class(object as *mut FrameworkObject, 0x2480) as *mut RequestTarget;
        if target.is_null() { return; }
        let vtable = read_volatile(addr_of_mut!((*target).vtable));
        ((*vtable).dispatch)(target, owner, payload);
        let current_data = read_volatile(addr_of_mut!((*owner).data));
        lock = addr_of_mut!((*current_data).lock);
        mutex_lock_counted(lock);
        let slot = table6_find_by_key(table, key);
        if !slot.is_null() { (*slot).state = 2; }
    }
    mutex_unlock_counted(lock);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::registry::*;
    use crate::kernel::sync_mutex::Mutex;
    use core::ptr;

    unsafe extern "C" fn insert(_: *mut Registry, _: *const RegistryEntry) -> usize { 0 }
    unsafe extern "C" fn assign(_: *mut Registry, _: i32, _: *const RegistryEntry) -> usize { 0 }
    unsafe extern "C" fn notify(_: *mut Registry) -> *mut u8 { ptr::null_mut() }
    unsafe extern "C" fn index(registry: *mut Registry, _: *const u32) -> i32 {
        if (*registry).container[0] == 0 { -1 } else { 0 }
    }
    unsafe extern "C" fn entry(registry: *mut Registry, _: i32, out: *mut RegistryEntry) -> *mut RegistryEntry {
        out.write(RegistryEntry { class_id: 7, instance: (*registry).container[0] as *mut u8 });
        out
    }
    static REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7], insert, unresolved_20: 0, assign_at: assign,
        unresolved_28: [0; 5], entry_at: entry, unresolved_40: [0; 3], index_of: index,
        unresolved_50: [0; 4], has_pending_changes: notify, notify_deferred: notify, notify_changed: notify,
    };
    #[repr(C)]
    struct Object { base: FrameworkObject, target: *mut RequestTarget }
    unsafe extern "C" fn cast(object: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, 0x2480);
        (*(object as *mut Object)).target as *mut u8
    }
    static OBJECT_VTABLE: FrameworkObjectVtable = FrameworkObjectVtable {
        unresolved_00: [0; 5], cast_to_class: cast,
    };
    #[repr(C)]
    struct Target {
        base: RequestTarget,
        calls: u32,
        replacement: *mut RequestData,
        expected_state: u8,
    }
    unsafe extern "C" fn dispatch(target: *mut RequestTarget, owner: *mut RequestOwner, payload: u32) {
        let target = &mut *(target as *mut Target);
        assert_eq!(payload, 0xfeed);
        let data = &mut *(*owner).data;
        assert_eq!(data.lock.hold_count, 0);
        assert_eq!((*data.slots).state, target.expected_state);
        target.calls += 1;
        if !target.replacement.is_null() { (*owner).data = target.replacement; }
    }
    static TARGET_VTABLE: RequestTargetVtable = RequestTargetVtable { prefix: [0; 40], dispatch };

    fn data(slots: *mut RequestSlot) -> RequestData {
        RequestData { prefix: [0; 15], slots, lock: CountedMutex {
            mutex: Mutex { sem_cell: ptr::null_mut(), unused: 0 }, hold_count: 0,
        } }
    }

    #[test]
    fn request_state_transitions_and_resolution_failures() {
        let _guard = crate::testing::CLASS_REGISTRY_TEST_LOCK.lock().unwrap();
        unsafe {
            let registry = addr_of_mut!(CLASS_REGISTRY);
            let saved = registry.read();
            (*registry).vtable = &REGISTRY_VTABLE;
            let mut slots = core::array::from_fn::<_, 6, _>(|i| RequestSlot {
                key: 7 + i as u32, state: 0, reserved: [0xa5; 3],
            });
            let mut old = data(slots.as_mut_ptr());
            let mut other_slots = core::array::from_fn::<_, 6, _>(|i| RequestSlot {
                key: 7 + i as u32, state: 0, reserved: [0x5a; 3],
            });
            let mut replacement = data(other_slots.as_mut_ptr());
            let mut owner = RequestOwner { prefix: [0; 10], data: &mut old };
            let mut target = Target { base: RequestTarget { vtable: &TARGET_VTABLE },
                calls: 0, replacement: ptr::null_mut(), expected_state: 1 };
            let mut object = Object { base: FrameworkObject { vtable: &OBJECT_VTABLE }, target: &mut target.base };
            (*registry).container[0] = &mut object as *mut Object as usize;
            for state in [1, 2, 0xff] {
                slots[0].state = state;
                request_dispatch(&mut owner, 7, 0xfeed);
                assert_eq!(slots[0].state, state);
                assert_eq!(target.calls, 0);
                assert_eq!(old.lock.hold_count, 0);
            }
            slots[0].state = 0;
            (*registry).container[0] = 0;
            request_dispatch(&mut owner, 7, 0xfeed);
            assert_eq!(slots[0].state, 1);
            assert_eq!(old.lock.hold_count, 0);
            slots[0].state = 0;
            (*registry).container[0] = &mut object as *mut Object as usize;
            object.target = ptr::null_mut();
            request_dispatch(&mut owner, 7, 0xfeed);
            assert_eq!(slots[0].state, 1);
            assert_eq!(old.lock.hold_count, 0);
            assert_eq!(target.calls, 0);
            object.target = &mut target.base;
            slots[0].state = 0;
            target.replacement = &mut replacement;
            request_dispatch(&mut owner, 7, 0xfeed);
            assert_eq!(target.calls, 1);
            assert_eq!(slots[0].state, 2);
            assert_eq!(other_slots[0].state, 0);
            assert_eq!(old.lock.hold_count, 0);
            assert_eq!(replacement.lock.hold_count, 0);
            owner.data = &mut old;
            target.replacement = ptr::null_mut();
            target.expected_state = 2;
            request_dispatch(&mut owner, 99, 0xfeed);
            assert_eq!(target.calls, 2);
            assert_eq!(slots[0].state, 2);
            assert!(slots.iter().all(|s| s.reserved == [0xa5; 3]));
            assert_eq!(old.lock.hold_count, 0);
            registry.write(saved);
        }
    }
}
