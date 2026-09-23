//! `registration_slot_release` — retailOS `FUN_081d9918` at `0x081d9918`.
//!
//! Raw `osos.dec` establishes the 108-byte extent `0x081d9918..0x081d9984`;
//! the next independently entered function begins with `push {r3-r7,lr}` at
//! `0x081d9984`. There are three inbound direct `bl` callers: one plain `bl`
//! at `0x081d9ab8` and two predicated `blne` calls at `0x081d9750` and
//! `0x081d9880`.
//!
//! A valid index selects one of 32 twenty-byte manager slots, locks its mutex
//! at `+0x0c` through the lock wrapper at `0x08228360`, and releases the slot
//! object's signed reference count. The final release clears the object and
//! state byte before dispatching the object's vtable slot `+0x04`; it then
//! stores the decremented count and tail-branches through the corresponding
//! unlock wrapper. Deliberate deviation: wrapper calls go directly through
//! ported mutex helpers, and host vtables use native-width function pointers.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const SLOT_COUNT: u32 = 32;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RegistrationSlot {
    pub opaque: u32,
    pub object: *mut RegistrationSlotObject,
    pub state: u8,
    pub padding: [u8; 3],
    pub lock: Mutex,
    pub refcount: i32,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RegistrationSlotManager {
    pub slots: [RegistrationSlot; SLOT_COUNT as usize],
    pub padding: [u32; 3],
    pub lock: Mutex,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RegistrationSlotVtable {
    pub reserved: usize,
    pub release: unsafe extern "C" fn(*mut RegistrationSlotObject),
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RegistrationSlotObject {
    pub vtable: *const RegistrationSlotVtable,
}

/// Releases a manager slot reference when `slot_index` is in 0..32.
///
/// # Safety
///
/// A valid `slot_index` requires `manager` to reference a live manager table.
/// A final release requires a valid object and release vtable slot. Stock code
/// provides no further validation.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn registration_slot_release(manager: *mut RegistrationSlotManager, slot_index: u32) {
    if slot_index >= SLOT_COUNT {
        return;
    }
    let slot = &mut (*manager).slots[slot_index as usize];
    mutex_lock(&mut slot.lock);
    if !slot.object.is_null() && slot.refcount != 0 {
        let refcount = slot.refcount.wrapping_sub(1);
        if refcount == 0 {
            let object = slot.object;
            slot.object = core::ptr::null_mut();
            slot.state = 0;
            ((*(*object).vtable).release)(object);
        }
        slot.refcount = refcount;
    }
    mutex_unlock(&mut slot.lock);
}

#[cfg(target_os = "none")]
#[repr(C)]
pub struct RegistrationSlotManager {
    _opaque: [u8; 0],
}

#[cfg(target_os = "none")]
#[repr(C)]
pub struct RegistrationSlotObject {
    pub vtable: *const u32,
}

#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_slot_release(manager: *mut RegistrationSlotManager, slot_index: u32) {
    if slot_index >= SLOT_COUNT {
        return;
    }
    let slot = manager.cast::<u8>().add(slot_index as usize * 0x14);
    mutex_lock(slot.add(0x0c).cast::<Mutex>());
    let object = slot.add(4).cast::<*mut RegistrationSlotObject>().read();
    let refcount = slot.add(0x14).cast::<i32>().read();
    if !object.is_null() && refcount != 0 {
        let refcount = refcount.wrapping_sub(1);
        if refcount == 0 {
            slot.add(4).cast::<u32>().write(0);
            slot.add(8).write(0);
            let release: unsafe extern "C" fn(*mut RegistrationSlotObject) =
                core::mem::transmute((*object).vtable.add(1).read());
            release(object);
        }
        slot.add(0x14).cast::<i32>().write(refcount);
    }
    mutex_unlock(slot.add(0x0c).cast::<Mutex>());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex as HostMutex;

    static CALL_LOCK: HostMutex<()> = HostMutex::new(());
    static mut RELEASED: *mut RegistrationSlotObject = core::ptr::null_mut();

    unsafe extern "C" fn record_release(object: *mut RegistrationSlotObject) {
        addr_of_mut!(RELEASED).write(object);
    }

    fn empty_manager() -> RegistrationSlotManager { unsafe { core::mem::zeroed() } }

    #[test]
    fn out_of_range_index_does_not_dereference_manager() {
        unsafe { registration_slot_release(core::ptr::null_mut(), SLOT_COUNT) };
    }

    #[test]
    fn null_object_and_zero_refcount_do_not_dispatch() {
        let _guard = CALL_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe { addr_of_mut!(RELEASED).write(core::ptr::null_mut()) };
        let mut manager = empty_manager();
        manager.slots[0].refcount = 0;
        unsafe { registration_slot_release(&mut manager, 0) };
        assert!(manager.slots[0].object.is_null());
        assert!(unsafe { addr_of!(RELEASED).read().is_null() });
    }

    #[test]
    fn final_release_clears_slot_before_vtable_dispatch() {
        let _guard = CALL_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe { addr_of_mut!(RELEASED).write(core::ptr::null_mut()) };
        let vtable = RegistrationSlotVtable { reserved: 0, release: record_release };
        let mut object = RegistrationSlotObject { vtable: &vtable };
        let mut manager = empty_manager();
        manager.slots[3].object = &mut object;
        manager.slots[3].state = 4;
        manager.slots[3].refcount = 1;
        unsafe { registration_slot_release(&mut manager, 3) };
        assert!(manager.slots[3].object.is_null());
        assert_eq!(manager.slots[3].state, 0);
        assert_eq!(manager.slots[3].refcount, 0);
        assert!(core::ptr::eq(unsafe { addr_of!(RELEASED).read() }, &mut object));
    }
}
