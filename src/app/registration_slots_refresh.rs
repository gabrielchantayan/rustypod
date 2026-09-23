//! `registration_slots_refresh` — retailOS `FUN_081d9810` at `0x081d9810`.
//!
//! Raw `osos.dec` establishes the 168-byte extent `0x081d9810..0x081d98b8`:
//! the next independently entered function starts with `push {r4-r7,lr}` at
//! `0x081d98b8`. Verified call count: three plain `bl` (two lock-service
//! calls and one unlock-service call), one predicated `blne` to
//! `registration_slot_release`, and one indirect `blx` through vtable slot
//! `+0x44`.
//!
//! It locks the manager, walks all 32 twenty-byte registration slots, and
//! locks each slot while inspecting state `2`. A NULL object clears that state.
//! Otherwise vtable slot `+0x44` decides whether the state becomes `4` and the
//! slot reference is released. It unlocks every slot and returns success only
//! when the final manager unlock succeeds. Deliberate deviations: ported mutex
//! helpers replace the service wrappers; host vtables use native-width entries.

#[cfg(not(target_os = "none"))]
use crate::app::registration_slot_release::{registration_slot_release, RegistrationSlotManager};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock};
#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::Mutex;

const SLOT_COUNT: usize = 32;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RegistrationRefreshVtable {
    pub reserved: usize,
    pub release: unsafe extern "C" fn(*mut RegistrationRefreshObject),
    pub padding: [usize; 15],
    pub can_release: unsafe extern "C" fn(*mut RegistrationRefreshObject) -> u32,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RegistrationRefreshObject {
    pub vtable: *const RegistrationRefreshVtable,
}

/// Refreshes state-two registration slots and returns zero.
///
/// # Safety
///
/// `manager` must reference a manager with live mutexes. Every non-NULL slot
/// object in state two must begin with a vtable whose slot `+0x44` is callable.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn registration_slots_refresh(manager: *mut RegistrationSlotManager) -> u32 {
    mutex_lock(&mut (*manager).lock);
    for slot_index in 0..SLOT_COUNT {
        let slot = &mut (*manager).slots[slot_index];
        mutex_lock(&mut slot.lock);
        if slot.state == 2 {
            if slot.object.is_null() {
                slot.state = 0;
            } else {
                let object = slot.object.cast::<RegistrationRefreshObject>();
                if ((*(*object).vtable).can_release)(object) != 0 {
                    slot.state = 4;
                    registration_slot_release(manager, slot_index as u32);
                }
            }
        }
        mutex_unlock(&mut slot.lock);
    }
    mutex_unlock(&mut (*manager).lock);
    0
}

#[cfg(target_os = "none")]
#[repr(C)]
pub struct RegistrationSlotManagerOpaque {
    _opaque: [u8; 0],
}

#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_slots_refresh(manager: *mut RegistrationSlotManagerOpaque) -> u32 {
    let manager_bytes = manager.cast::<u8>();
    mutex_lock(manager_bytes.add(0x29c).cast::<Mutex>());
    for slot_index in 0..SLOT_COUNT {
        let slot = manager_bytes.add(slot_index * 0x14);
        mutex_lock(slot.add(0x0c).cast::<Mutex>());
        if slot.add(8).read() == 2 {
            let object = slot.add(4).cast::<*mut u32>().read();
            if object.is_null() {
                slot.add(8).write(0);
            } else {
                let vtable = object.read() as *const u32;
                let can_release: unsafe extern "C" fn(*mut u32) -> u32 =
                    core::mem::transmute(vtable.add(17).read());
                if can_release(object) != 0 {
                    slot.add(8).write(4);
                    super::registration_slot_release::registration_slot_release(manager.cast(), slot_index as u32);
                }
            }
        }
        mutex_unlock(slot.add(0x0c).cast::<Mutex>());
    }
    mutex_unlock(manager_bytes.add(0x29c).cast::<Mutex>());
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::registration_slot_release::RegistrationSlotObject;
    use core::mem::zeroed;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASES: AtomicUsize = AtomicUsize::new(0);
    static PREDICATES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release(_object: *mut RegistrationSlotObject) {
        RELEASES.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn reject(_object: *mut RegistrationRefreshObject) -> u32 {
        PREDICATES.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn accept(_object: *mut RegistrationRefreshObject) -> u32 {
        PREDICATES.fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe fn manager() -> RegistrationSlotManager {
        zeroed()
    }

    #[test]
    fn clears_null_state_two_slot_without_predicate() {
        let mut manager = unsafe { manager() };
        manager.slots[3].state = 2;
        PREDICATES.store(0, Ordering::SeqCst);

        assert_eq!(unsafe { registration_slots_refresh(&mut manager) }, 0);
        assert_eq!(manager.slots[3].state, 0);
        assert_eq!(PREDICATES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn retains_slot_when_predicate_rejects() {
        let vtable = RegistrationRefreshVtable {
            reserved: 0,
            release: unsafe { core::mem::transmute(release as unsafe extern "C" fn(*mut RegistrationSlotObject)) },
            padding: [0; 15],
            can_release: reject,
        };
        let mut object = RegistrationRefreshObject { vtable: &vtable };
        let mut manager = unsafe { manager() };
        manager.slots[7].object = (&mut object as *mut RegistrationRefreshObject).cast();
        manager.slots[7].state = 2;
        manager.slots[7].refcount = 2;
        PREDICATES.store(0, Ordering::SeqCst);

        assert_eq!(unsafe { registration_slots_refresh(&mut manager) }, 0);
        assert_eq!(manager.slots[7].state, 2);
        assert_eq!(manager.slots[7].refcount, 2);
        assert_eq!(PREDICATES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn accepts_and_releases_slot() {
        let vtable = RegistrationRefreshVtable {
            reserved: 0,
            release: unsafe { core::mem::transmute(release as unsafe extern "C" fn(*mut RegistrationSlotObject)) },
            padding: [0; 15],
            can_release: accept,
        };
        let mut object = RegistrationRefreshObject { vtable: &vtable };
        let mut manager = unsafe { manager() };
        manager.slots[11].object = (&mut object as *mut RegistrationRefreshObject).cast();
        manager.slots[11].state = 2;
        manager.slots[11].refcount = 1;
        PREDICATES.store(0, Ordering::SeqCst);
        RELEASES.store(0, Ordering::SeqCst);

        assert_eq!(unsafe { registration_slots_refresh(&mut manager) }, 0);
        assert_eq!(manager.slots[11].state, 0);
        assert!(manager.slots[11].object.is_null());
        assert_eq!(manager.slots[11].refcount, 0);
        assert_eq!(PREDICATES.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
    }
}
