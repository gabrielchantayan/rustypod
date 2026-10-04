//! Slot completion poll, FUN_081d9760 @ 0x081d9760.
//! True size 176 bytes, ending at the next prologue at 0x081d9810.
//! Raw A32 decoding: two inbound plain BLs (0x081af6c0, 0x081c886c),
//! four outbound plain BLs, zero predicated BLs, two indirect BLX sites.
//! Lock the indexed twenty-byte slot. For a non-null object in state one,
//! call vtable +0x38 with the object as this. Nonzero returns one without
//! changing state; zero changes state to two and optionally reports the
//! object's two payload words after unlocking. All other paths return zero.
//! Deliberate deviations: repr(C) pointer fields widen on hosts; target
//! offsets remain exact. Reuses ported lock adapters; no new callee seams.

use core::ffi::c_void;
use crate::app::lock_service::{lock_service_lock, lock_service_unlock};
use crate::kernel::sync_mutex::Mutex;

#[repr(C)]
pub struct CompletionVtable {
    pub preceding: [usize; 14],
    pub poll: unsafe extern "C" fn(*mut CompletionObject) -> i32,
}

#[repr(C)]
pub struct CompletionObject {
    pub vtable: *const CompletionVtable,
    pub reserved: u32,
    pub payload: [u32; 2],
}

#[repr(C)]
pub struct CompletionSlot {
    pub reserved: u32,
    pub object: *mut CompletionObject,
    pub state: u8,
    pub padding: [u8; 3],
    pub mutex: Mutex,
}

pub type CompletionCallback = unsafe extern "C" fn(u32, u32, *mut c_void);

#[repr(C)]
pub struct CompletionManager {
    pub slots: [CompletionSlot; 32],
    pub reserved: [u32; 3],
    pub lock_service: *mut c_void,
    pub reserved_after_service: u32,
    pub completed: Option<CompletionCallback>,
    pub context: *mut c_void,
}

/// # Safety
/// `manager` and the selected slot must be live, index must be in 0..32,
/// and any object/vtable/callback must have the declared ABI and lifetime.
/// Mutations must obey the slot mutex; kernel semaphore ops must be installed
/// when using a non-null semaphore cell. Callback may reenter after unlock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_completion_poll(manager: *mut CompletionManager, index: u32) -> i32 {
    let slot = core::ptr::addr_of_mut!((*manager).slots).cast::<CompletionSlot>().add(index as usize);
    let mutex = core::ptr::addr_of_mut!((*slot).mutex);
    lock_service_lock(core::ptr::addr_of!((*manager).lock_service).read(), mutex);
    let object = core::ptr::addr_of!((*slot).object).read();
    if !object.is_null() && core::ptr::addr_of!((*slot).state).read() == 1 {
        if ((*(*object).vtable).poll)(object) != 0 {
            lock_service_unlock(core::ptr::addr_of!((*manager).lock_service).read(), mutex);
            return 1;
        }
        core::ptr::addr_of_mut!((*slot).state).write(2);
        if core::ptr::addr_of!((*manager).completed).read().is_some() {
            let object = core::ptr::addr_of!((*slot).object).read();
            let payload = core::ptr::addr_of!((*object).payload).read();
            lock_service_unlock(core::ptr::addr_of!((*manager).lock_service).read(), mutex);
            let callback = core::ptr::addr_of!((*manager).completed).read().unwrap_unchecked();
            callback(payload[0], payload[1], core::ptr::addr_of!((*manager).context).read());
            return 0;
        }
    }
    lock_service_unlock(core::ptr::addr_of!((*manager).lock_service).read(), mutex);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn poll(object: *mut CompletionObject) -> i32 {
        (*object).reserved += 1;
        (*object).payload[0] as i32
    }
    static VTABLE: CompletionVtable = CompletionVtable { preceding: [0; 14], poll };

    fn manager() -> CompletionManager {
        CompletionManager {
            slots: core::array::from_fn(|_| CompletionSlot { reserved: 0x12345678,
                object: core::ptr::null_mut(), state: 0, padding: [0xa5; 3],
                mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 } }),
            reserved: [0; 3], lock_service: core::ptr::null_mut(),
            reserved_after_service: 0, completed: None, context: core::ptr::null_mut(),
        }
    }

    #[test]
    fn null_objects_and_nonactive_states_do_not_dispatch() {
        let mut manager = manager();
        manager.slots[31].state = 1;
        assert_eq!(unsafe { slot_completion_poll(&mut manager, 31) }, 0);
        assert_eq!(manager.slots[31].state, 1);
        let mut object = CompletionObject { vtable: &VTABLE, reserved: 0, payload: [0, 9] };
        manager.slots[31].object = &mut object;
        for state in 0..=255 {
            if state == 1 { continue; }
            manager.slots[31].state = state;
            assert_eq!(unsafe { slot_completion_poll(&mut manager, 31) }, 0);
            assert_eq!(manager.slots[31].state, state);
        }
        assert_eq!(object.reserved, 0);
    }

    #[test]
    fn nonzero_poll_preserves_active_state_then_zero_completes_once() {
        let mut manager = manager();
        let mut object = CompletionObject { vtable: &VTABLE, reserved: 0, payload: [u32::MAX, 9] };
        manager.slots[0].object = &mut object;
        manager.slots[0].state = 1;
        assert_eq!(unsafe { slot_completion_poll(&mut manager, 0) }, 1);
        assert_eq!(manager.slots[0].state, 1);
        object.payload[0] = 0;
        assert_eq!(unsafe { slot_completion_poll(&mut manager, 0) }, 0);
        assert_eq!(manager.slots[0].state, 2);
        assert_eq!(unsafe { slot_completion_poll(&mut manager, 0) }, 0);
        assert_eq!(object.reserved, 2);
        assert_eq!(manager.slots[0].reserved, 0x12345678);
        assert_eq!(manager.slots[0].padding, [0xa5; 3]);
    }

    unsafe extern "C" fn completed(a: u32, b: u32, context: *mut c_void) {
        let manager = context.cast::<CompletionManager>();
        assert_eq!((a, b), (0, 0xabcdef01));
        assert_eq!((*manager).slots[31].state, 2);
        assert_eq!(slot_completion_poll(manager, 31), 0);
        (*manager).reserved[0] += 1;
    }

    #[test]
    fn completion_callback_sees_transition_and_can_reenter() {
        let mut manager = manager();
        let mut object = CompletionObject { vtable: &VTABLE, reserved: 0, payload: [0, 0xabcdef01] };
        manager.slots[31].object = &mut object;
        manager.slots[31].state = 1;
        manager.completed = Some(completed);
        manager.context = (&mut manager as *mut CompletionManager).cast();
        assert_eq!(unsafe { slot_completion_poll(&mut manager, 31) }, 0);
        assert_eq!(manager.reserved[0], 1);
        assert_eq!(object.reserved, 1);
    }
}
