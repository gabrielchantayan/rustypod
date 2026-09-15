//! `app_state_cleanup` — original: `FUN_08294a94` @ **0x08294a94**
//! (**148 bytes**, `0x08294a94..0x08294b24`; the next separately linked
//! function begins at `0x08294b30` after two literal-pool words).
//!
//! A direct scan of aligned ARM B/BL-immediate words in `osos.dec` finds
//! **5 incoming `bl` calls**, all unconditional, and **0 predicated `bl`
//! forms**. The body has two direct `bl` instructions (each reached from the
//! four-entry loop) and one runtime `blx` through vtable slot `+0x1c`.
//!
//! Algorithm: if the controller's active sequence index is zero, return.
//! Otherwise, cancel each active entry in the fixed four-entry registration
//! table and clear its matching shared slot. Then select the byte sequence
//! immediately before the indexed sequence-table pointer and invoke vtable
//! slot `+0x1c` on each controller object named by that sequence until byte
//! sentinel `4`.
//!
//! `FUN_08293384` and `FUN_0810756c` have no recovered identities. Target
//! builds call their verified retail addresses; host tests inject only those
//! direct calls. Host vtables deliberately use native pointers rather than
//! target 32-bit words, preserving the dispatched slot without truncation.

#[cfg(not(target_os = "none"))]
use core::ptr;

const REGISTRATION_TABLE: usize = 0x089d_04c4;
const SEQUENCE_TABLE: usize = 0x089d_04bc;
const REGISTERED_ENTRY_STRIDE: usize = 0x18;
const REGISTERED_ENTRY_ACTIVE_OFFSET: usize = 0x13;
const CONTROLLER_CONTEXT_OFFSET: usize = 0x34;
const CONTROLLER_OBJECTS_OFFSET: usize = 0x38;
const CONTROLLER_SEQUENCE_INDEX_OFFSET: usize = 0xc4;
const VTABLE_DISPATCH_WORD: usize = 7;
const SEQUENCE_END: u8 = 4;
const REGISTERED_ENTRY_COUNT: usize = 4;
const RETAIL_CANCEL_REGISTERED_ENTRY: usize = 0x0829_3384;
const RETAIL_CLEAR_SHARED_SLOT: usize = 0x0810_756c;

type CancelRegisteredEntry = unsafe extern "C" fn(*mut u8, u8);
type ClearSharedSlot = unsafe extern "C" fn(*mut u8, u8);
type DispatchObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cancel_registered_entry(controller: *mut u8, entry_id: u8) {
    let cancel: CancelRegisteredEntry = core::mem::transmute(RETAIL_CANCEL_REGISTERED_ENTRY);
    cancel(controller, entry_id);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_shared_slot(context: *mut u8, entry_id: u8) {
    let clear: ClearSharedSlot = core::mem::transmute(RETAIL_CLEAR_SHARED_SLOT);
    clear(context, entry_id);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct AppStateCleanupOps {
    pub registrations: *const HostRegistrationEntry,
    pub sequence_table: *const *const u8,
    pub cancel_registered_entry: CancelRegisteredEntry,
    pub clear_shared_slot: ClearSharedSlot,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_cancel(_: *mut u8, _: u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_clear(_: *mut u8, _: u8) {}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_APP_STATE_CLEANUP_OPS: AppStateCleanupOps = AppStateCleanupOps {
    registrations: ptr::null(),
    sequence_table: ptr::null(),
    cancel_registered_entry: no_op_cancel,
    clear_shared_slot: no_op_clear,
};

#[cfg(not(target_os = "none"))]
pub static mut APP_STATE_CLEANUP_OPS: AppStateCleanupOps = DEFAULT_APP_STATE_CLEANUP_OPS;

/// Target-layout registration entry at `0x089d04c4 + id * 0x18`.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HostRegistrationEntry {
    pub entry_id: u8,
    pub unresolved_01_to_12: [u8; 0x12],
    pub active: u8,
    pub unresolved_14_to_17: [u8; 4],
}

/// Host representation of the dispatched vtable slot.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostCleanupVtable {
    pub unresolved_00_to_18: [usize; VTABLE_DISPATCH_WORD],
    pub dispatch: DispatchObject,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostCleanupObject {
    pub vtable: *const HostCleanupVtable,
    pub tag: u8,
}

/// Host controller fixture. Its fields model the values used by the ARM body;
/// its native-pointer layout intentionally differs from the target offsets.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostAppStateController {
    pub context: *mut u8,
    pub objects: [*mut HostCleanupObject; SEQUENCE_END as usize],
    pub sequence_index: usize,
}

/// Cancels active registered entries, clears their shared state, and dispatches
/// the selected controller-object cleanup sequence.
///
/// # Safety
///
/// `controller` must satisfy the target's `+0x34`, `+0x38`, and `+0xc4`
/// accesses. The fixed registration/sequence tables and every selected vtable
/// slot must be valid; retailOS has no NULL guards for these accesses.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_state_cleanup(controller: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let sequence_index = (controller.add(CONTROLLER_SEQUENCE_INDEX_OFFSET) as *const u32).read_volatile();
        if sequence_index == 0 {
            return;
        }
        for entry_index in 0..REGISTERED_ENTRY_COUNT {
            let entry = (REGISTRATION_TABLE as *const u8).add(entry_index * REGISTERED_ENTRY_STRIDE);
            if entry.add(REGISTERED_ENTRY_ACTIVE_OFFSET).read_volatile() != 0 {
                let entry_id = entry.read_volatile();
                cancel_registered_entry(controller, entry_id);
                let context = (controller.add(CONTROLLER_CONTEXT_OFFSET) as *const u32).read_volatile() as *mut u8;
                clear_shared_slot(context, entry_id);
            }
        }
        let sequence = *((SEQUENCE_TABLE as *const u32).add(sequence_index as usize - 1)) as *const u8;
        let mut position = 0usize;
        loop {
            let object_index = sequence.add(position).read_volatile();
            if object_index == SEQUENCE_END {
                break;
            }
            let object = ((controller.add(CONTROLLER_OBJECTS_OFFSET) as *const u32).add(object_index as usize)).read_volatile() as *mut u8;
            let vtable = (object as *const u32).read_volatile() as *const u32;
            let dispatch: DispatchObject = core::mem::transmute(vtable.add(VTABLE_DISPATCH_WORD).read_volatile() as usize);
            dispatch(object);
            position += 1;
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let controller = &mut *controller.cast::<HostAppStateController>();
        if controller.sequence_index == 0 {
            return;
        }
        let ops = APP_STATE_CLEANUP_OPS;
        for entry_index in 0..REGISTERED_ENTRY_COUNT {
            let entry = &*ops.registrations.add(entry_index);
            if entry.active != 0 {
                (ops.cancel_registered_entry)(controller as *mut _ as *mut u8, entry.entry_id);
                (ops.clear_shared_slot)(controller.context, entry.entry_id);
            }
        }
        let sequence = *ops.sequence_table.add(controller.sequence_index - 1);
        let mut position = 0usize;
        loop {
            let object_index = *sequence.add(position);
            if object_index == SEQUENCE_END {
                break;
            }
            let object = *controller.objects.get_unchecked(object_index as usize);
            let vtable = (*object).vtable;
            ((*vtable).dispatch)(object.cast());
            position += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    static ACTIONS: Mutex<([u8; 6], usize)> = Mutex::new(([0; 6], 0));
    fn record(action: u8) {
        let mut actions = ACTIONS.lock();
        let position = actions.1;
        actions.0[position] = action;
        actions.1 += 1;
    }
    unsafe extern "C" fn cancel(_: *mut u8, entry_id: u8) { record(entry_id); }
    unsafe extern "C" fn clear(_: *mut u8, entry_id: u8) { record(0x80 | entry_id); }
    unsafe extern "C" fn dispatch(object: *mut u8) { record(0xc0 | (*object.cast::<HostCleanupObject>()).tag); }

    static VTABLE: HostCleanupVtable = HostCleanupVtable { unresolved_00_to_18: [0; VTABLE_DISPATCH_WORD], dispatch };

    #[test]
    fn inactive_sequence_has_no_side_effects() {
        let _lock = TEST_LOCK.lock();
        let registrations = [HostRegistrationEntry { entry_id: 1, unresolved_01_to_12: [0; 0x12], active: 1, unresolved_14_to_17: [0; 4] }; 4];
        *ACTIONS.lock() = ([0; 6], 0);
        let sequences = [b"\x04".as_ptr()];
        unsafe { APP_STATE_CLEANUP_OPS = AppStateCleanupOps { registrations: registrations.as_ptr(), sequence_table: sequences.as_ptr(), cancel_registered_entry: cancel, clear_shared_slot: clear }; }
        let mut controller = HostAppStateController { context: ptr::null_mut(), objects: [ptr::null_mut(); 4], sequence_index: 0 };
        unsafe { app_state_cleanup((&mut controller as *mut HostAppStateController).cast()); }
        assert_eq!(ACTIONS.lock().1, 0);
    }

    #[test]
    fn cleans_active_entries_then_dispatches_selected_sequence() {
        let _lock = TEST_LOCK.lock();
        *ACTIONS.lock() = ([0; 6], 0);
        let registrations = [
            HostRegistrationEntry { entry_id: 1, unresolved_01_to_12: [0; 0x12], active: 0, unresolved_14_to_17: [0; 4] },
            HostRegistrationEntry { entry_id: 2, unresolved_01_to_12: [0; 0x12], active: 1, unresolved_14_to_17: [0; 4] },
            HostRegistrationEntry { entry_id: 3, unresolved_01_to_12: [0; 0x12], active: 1, unresolved_14_to_17: [0; 4] },
            HostRegistrationEntry { entry_id: 4, unresolved_01_to_12: [0; 0x12], active: 0, unresolved_14_to_17: [0; 4] },
        ];
        let sequences = [b"\x01\x03\x04".as_ptr()];
        unsafe { APP_STATE_CLEANUP_OPS = AppStateCleanupOps { registrations: registrations.as_ptr(), sequence_table: sequences.as_ptr(), cancel_registered_entry: cancel, clear_shared_slot: clear }; }
        let mut one = HostCleanupObject { vtable: &VTABLE, tag: 1 };
        let mut three = HostCleanupObject { vtable: &VTABLE, tag: 3 };
        let mut controller = HostAppStateController { context: ptr::null_mut(), objects: [ptr::null_mut(), &mut one, ptr::null_mut(), &mut three], sequence_index: 1 };
        unsafe { app_state_cleanup((&mut controller as *mut HostAppStateController).cast()); }
        assert_eq!(ACTIONS.lock().0, [2, 0x82, 3, 0x83, 0xc1, 0xc3]);
    }
}
