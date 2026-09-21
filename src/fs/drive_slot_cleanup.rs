//! Drive-slot cleanup wrapper.

#[cfg(target_os = "none")]
use crate::fs::drive_slot;

const RETAIL_CLEAR_INDEX_REGISTRATIONS: usize = 0x082e_186c;
const RETAIL_CLEAR_SLOT_VOLUMES: usize = 0x082e_1804;
const RETAIL_CLEAR_SLOT_EVENTS: usize = 0x082e_180c;
const RETAIL_CLEAR_SLOT_REFERENCES: usize = 0x082e_17b0;

type ClearIndexRegistrations = unsafe extern "C" fn(u32);
type ClearSlot = unsafe extern "C" fn(*mut u8);
type DriveSlotLookup = unsafe extern "C" fn(u32) -> *mut u8;

/// `drive_slot_cleanup` — original: `FUN_082e073c` @ `0x082e073c` (104
/// bytes; true extent `0x082e073c..0x082e07a3`; the next independent function
/// begins at `0x082e07a4` with `push {r4-r9,lr}`).
///
/// Raw ARM decoding finds three inbound direct BL instructions: one plain BL
/// (`0x081bc9b0`) and two `blne` forms (`0x082c30e8`, `0x082c3158`). The body
/// has five unconditional direct BL instructions: the ported drive-slot lookup
/// plus verified retail targets `0x082e186c`, `0x082e1804`, `0x082e180c`, and
/// `0x082e17b0`; no body BL is predicated.
///
/// Algorithm: look up the live slot for `index`; fail if absent. A nonzero
/// `force_cleanup` replaces its count with one. Cleanup runs when forced or
/// when the prior count was one, then decrements the slot count and returns
/// one. Otherwise it only decrements and returns one.
///
/// Deliberate deviation: the four directly called but unnamed retail helpers
/// remain address-verified opaque seams on target; host tests inject them and
/// the slot lookup rather than reaching drive_slot's private host BSS model.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_index_registrations(index: u32) {
    core::mem::transmute::<usize, ClearIndexRegistrations>(RETAIL_CLEAR_INDEX_REGISTRATIONS)(index);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_slot_volumes(slot: *mut u8) {
    core::mem::transmute::<usize, ClearSlot>(RETAIL_CLEAR_SLOT_VOLUMES)(slot);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_slot_events(slot: *mut u8) {
    core::mem::transmute::<usize, ClearSlot>(RETAIL_CLEAR_SLOT_EVENTS)(slot);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_slot_references(slot: *mut u8) {
    core::mem::transmute::<usize, ClearSlot>(RETAIL_CLEAR_SLOT_REFERENCES)(slot);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct DriveSlotCleanupOps {
    pub lookup: DriveSlotLookup,
    pub clear_index_registrations: ClearIndexRegistrations,
    pub clear_slot_volumes: ClearSlot,
    pub clear_slot_events: ClearSlot,
    pub clear_slot_references: ClearSlot,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_: u32) -> *mut u8 {
    core::ptr::null_mut()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_index(_: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_slot(_: *mut u8) {}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_DRIVE_SLOT_CLEANUP_OPS: DriveSlotCleanupOps = DriveSlotCleanupOps {
    lookup: missing_lookup,
    clear_index_registrations: no_op_index,
    clear_slot_volumes: no_op_slot,
    clear_slot_events: no_op_slot,
    clear_slot_references: no_op_slot,
};

#[cfg(not(target_os = "none"))]
pub static mut DRIVE_SLOT_CLEANUP_OPS: DriveSlotCleanupOps = DEFAULT_DRIVE_SLOT_CLEANUP_OPS;

/// Cleans a live drive slot and drops one reference count.
///
/// # Safety
///
/// `index` must select a valid retail drive slot. On target, every called
/// retail helper and the returned slot's first word must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn drive_slot_cleanup(index: u32, force_cleanup: u32) -> u32 {
    #[cfg(target_os = "none")]
    let slot = drive_slot::drive_slot_lookup(index);
    #[cfg(not(target_os = "none"))]
    let slot = (DRIVE_SLOT_CLEANUP_OPS.lookup)(index);

    if slot.is_null() {
        return 0;
    }

    let count = slot.cast::<u32>();
    if force_cleanup != 0 {
        count.write_volatile(1);
    } else if count.read_volatile() != 1 {
        count.write_volatile(count.read_volatile().wrapping_sub(1));
        return 1;
    }

    #[cfg(target_os = "none")]
    {
        clear_index_registrations(index);
        clear_slot_volumes(slot);
        clear_slot_events(slot);
        clear_slot_references(slot);
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = DRIVE_SLOT_CLEANUP_OPS;
        (ops.clear_index_registrations)(index);
        (ops.clear_slot_volumes)(slot);
        (ops.clear_slot_events)(slot);
        (ops.clear_slot_references)(slot);
    }
    count.write_volatile(count.read_volatile().wrapping_sub(1));
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOT: u32 = 0;
    static mut LOOKUP_RESULT: *mut u8 = core::ptr::null_mut();
    static mut ACTIONS: [u32; 4] = [0; 4];
    static mut ACTION_COUNT: usize = 0;

    unsafe extern "C" fn lookup(_: u32) -> *mut u8 { LOOKUP_RESULT }
    unsafe fn record(action: u32) {
        ACTIONS[ACTION_COUNT] = action;
        ACTION_COUNT += 1;
    }
    unsafe extern "C" fn clear_index(index: u32) { record(0x10 | index); }
    unsafe extern "C" fn clear_volumes(_: *mut u8) { record(2); }
    unsafe extern "C" fn clear_events(_: *mut u8) { record(3); }
    unsafe extern "C" fn clear_references(_: *mut u8) { record(4); }

    struct Restore(DriveSlotCleanupOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { DRIVE_SLOT_CLEANUP_OPS = self.0; } }
    }

    fn setup(slot: *mut u8) -> Restore {
        unsafe {
            let previous = DRIVE_SLOT_CLEANUP_OPS;
            DRIVE_SLOT_CLEANUP_OPS = DriveSlotCleanupOps {
                lookup, clear_index_registrations: clear_index, clear_slot_volumes: clear_volumes,
                clear_slot_events: clear_events, clear_slot_references: clear_references,
            };
            LOOKUP_RESULT = slot;
            ACTION_COUNT = 0;
            Restore(previous)
        }
    }

    #[test]
    fn absent_slot_fails_without_cleanup() {
        let _lock = TEST_LOCK.lock();
        let _restore = setup(core::ptr::null_mut());
        assert_eq!(unsafe { drive_slot_cleanup(3, 1) }, 0);
        assert_eq!(unsafe { ACTION_COUNT }, 0);
    }

    #[test]
    fn ordinary_nonfinal_reference_only_decrements() {
        let _lock = TEST_LOCK.lock();
        unsafe { SLOT = 3; }
        let _restore = setup(core::ptr::addr_of_mut!(SLOT).cast());
        assert_eq!(unsafe { drive_slot_cleanup(2, 0) }, 1);
        assert_eq!(unsafe { SLOT }, 2);
        assert_eq!(unsafe { ACTION_COUNT }, 0);
    }

    #[test]
    fn forced_cleanup_orders_callbacks_and_leaves_zero_count() {
        let _lock = TEST_LOCK.lock();
        unsafe { SLOT = 7; }
        let _restore = setup(core::ptr::addr_of_mut!(SLOT).cast());
        assert_eq!(unsafe { drive_slot_cleanup(5, 1) }, 1);
        assert_eq!(unsafe { SLOT }, 0);
        assert_eq!(unsafe { ACTION_COUNT }, 4);
        assert_eq!(unsafe { ACTIONS }, [0x15, 2, 3, 4]);
    }
}
