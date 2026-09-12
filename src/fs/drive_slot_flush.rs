//! Pending drive-slot flush gate.
//!
//! A live drive slot records pending metadata writes in its word at `+0x88`.
//! This gate routes those writes through the two resident flush phases and
//! clears that word only after both phases report success.

use crate::fs::drive_slot;

/// Target word index of the drive slot's pending-flush indicator (`+0x88`).
const DRIVE_SLOT_PENDING_FLUSH_WORD: usize = 34;

/// The two unrecovered flush phases have this observed ABI. Their individual
/// semantics remain unrecovered; this port preserves their order and status
/// gates without assigning them identities beyond their role in this wrapper.
type DriveSlotFlushPhase = unsafe extern "C" fn(*mut u8) -> u32;

/// First resident flush phase called when a slot is pending.
const FIRST_FLUSH_PHASE_ADDRESS: usize = 0x082e_14f0;
/// Second resident flush phase called after the first succeeds.
const SECOND_FLUSH_PHASE_ADDRESS: usize = 0x082e_3be4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn first_flush_phase(slot: *mut u8) -> u32 {
    let phase: DriveSlotFlushPhase = core::mem::transmute(FIRST_FLUSH_PHASE_ADDRESS);
    phase(slot)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn second_flush_phase(slot: *mut u8) -> u32 {
    let phase: DriveSlotFlushPhase = core::mem::transmute(SECOND_FLUSH_PHASE_ADDRESS);
    phase(slot)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_slot_lookup(_index: u32) -> *mut u8 {
    panic!("drive_slot_flush_pending_writes called without a host slot-lookup seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_flush_phase(_slot: *mut u8) -> u32 {
    panic!("drive_slot_flush_pending_writes called without a host flush-phase seam")
}

#[cfg(not(target_os = "none"))]
static mut DRIVE_SLOT_LOOKUP: unsafe extern "C" fn(u32) -> *mut u8 = unavailable_slot_lookup;
#[cfg(not(target_os = "none"))]
static mut FIRST_FLUSH_PHASE: DriveSlotFlushPhase = unavailable_flush_phase;
#[cfg(not(target_os = "none"))]
static mut SECOND_FLUSH_PHASE: DriveSlotFlushPhase = unavailable_flush_phase;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_lookup_drive_slot(index: u32) -> *mut u8 {
    let lookup = core::ptr::read_volatile(core::ptr::addr_of!(DRIVE_SLOT_LOOKUP));
    lookup(index)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn first_flush_phase(slot: *mut u8) -> u32 {
    let phase = core::ptr::read_volatile(core::ptr::addr_of!(FIRST_FLUSH_PHASE));
    phase(slot)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn second_flush_phase(slot: *mut u8) -> u32 {
    let phase = core::ptr::read_volatile(core::ptr::addr_of!(SECOND_FLUSH_PHASE));
    phase(slot)
}

#[inline(always)]
unsafe fn lookup_drive_slot(index: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        drive_slot::drive_slot_lookup(index)
    }
    #[cfg(not(target_os = "none"))]
    {
        host_lookup_drive_slot(index)
    }
}

/// Flushes a live drive slot's pending writes.
///
/// Original: `FUN_082e149c` at `0x082e149c`, 84 code bytes. Its true extent
/// is `0x082e149c..0x082e14ec`: the next separately entered function begins
/// at `0x082e14f0`. Every ARM B/BL word in `osos.dec` was decoded: seven
/// direct call sites are unconditional `bl` at 0x082b1770, 0x082c50f0,
/// 0x082e0650, 0x082e3414, 0x082e61a4, 0x082e64bc, and 0x082e67c0; one
/// additional unconditional tail `b` is at 0x082e42a4. There are no predicated
/// calls and no aligned data-word references, so it is neither caller-gated nor
/// virtually dispatched.
///
/// Looks up `index`'s live drive slot. A missing slot fails. A zero pending
/// indicator succeeds without calling either resident phase. Otherwise it runs
/// the resident `0x082e14f0` phase and then the resident `0x082e3be4` phase;
/// either zero status fails and retains the indicator. Only two nonzero phase
/// statuses clear the indicator and return one.
///
/// Deliberate deviation: the two phases are not yet ported, so device builds
/// call their verified resident addresses. Host builds use recording seams;
/// the already ported `drive_slot_lookup` is likewise a host seam only so tests
/// do not depend on its BSS-backed drive table.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn drive_slot_flush_pending_writes(index: u32) -> u32 {
    let slot = lookup_drive_slot(index);
    if slot.is_null() {
        return 0;
    }

    let pending = slot.cast::<u32>().add(DRIVE_SLOT_PENDING_FLUSH_WORD);
    if pending.read() == 0 {
        return 1;
    }
    if first_flush_phase(slot) == 0 || second_flush_phase(slot) == 0 {
        return 0;
    }

    pending.write(0);
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP_RESULT: *mut u8 = core::ptr::null_mut();
    static mut LOOKUP_INDEX: u32 = 0;
    static mut LOOKUP_CALLS: u32 = 0;
    static mut FIRST_RESULT: u32 = 0;
    static mut FIRST_SLOT: *mut u8 = core::ptr::null_mut();
    static mut FIRST_CALLS: u32 = 0;
    static mut SECOND_RESULT: u32 = 0;
    static mut SECOND_SLOT: *mut u8 = core::ptr::null_mut();
    static mut SECOND_CALLS: u32 = 0;

    #[repr(C)]
    struct DriveSlotFixture {
        words_before_pending: [u32; DRIVE_SLOT_PENDING_FLUSH_WORD],
        pending_flush: u32,
    }

    unsafe extern "C" fn record_lookup(index: u32) -> *mut u8 {
        LOOKUP_INDEX = index;
        LOOKUP_CALLS += 1;
        LOOKUP_RESULT
    }

    unsafe extern "C" fn record_first_phase(slot: *mut u8) -> u32 {
        FIRST_SLOT = slot;
        FIRST_CALLS += 1;
        FIRST_RESULT
    }

    unsafe extern "C" fn record_second_phase(slot: *mut u8) -> u32 {
        SECOND_SLOT = slot;
        SECOND_CALLS += 1;
        SECOND_RESULT
    }

    struct HostOpsReset(
        unsafe extern "C" fn(u32) -> *mut u8,
        DriveSlotFlushPhase,
        DriveSlotFlushPhase,
    );

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe {
                DRIVE_SLOT_LOOKUP = self.0;
                FIRST_FLUSH_PHASE = self.1;
                SECOND_FLUSH_PHASE = self.2;
            }
        }
    }

    unsafe fn install_host_ops() -> HostOpsReset {
        let reset = HostOpsReset(
            core::ptr::read_volatile(core::ptr::addr_of!(DRIVE_SLOT_LOOKUP)),
            core::ptr::read_volatile(core::ptr::addr_of!(FIRST_FLUSH_PHASE)),
            core::ptr::read_volatile(core::ptr::addr_of!(SECOND_FLUSH_PHASE)),
        );
        DRIVE_SLOT_LOOKUP = record_lookup;
        FIRST_FLUSH_PHASE = record_first_phase;
        SECOND_FLUSH_PHASE = record_second_phase;
        reset
    }

    unsafe fn reset_recording(slot: *mut u8, first_result: u32, second_result: u32) {
        LOOKUP_RESULT = slot;
        LOOKUP_INDEX = u32::MAX;
        LOOKUP_CALLS = 0;
        FIRST_RESULT = first_result;
        FIRST_SLOT = core::ptr::null_mut();
        FIRST_CALLS = 0;
        SECOND_RESULT = second_result;
        SECOND_SLOT = core::ptr::null_mut();
        SECOND_CALLS = 0;
    }

    fn lock_tests() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    #[test]
    fn missing_slot_fails_before_any_flush_phase() {
        let _test_guard = lock_tests();
        let reset = unsafe { install_host_ops() };

        unsafe {
            reset_recording(core::ptr::null_mut(), 1, 1);
            assert_eq!(drive_slot_flush_pending_writes(3), 0);
            assert_eq!(LOOKUP_INDEX, 3);
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(FIRST_CALLS, 0);
            assert_eq!(SECOND_CALLS, 0);
        }

        drop(reset);
    }

    #[test]
    fn clean_slot_succeeds_without_resident_flushes() {
        let _test_guard = lock_tests();
        let reset = unsafe { install_host_ops() };
        let mut slot = DriveSlotFixture {
            words_before_pending: [0; DRIVE_SLOT_PENDING_FLUSH_WORD],
            pending_flush: 0,
        };

        unsafe {
            reset_recording((&mut slot as *mut DriveSlotFixture).cast(), 1, 1);
            assert_eq!(drive_slot_flush_pending_writes(1), 1);
            assert_eq!(LOOKUP_INDEX, 1);
            assert_eq!(FIRST_CALLS, 0);
            assert_eq!(SECOND_CALLS, 0);
            assert_eq!(slot.pending_flush, 0);
        }

        drop(reset);
    }

    #[test]
    fn failed_first_phase_retains_pending_indicator() {
        let _test_guard = lock_tests();
        let reset = unsafe { install_host_ops() };
        let mut slot = DriveSlotFixture {
            words_before_pending: [0; DRIVE_SLOT_PENDING_FLUSH_WORD],
            pending_flush: 0xfeed_face,
        };
        let slot_ptr = (&mut slot as *mut DriveSlotFixture).cast();

        unsafe {
            reset_recording(slot_ptr, 0, 1);
            assert_eq!(drive_slot_flush_pending_writes(2), 0);
            assert_eq!(FIRST_SLOT, slot_ptr);
            assert_eq!(FIRST_CALLS, 1);
            assert_eq!(SECOND_CALLS, 0);
            assert_eq!(slot.pending_flush, 0xfeed_face);
        }

        drop(reset);
    }

    #[test]
    fn failed_second_phase_retains_pending_indicator() {
        let _test_guard = lock_tests();
        let reset = unsafe { install_host_ops() };
        let mut slot = DriveSlotFixture {
            words_before_pending: [0; DRIVE_SLOT_PENDING_FLUSH_WORD],
            pending_flush: 1,
        };
        let slot_ptr = (&mut slot as *mut DriveSlotFixture).cast();

        unsafe {
            reset_recording(slot_ptr, 1, 0);
            assert_eq!(drive_slot_flush_pending_writes(0), 0);
            assert_eq!(FIRST_SLOT, slot_ptr);
            assert_eq!(SECOND_SLOT, slot_ptr);
            assert_eq!(FIRST_CALLS, 1);
            assert_eq!(SECOND_CALLS, 1);
            assert_eq!(slot.pending_flush, 1);
        }

        drop(reset);
    }

    #[test]
    fn completed_phases_clear_pending_indicator() {
        let _test_guard = lock_tests();
        let reset = unsafe { install_host_ops() };
        let mut slot = DriveSlotFixture {
            words_before_pending: [0; DRIVE_SLOT_PENDING_FLUSH_WORD],
            pending_flush: 0x8765_4321,
        };
        let slot_ptr = (&mut slot as *mut DriveSlotFixture).cast();

        unsafe {
            reset_recording(slot_ptr, 1, 0xdead_beef);
            assert_eq!(drive_slot_flush_pending_writes(7), 1);
            assert_eq!(LOOKUP_INDEX, 7);
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(FIRST_SLOT, slot_ptr);
            assert_eq!(SECOND_SLOT, slot_ptr);
            assert_eq!(FIRST_CALLS, 1);
            assert_eq!(SECOND_CALLS, 1);
            assert_eq!(slot.pending_flush, 0);
        }

        drop(reset);
    }
}
