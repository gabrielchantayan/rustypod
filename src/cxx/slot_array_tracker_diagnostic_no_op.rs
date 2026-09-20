//! `slot_array_tracker_diagnostic_no_op` — original: `FUN_083d4dd0` @ 0x083d4dd0
//! (4 bytes).
//!
//! Raw `osos.dec` establishes the true extent: the sole A32 word is `bx lr`
//! (`0xe12fff1e`) at 0x083d4dd0; 0x083d4dd4 starts the owning slot-array insert
//! routine with `push {r4,r5,r6,lr}`. It is neither a veneer nor a branch.
//! Whole-image ARM disassembly finds three direct incoming calls, all plain
//! unconditional `bl` (0x081ee418, 0x083d4ee8, and 0x083d500c), and no
//! predicated `bl` calls. Callers pass Tracker diagnostic format strings and
//! values, but this retail build performs no diagnostic work.
//!
//! Algorithm: access no memory and return the incoming Tracker pointer in r0
//! unchanged. Deliberate deviations: none; the target export is naked A32
//! assembly, preserving the exact single-word body.

use core::ffi::c_void;

/// Returns the Tracker word unchanged without recording a slot-array diagnostic.
///
/// The ARM body dereferences nothing, so `tracker` may be NULL, unaligned, or
/// dangling.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_tracker_diagnostic_no_op(_tracker: *mut c_void) -> *mut c_void {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn slot_array_tracker_diagnostic_no_op(tracker: *mut c_void) -> *mut c_void {
    tracker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_tracker_word_for_null_unaligned_and_maximum_values() {
        for word in [0usize, 1, 0x0800_0001, 0x083d_4dd0, usize::MAX] {
            let tracker = word as *mut c_void;
            assert_eq!(unsafe { slot_array_tracker_diagnostic_no_op(tracker) }, tracker, "tracker={word:#x}");
        }
    }

    #[test]
    fn does_not_access_tracker_memory() {
        let mut tracker = [0xa5u8; 32];
        let before = tracker;

        let returned = unsafe { slot_array_tracker_diagnostic_no_op(tracker.as_mut_ptr().cast()) };

        assert_eq!(returned, tracker.as_mut_ptr().cast::<c_void>());
        assert_eq!(tracker, before, "the one-instruction body performs no stores");
    }
}
