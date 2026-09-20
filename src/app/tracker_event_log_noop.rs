//! `tracker_event_log_noop` — original: `FUN_083d551c` @ **0x083d551c**
//! (4 bytes).
//!
//! Raw `osos.dec` establishes the true extent: the sole A32 word is `bx lr`
//! (`0xe12fff1e`) at 0x083d551c; 0x083d5518 closes the preceding element-array
//! lookup and 0x083d5520 starts the next separately linked function with
//! `push {r4-r6,lr}`. It is neither a veneer nor a tail branch. Whole-image
//! decoding finds three direct incoming calls, all plain unconditional `bl`
//! (0x081062d8, 0x083d5628, and 0x083d574c), and no predicated `bl` calls.
//!
//! Algorithm: accept the tracker word in `r0`, access no memory, and return it
//! unchanged in `r0`. Call contexts pass tracker format strings and event
//! details, establishing this as disabled tracker-event instrumentation.
//! Deliberate deviations: none; the target export is naked A32 assembly to
//! preserve the exact single-word body.

use core::ffi::c_void;

/// Returns the tracker word unchanged without recording its event.
///
/// The ARM body dereferences nothing, so `tracker` may be NULL, unaligned, or
/// dangling.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracker_event_log_noop(_tracker: *mut c_void) -> *mut c_void {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn tracker_event_log_noop(tracker: *mut c_void) -> *mut c_void {
    tracker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_tracker_word() {
        for tracker_word in [0usize, 1, 0x0800_0001, 0x0897_cc8d, usize::MAX] {
            let tracker = tracker_word as *mut c_void;
            assert_eq!(unsafe { tracker_event_log_noop(tracker) }, tracker, "tracker={tracker_word:#x}");
        }
    }

    #[test]
    fn does_not_access_tracker_memory() {
        let mut tracker = [0xa5u8; 32];
        let before = tracker;
        let returned = unsafe { tracker_event_log_noop(tracker.as_mut_ptr().cast()) };

        assert_eq!(returned, tracker.as_mut_ptr().cast::<c_void>());
        assert_eq!(tracker, before, "the bare return writes no tracker byte");
    }
}
