//! `element_array0_tracker_diagnostic_noop` — original: `FUN_083d3cec` @ **0x083d3cec**
//! (4 bytes).
//!
//! Raw `osos.dec` establishes the true extent: the sole A32 word is `bx lr`
//! (`0xe12fff1e`) at 0x083d3cec; 0x083d3cf0 starts the next real function with
//! `push {r4-r6,lr}`. It is neither a veneer nor a tail branch. Whole-image raw
//! A32 decoding finds three direct incoming plain unconditional `bl` calls
//! (0x08106448, 0x083d3df8, and 0x083d3f20), and no predicated `bl` calls.
//!
//! Algorithm: accept the tracker word in `r0`, access no memory, and return it
//! unchanged in `r0`. Callers supply element-array relocation and fTable
//! diagnostics, establishing this as disabled element-array-0 tracker
//! instrumentation. Deliberate deviations: none; the target export is naked A32
//! assembly to preserve the exact single-word body.

use core::ffi::c_void;

/// Returns the tracker word unchanged without recording a diagnostic.
///
/// The ARM body dereferences nothing, so `tracker` may be NULL, unaligned, or
/// dangling.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array0_tracker_diagnostic_noop(_tracker: *mut c_void) -> *mut c_void {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn element_array0_tracker_diagnostic_noop(tracker: *mut c_void) -> *mut c_void {
    tracker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_tracker_word() {
        for tracker_word in [0usize, 1, 0x0800_0001, 0x0897_ba01, usize::MAX] {
            let tracker = tracker_word as *mut c_void;
            assert_eq!(unsafe { element_array0_tracker_diagnostic_noop(tracker) }, tracker, "tracker={tracker_word:#x}");
        }
    }

    #[test]
    fn does_not_access_tracker_memory() {
        let mut tracker = [0xa5u8; 32];
        let before = tracker;
        let returned = unsafe { element_array0_tracker_diagnostic_noop(tracker.as_mut_ptr().cast()) };

        assert_eq!(returned, tracker.as_mut_ptr().cast::<c_void>());
        assert_eq!(tracker, before, "the bare return writes no tracker byte");
    }
}
