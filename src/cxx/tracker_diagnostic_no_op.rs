//! `tracker_diagnostic_no_op` — original: `FUN_083d52a0` @ 0x083d52a0
//! (4 bytes).
//!
//! Raw `osos.dec` word `0xe12fff1e` decodes as `bx lr`; the next real function
//! starts at 0x083d52a4 with `push {r4,r5,r6,lr}`. This is neither a veneer
//! (`ldr pc,[pc,#-4]` plus a target word) nor a branch. The body has three
//! inbound plain `bl` call sites and no predicated `bl` call sites. Its callers
//! pass Tracker diagnostic format strings and values, but this retail build
//! performs no diagnostic work.
//!
//! Algorithm: read and write nothing, then return the incoming tracker pointer
//! unchanged in r0. Deliberate deviation: only r0 is expressed in the Rust ABI;
//! the original's `bx lr` incidentally preserves every register.

use core::ffi::c_void;

/// Ignores a disabled Tracker diagnostic and preserves its first argument.
///
/// Original: `FUN_083d52a0` @ 0x083d52a0 (4 bytes; 3 plain `bl` call sites).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tracker_diagnostic_no_op")]
#[inline(never)]
pub unsafe extern "C" fn tracker_diagnostic_no_op(tracker: *mut c_void) -> *mut c_void {
    tracker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_tracker_pointer_for_each_observable_pointer_value() {
        for address in [0usize, 1, 0x0800_0001, 0x083d_52a0, usize::MAX] {
            let tracker = address as *mut c_void;
            assert_eq!(unsafe { tracker_diagnostic_no_op(tracker) }, tracker, "{address:#x}");
        }
    }

    #[test]
    fn does_not_touch_the_tracker_object() {
        let mut tracker = [0xa5u8; 32];
        let before = tracker;

        let returned = unsafe { tracker_diagnostic_no_op(tracker.as_mut_ptr().cast()) };

        assert_eq!(returned, tracker.as_mut_ptr().cast::<c_void>());
        assert_eq!(tracker, before, "the one-instruction body performs no stores");
    }
}
