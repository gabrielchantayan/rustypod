//! Opaque view-layout marker dispatch.
//!
//! `show_view_layout_marker` — `FUN_0811abf0` @ `0x0811abf0`.
//! True extent: 64 bytes, 0x0811abf0..0x0811ac30 (60 code + 4 literal).
//! Raw A32 verifies two plain BLs, zero predicated BLs, one virtual BLX.
//! Constructs a temporary COW string from 0x08900080, dispatches through
//! vtable +0x11c, releases it, and returns 1. The source is exactly a1 a8 00;
//! its encoding and meaning are intentionally not guessed. Callers are
//! FUN_0811ac30 (initial display) and FUN_0811ae04 (event dispatch).
//! Deliberate deviations: omit dead r1/r2/r3 inputs and stack residue used
//! as a spurious third constructor argument by Ghidra. Reuse the existing
//! one-pointer controller ABI; host pointers are native-width, with the
//! target display offset checked there. Target retains the firmware source
//! address; host uses its exact bytes. No NULL guards or behavioral changes.

use crate::app::now_playing_highlight_display::NowPlayingHighlightController;
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

#[cfg(not(target_os = "none"))]
const LAYOUT_SOURCE: &[u8] = b"\xa1\xa8\0";

/// Displays the opaque firmware layout marker and reports handled (1).
///
/// # Safety
/// `controller` and its display vtable must be valid. The display method
/// may copy the COW string but must not retain its temporary stack slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn show_view_layout_marker(controller: *mut NowPlayingHighlightController) -> u32 {
    #[cfg(target_os = "none")]
    let source = 0x08900080 as *const u8;
    #[cfg(not(target_os = "none"))]
    let source = LAYOUT_SOURCE.as_ptr();
    let mut message = core::ptr::null_mut();
    unsafe {
        let slot = cxx_string_from_cstr(&mut message, source);
        ((*(*controller).vtable).display)(controller, slot);
        cxx_string_release(&mut message);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::now_playing_highlight_display::NowPlayingHighlightVtable;
    use crate::cxx::string::{cxx_string_copy_ctor, StringRep};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    #[repr(C)]
    struct Fixture {
        controller: NowPlayingHighlightController,
        retained: *mut u8,
        retain: bool,
        state: u32,
    }

    unsafe extern "C" fn display(controller: *mut NowPlayingHighlightController, slot: *mut *mut u8) {
        unsafe {
            let fixture = &mut *controller.cast::<Fixture>();
            assert_eq!(core::slice::from_raw_parts(*slot, 3), b"\xa1\xa8\0");
            assert_eq!(free_log().0, 0, "temporary must remain alive during dispatch");
            if fixture.retain { cxx_string_copy_ctor(&mut fixture.retained, slot); }
            fixture.state = 0x12345678;
        }
    }

    #[test]
    fn dispatch_preserves_callback_state_and_cow_ownership() {
        for retain in [false, true] {
            let _heap = mock_heap();
            let vtable = NowPlayingHighlightVtable { unresolved_00_118: [0; 71], display };
            let mut fixture = Fixture {
                controller: NowPlayingHighlightController { vtable: &vtable },
                retained: core::ptr::null_mut(), retain, state: 0,
            };
            let mut allocation = [0u32; 16];
            unsafe {
                let rep = allocation.as_mut_ptr().cast::<StringRep>();
                set_alloc_ret(rep.cast());
                assert_eq!(show_view_layout_marker(&mut fixture.controller), 1);
                assert_eq!(fixture.state, 0x12345678);
                if retain {
                    assert_eq!((*rep).refcount, 0);
                    assert_eq!(free_log().0, 0);
                    assert_eq!(core::slice::from_raw_parts(fixture.retained, 3), b"\xa1\xa8\0");
                    cxx_string_release(&mut fixture.retained);
                } else { assert_eq!((*rep).refcount, -1); }
                assert_eq!(free_log(), (1, rep.cast(), 2));
            }
        }
    }
}
