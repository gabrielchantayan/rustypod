//! Now-playing highlight layout dispatch.
//!
//! `show_now_playing_highlight` — `FUN_0822fae8` @ `0x0822fae8`.
//! True extent: 64 bytes, 0x0822fae8..0x0822fb28 (60 code + 4 literal).
//! Raw decoding: two unconditional BLs, zero predicated BLs, one virtual BLX;
//! inbound BLs: zero unconditional, two predicated (NE @ 0x0822d4b0,
//! EQ @ 0x08230b58). Constructs a temporary COW string from 0x088ffd30,
//! invokes controller vtable slot +0x11c, releases the temporary, returns 1.
//! The source is preserved as opaque bytes, not guessed from its encoding.
//! Deliberate deviations: dead r1/r2/r3 inputs and allocator-tag stack residue
//! are omitted; host builds use the exact source bytes and native-width vtable
//! fields. Target builds retain the fixed source address and 32-bit layout.

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

#[repr(C)]
pub struct NowPlayingHighlightController {
    pub vtable: *const NowPlayingHighlightVtable,
}

#[repr(C)]
pub struct NowPlayingHighlightVtable {
    pub unresolved_00_118: [usize; 71],
    pub display: unsafe extern "C" fn(*mut NowPlayingHighlightController, *mut *mut u8),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x11c] = [0; core::mem::offset_of!(NowPlayingHighlightVtable, display)];

// Verbatim bytes at 0x088ffd30 through the first NUL in osos.dec.
#[cfg(not(target_os = "none"))]
const LAYOUT_SOURCE: &[u8] = b"\x88\x86\xe9\x90\x98\0";

/// Displays the now-playing highlighted layout and reports handled (1).
///
/// # Safety
/// `controller` and its vtable must be valid; the display method must accept
/// a temporary COW string slot and must not retain that stack slot itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn show_now_playing_highlight(controller: *mut NowPlayingHighlightController) -> u32 {
    #[cfg(target_os = "none")]
    let source = 0x088ffd30 as *const u8;
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
    use crate::cxx::string::{cxx_string_copy_ctor, StringRep};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    #[repr(C)]
    struct Fixture {
        controller: NowPlayingHighlightController,
        retained: *mut u8,
        retain: bool,
        calls: u32,
    }

    unsafe extern "C" fn display(controller: *mut NowPlayingHighlightController, message: *mut *mut u8) {
        unsafe {
            let fixture = &mut *controller.cast::<Fixture>();
            assert_eq!(core::slice::from_raw_parts(*message, 6), LAYOUT_SOURCE);
            assert_eq!(free_log().0, 0, "temporary must remain alive during dispatch");
            fixture.calls += 1;
            if fixture.retain {
                cxx_string_copy_ctor(&mut fixture.retained, message);
            }
        }
    }

    fn exercise(retain: bool) {
        let _heap = mock_heap();
        let vtable = NowPlayingHighlightVtable { unresolved_00_118: [0; 71], display };
        let mut fixture = Fixture {
            controller: NowPlayingHighlightController { vtable: &vtable },
            retained: core::ptr::null_mut(), retain, calls: 0,
        };
        let mut allocation = [0u32; 16];
        unsafe {
            let rep = allocation.as_mut_ptr().cast::<StringRep>();
            set_alloc_ret(rep.cast());
            assert_eq!(show_now_playing_highlight(&mut fixture.controller), 1);
            assert_eq!(fixture.calls, 1);
            if retain {
                assert_eq!((*rep).refcount, 0, "only the retained owner survives");
                assert_eq!(free_log().0, 0);
                assert_eq!(core::slice::from_raw_parts(fixture.retained, 6), LAYOUT_SOURCE);
                cxx_string_release(&mut fixture.retained);
            } else {
                assert_eq!((*rep).refcount, -1);
            }
            assert_eq!(free_log(), (1, rep.cast(), 2));
        }
    }

    #[test]
    fn releases_unretained_temporary_after_display() { exercise(false); }

    #[test]
    fn retained_layout_survives_temporary_release() { exercise(true); }
}
