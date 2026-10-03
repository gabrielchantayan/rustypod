//! GMT-offset highlight display.
//!
//! `show_gmt_offset_highlight` — `FUN_0822ef20` @ `0x0822ef20`.
//! True extent: 72 bytes, 0x0822ef20..0x0822ef68 (68 code, four-byte
//! source literal). Raw A32 verifies two plain outbound BLs, no predicated
//! outbound BLs, and one virtual BLX. Inbound calls: BLNE at 0x0822d43c,
//! plain BL at 0x0823091c. Sets controller byte +0xb0 to 4, constructs a
//! temporary COW string from 0x088ffd48, invokes vtable +0x11c, releases
//! the string, and returns 1 irrespective of the display method's result.
//! The raw source is `GMT + %d 小時 %d 分鐘`; percent sequences are not formatted.
//! Deliberate deviations: omit unused input registers and allocator-tag
//! stack residue, following cxx_string_from_cstr. Reuse the existing
//! highlight-controller ABI; host pointers are native-width, target offsets
//! are checked by that module. No NULL guards or behavioral deviations.

use crate::app::podcast_highlight_display::PodcastHighlightController;
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

const MESSAGE: &[u8] = b"GMT + %d \xe5\xb0\x8f\xe6\x99\x82 %d \xe5\x88\x86\xe9\x90\x98\0";

/// Displays the firmware GMT-offset string with highlight state 4.
///
/// # Safety
/// `controller` must be writable and have a valid display vtable. The
/// display method may copy the string but must not retain its stack slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn show_gmt_offset_highlight(controller: *mut PodcastHighlightController) -> u32 {
    unsafe { (*controller).highlight = 4 };
    let mut message = core::ptr::null_mut();
    unsafe {
        let slot = cxx_string_from_cstr(&mut message, MESSAGE.as_ptr());
        ((*(*controller).vtable).display)(controller, slot);
        cxx_string_release(&mut message);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::podcast_highlight_display::PodcastHighlightVtable;
    use crate::cxx::string::{cxx_string_copy_ctor, StringRep};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    #[repr(C)]
    struct Fixture {
        controller: PodcastHighlightController,
        retain: bool,
        retained: *mut u8,
    }

    unsafe extern "C" fn display(controller: *mut PodcastHighlightController, slot: *mut *mut u8) {
        unsafe {
            let fixture = &mut *controller.cast::<Fixture>();
            assert_eq!(fixture.controller.highlight, 4);
            assert_eq!(core::slice::from_raw_parts(*slot, MESSAGE.len()), MESSAGE);
            assert_eq!(free_log().0, 0, "string must remain alive during dispatch");
            if fixture.retain { cxx_string_copy_ctor(&mut fixture.retained, slot); }
            fixture.controller.highlight = 0x7f;
        }
    }

    #[test]
    fn dispatch_preserves_callback_state_and_string_ownership() {
        for retain in [false, true] {
            let _heap = mock_heap();
            let vtable = PodcastHighlightVtable { unresolved_00_118: [0; 71], display };
            let mut fixture = Fixture {
                controller: PodcastHighlightController {
                    vtable: &vtable, opaque_04_af: [0xdeadbeef; 43], highlight: 0xff,
                },
                retain, retained: core::ptr::null_mut(),
            };
            let mut allocation = [0u32; 16];
            unsafe {
                let rep = allocation.as_mut_ptr().cast::<StringRep>();
                set_alloc_ret(rep.cast());
                assert_eq!(show_gmt_offset_highlight(&mut fixture.controller), 1);
                assert_eq!(fixture.controller.highlight, 0x7f);
                assert_eq!(fixture.controller.opaque_04_af, [0xdeadbeef; 43]);
                if retain {
                    assert_eq!((*rep).refcount, 0);
                    assert_eq!(free_log().0, 0);
                    assert_eq!(core::slice::from_raw_parts(fixture.retained, MESSAGE.len()), MESSAGE);
                    cxx_string_release(&mut fixture.retained);
                } else { assert_eq!((*rep).refcount, -1); }
                assert_eq!(free_log(), (1, rep.cast(), 2));
            }
        }
    }
}
