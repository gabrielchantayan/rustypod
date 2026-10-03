//! Podcast highlight layout dispatch.
//!
//! `show_podcast_highlight` — `FUN_0822f1f4` @ `0x0822f1f4`.
//! True extent: 140 bytes, 0x0822f1f4..0x0822f280 (88 code, 4-byte
//! global-pointer literal, 48 bytes of padded strings). Raw A32 decoding
//! verifies three plain outbound BLs, zero predicated outbound BLs, and one
//! virtual BLX. Inbound BLs: plain at 0x0823090c, NE at 0x0822d414.
//! Loads the object pointer from 0x089ca674, sets controller byte +0xb0 to 3,
//! queries object_word_at_f0_or_zero, chooses EmptyPodcastsHilited for zero
//! or NoArtPodcastsHilited otherwise, constructs a COW string, dispatches
//! through vtable +0x11c, releases the temporary, and returns 1.
//! Deliberate deviations: unused input registers and allocator-tag stack
//! residue are omitted, as in the existing COW-string port. Host builds use
//! a replaceable global object pointer and native-width vtable fields;
//! target offsets are checked. No NULL guards or behavioral deviations.

use crate::app::object_word_at_f0_or_zero::object_word_at_f0_or_zero;
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

#[repr(C)]
pub struct PodcastHighlightController {
    pub vtable: *const PodcastHighlightVtable,
    pub opaque_04_af: [u32; 43],
    pub highlight: u8,
}

#[repr(C)]
pub struct PodcastHighlightVtable {
    pub unresolved_00_118: [usize; 71],
    pub display: unsafe extern "C" fn(*mut PodcastHighlightController, *mut *mut u8),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xb0] = [0; core::mem::offset_of!(PodcastHighlightController, highlight)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x11c] = [0; core::mem::offset_of!(PodcastHighlightVtable, display)];

#[cfg(not(target_os = "none"))]
pub static mut PODCAST_HIGHLIGHT_OBJECT: *const u8 = core::ptr::null();

const EMPTY: &[u8] = b"EmptyPodcastsHilited\0";
const NO_ART: &[u8] = b"NoArtPodcastsHilited\0";

/// Displays the selected podcast highlight layout and reports handled (1).
///
/// # Safety
/// The firmware global (or host replacement) must point to an object readable
/// through +0xf0. `controller` must be writable with a valid display vtable;
/// the display method must not retain the temporary string slot itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn show_podcast_highlight(controller: *mut PodcastHighlightController) -> u32 {
    #[cfg(target_os = "none")]
    let object = unsafe { (0x089ca674 as *const *const u8).read() };
    #[cfg(not(target_os = "none"))]
    let object = unsafe { core::ptr::addr_of!(PODCAST_HIGHLIGHT_OBJECT).read() };
    unsafe { (*controller).highlight = 3 };
    let source = if unsafe { object_word_at_f0_or_zero(object) } == 0 { EMPTY } else { NO_ART };
    let mut message = core::ptr::null_mut();
    unsafe {
        let slot = cxx_string_from_cstr(&mut message, source.as_ptr());
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
        controller: PodcastHighlightController,
        expected: &'static [u8],
        retained: *mut u8,
        retain: bool,
        calls: u32,
    }

    unsafe extern "C" fn display(controller: *mut PodcastHighlightController, message: *mut *mut u8) {
        unsafe {
            let fixture = &mut *controller.cast::<Fixture>();
            assert_eq!(fixture.controller.highlight, 3, "state set before dispatch");
            assert_eq!(core::slice::from_raw_parts(*message, fixture.expected.len()), fixture.expected);
            assert_eq!(free_log().0, 0, "temporary alive during dispatch");
            fixture.calls += 1;
            if fixture.retain { cxx_string_copy_ctor(&mut fixture.retained, message); }
        }
    }

    fn exercise(word: i32, expected: &'static [u8], retain: bool) {
        let _heap = mock_heap();
        let vtable = PodcastHighlightVtable { unresolved_00_118: [0; 71], display };
        let mut fixture = Fixture {
            controller: PodcastHighlightController { vtable: &vtable, opaque_04_af: [0xdeadbeef; 43], highlight: 0xff },
            expected, retained: core::ptr::null_mut(), retain, calls: 0,
        };
        let mut object = [0i32; 61];
        object[60] = word;
        let mut allocation = [0u32; 16];
        unsafe {
            core::ptr::addr_of_mut!(PODCAST_HIGHLIGHT_OBJECT).write(object.as_ptr().cast());
            let rep = allocation.as_mut_ptr().cast::<StringRep>();
            set_alloc_ret(rep.cast());
            assert_eq!(show_podcast_highlight(&mut fixture.controller), 1);
            assert_eq!(fixture.calls, 1);
            assert_eq!(fixture.controller.opaque_04_af, [0xdeadbeef; 43]);
            assert_eq!(object[60], word);
            if retain {
                assert_eq!((*rep).refcount, 0);
                assert_eq!(free_log().0, 0);
                assert_eq!(core::slice::from_raw_parts(fixture.retained, expected.len()), expected);
                cxx_string_release(&mut fixture.retained);
            } else { assert_eq!((*rep).refcount, -1); }
            assert_eq!(free_log(), (1, rep.cast(), 2));
            core::ptr::addr_of_mut!(PODCAST_HIGHLIGHT_OBJECT).write(core::ptr::null());
        }
    }

    #[test]
    fn zero_and_sentinel_select_empty() {
        exercise(0, EMPTY, false);
        exercise(-1, EMPTY, false);
    }

    #[test]
    fn other_words_select_no_art_and_retained_string_survives() {
        for word in [1, -2, i32::MIN, i32::MAX] { exercise(word, NO_ART, true); }
    }
}
