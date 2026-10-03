//! Photo highlight layout dispatch.
//!
//! `show_photo_highlight` — `FUN_0822e718` @ `0x0822e718`.
//! True extent: 144 bytes through 0x0822e7a8 (108 code bytes and 36
//! padded string bytes). Raw words verify six plain outbound BLs, zero
//! predicated BLs and one virtual BLX; inbound: BLNE at 0x0822d488 and
//! plain BL at 0x0823092c. Sets controller highlight byte +0xb0 to 5,
//! calls the photo-browse singleton and queries 0x081cc7bc with argument 0.
//! Zero selects EmptyPhotosHilited; any nonzero result activates artwork
//! slot 3 and selects PhotosHilited. Displays a temporary COW string through
//! vtable +0x11c, releases it, and returns handled (1).
//! Deviations: unused input registers and allocator-tag stack residue omitted
//! following the existing string port. Reuses the video controller layout
//! (native-width host pointers, checked target offsets). The query remains
//! an unported firmware seam: its result is tested, not assigned a speculative
//! object identity. Artwork activation reuses the verified existing seam.

use super::singletons::{photo_browse_slideshow_get, singleton_class_7f80};
use super::video_highlight_display::{artwork_slot_activate, VideoHighlightController};
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

unsafe extern "C" fn photo_highlight_query_result(controller: *mut u8, argument: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let f: unsafe extern "C" fn(*mut u8, u32) -> u32 = unsafe { core::mem::transmute(0x081cc7bcusize) };
        unsafe { f(controller, argument) }
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (controller, argument); panic!("requires photo query at 0x081cc7bc"); }
}

#[cfg(not(target_os = "none"))]
struct HostOps {
    browse: unsafe extern "C" fn() -> *mut u8,
    query: unsafe extern "C" fn(*mut u8, u32) -> u32,
    artwork: unsafe extern "C" fn() -> *mut u8,
    activate: unsafe extern "C" fn(*mut u8, u32),
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    browse: photo_browse_slideshow_get, query: photo_highlight_query_result,
    artwork: singleton_class_7f80, activate: artwork_slot_activate,
};

const EMPTY: &[u8] = b"EmptyPhotosHilited\0";
const PHOTOS: &[u8] = b"PhotosHilited\0";

/// # Safety
/// Controller must have a writable highlight byte and valid display vtable.
/// Firmware dependencies must be initialized; display must not retain the
/// temporary slot itself (copying the COW string is permitted).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn show_photo_highlight(controller: *mut VideoHighlightController) -> u32 {
    #[cfg(target_os = "none")]
    let (browse, query, artwork, activate) = (
        photo_browse_slideshow_get, photo_highlight_query_result,
        singleton_class_7f80, artwork_slot_activate,
    );
    #[cfg(not(target_os = "none"))]
    let (browse, query, artwork, activate) = unsafe {
        (HOST_OPS.browse, HOST_OPS.query, HOST_OPS.artwork, HOST_OPS.activate)
    };
    unsafe { (*controller).highlight = 5 };
    let source = if unsafe { query(browse(), 0) } == 0 {
        EMPTY
    } else {
        unsafe { activate(artwork(), 3) };
        PHOTOS
    };
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
    use super::super::video_highlight_display::VideoHighlightVtable;
    use crate::cxx::string::{cxx_string_copy_ctor, StringRep};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    static mut RESULT: u32 = 0;
    static mut ARTWORK_GETS: u32 = 0;
    static mut ACTIVATIONS: u32 = 0;
    unsafe extern "C" fn browse() -> *mut u8 { core::ptr::dangling_mut() }
    unsafe extern "C" fn query(controller: *mut u8, argument: u32) -> u32 {
        assert_eq!(controller, core::ptr::dangling_mut());
        assert_eq!(argument, 0);
        unsafe { RESULT }
    }
    unsafe extern "C" fn artwork() -> *mut u8 {
        unsafe { ARTWORK_GETS += 1 };
        core::ptr::dangling_mut()
    }
    unsafe extern "C" fn activate(cache: *mut u8, slot: u32) {
        assert_eq!(cache, core::ptr::dangling_mut());
        assert_eq!(slot, 3);
        unsafe { ACTIVATIONS += 1 };
    }
    #[repr(C)]
    struct Fixture {
        controller: VideoHighlightController,
        expected: &'static [u8],
        expected_activations: u32,
        retained: *mut u8,
    }
    unsafe extern "C" fn display(controller: *mut VideoHighlightController, message: *mut *mut u8) {
        unsafe {
            let f = &mut *controller.cast::<Fixture>();
            assert_eq!(f.controller.highlight, 5);
            assert_eq!(ACTIVATIONS, f.expected_activations);
            assert_eq!(core::slice::from_raw_parts(*message, f.expected.len()), f.expected);
            assert_eq!(free_log().0, 0);
            cxx_string_copy_ctor(&mut f.retained, message);
        }
    }
    #[test]
    fn zero_and_nonzero_results_preserve_controller_and_cow_lifetime() {
        let vtable = VideoHighlightVtable { unresolved_00_118: [0; 71], display };
        for (result, expected, activations) in [(0, EMPTY, 0), (1, PHOTOS, 1), (u32::MAX, PHOTOS, 1)] {
            let _heap = mock_heap();
            let mut allocation = [0u32; 16];
            let mut f = Fixture {
                controller: VideoHighlightController { vtable: &vtable, opaque_04_af: [0xdeadbeef; 43], highlight: 0xff },
                expected, expected_activations: activations, retained: core::ptr::null_mut(),
            };
            unsafe {
                let old = core::ptr::addr_of!(HOST_OPS).read();
                HOST_OPS = HostOps { browse, query, artwork, activate };
                RESULT = result; ARTWORK_GETS = 0; ACTIVATIONS = 0;
                let rep = allocation.as_mut_ptr().cast::<StringRep>();
                set_alloc_ret(rep.cast());
                assert_eq!(show_photo_highlight(&mut f.controller), 1);
                assert_eq!(ARTWORK_GETS, activations);
                assert_eq!(f.controller.opaque_04_af, [0xdeadbeef; 43]);
                assert_eq!((*rep).refcount, 0);
                assert_eq!(core::slice::from_raw_parts(f.retained, expected.len()), expected);
                cxx_string_release(&mut f.retained);
                assert_eq!(free_log(), (1, rep.cast(), 2));
                HOST_OPS = old;
            }
        }
    }
}
