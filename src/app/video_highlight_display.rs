//! Video highlight layout dispatch.
//!
//! `show_video_highlight` — `FUN_0822e83c` @ `0x0822e83c`.
//! True extent: 208 bytes, 0x0822e83c..0x0822e90c: 144 code bytes,
//! one global-pointer literal and 60 bytes of padded strings. Raw A32 words
//! verify five plain outbound BLs, zero predicated BLs and one virtual BLX.
//! Inbound BLs: NE at 0x0822d3ec and plain at 0x082308fc.
//! Gets the class-0x7f80 singleton, sets controller byte +0xb0 to 2, and
//! chooses EmptyVideosHilited when global object +0x424 is zero. Otherwise
//! queries artwork slot 1: NULL selects NoArtVideosHilited; non-NULL activates
//! that slot and selects MediaContentHilited. Displays a temporary COW string
//! through vtable +0x11c, releases it, and returns handled (1).
//! Deviations: unused input registers and allocator-tag stack residue omitted
//! as in the existing COW-string port. Host vtable pointers are native width;
//! host-only operation replacement permits exercising firmware dependencies.
//! Slot activation remains the verified unported seam at 0x081b6dd8.

use super::artwork_slot_available::artwork_slot_available;
use super::singletons::singleton_class_7f80;
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

#[repr(C)]
pub struct VideoHighlightController {
    pub vtable: *const VideoHighlightVtable,
    pub opaque_04_af: [u32; 43],
    pub highlight: u8,
}

#[repr(C)]
pub struct VideoHighlightVtable {
    pub unresolved_00_118: [usize; 71],
    pub display: unsafe extern "C" fn(*mut VideoHighlightController, *mut *mut u8),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xb0] = [0; core::mem::offset_of!(VideoHighlightController, highlight)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x11c] = [0; core::mem::offset_of!(VideoHighlightVtable, display)];

unsafe extern "C" fn artwork_slot_activate(cache: *mut u8, slot: u32) {
    #[cfg(target_os = "none")]
    {
        let f: unsafe extern "C" fn(*mut u8, u32) = unsafe { core::mem::transmute(0x081b6dd8usize) };
        unsafe { f(cache, slot) };
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (cache, slot); panic!("requires artwork slot activation at 0x081b6dd8"); }
}

#[cfg(not(target_os = "none"))]
struct HostOps {
    get: unsafe extern "C" fn() -> *mut u8,
    available: unsafe extern "C" fn(*mut u8, u32) -> *mut u8,
    activate: unsafe extern "C" fn(*mut u8, u32),
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    get: singleton_class_7f80, available: artwork_slot_available, activate: artwork_slot_activate,
};
#[cfg(not(target_os = "none"))]
pub static mut VIDEO_HIGHLIGHT_OBJECT: *const u32 = core::ptr::null();

const EMPTY: &[u8] = b"EmptyVideosHilited\0";
const NO_ART: &[u8] = b"NoArtVideosHilited\0";
const CONTENT: &[u8] = b"MediaContentHilited\0";

/// # Safety
/// The global object must be readable through +0x424; the controller must
/// have a valid display vtable and writable highlight byte. The singleton
/// must satisfy both artwork callees; display must not retain the slot itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn show_video_highlight(controller: *mut VideoHighlightController) -> u32 {
    #[cfg(target_os = "none")]
    let (get, available, activate) = (singleton_class_7f80, artwork_slot_available, artwork_slot_activate);
    #[cfg(not(target_os = "none"))]
    let (get, available, activate) = unsafe { (HOST_OPS.get, HOST_OPS.available, HOST_OPS.activate) };
    let cache = unsafe { get() };
    #[cfg(target_os = "none")]
    let object = unsafe { (0x089ca674 as *const *const u32).read() };
    #[cfg(not(target_os = "none"))]
    let object = unsafe { core::ptr::addr_of!(VIDEO_HIGHLIGHT_OBJECT).read() };
    unsafe { (*controller).highlight = 2 };
    let source = if unsafe { object.add(0x424 / 4).read() } == 0 {
        EMPTY
    } else if unsafe { available(cache, 1) }.is_null() {
        NO_ART
    } else {
        unsafe { activate(cache, 1) };
        CONTENT
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
    use crate::cxx::string::{cxx_string_copy_ctor, StringRep};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    static mut AVAILABLE: bool = false;
    static mut QUERIES: u32 = 0;
    static mut ACTIVATIONS: u32 = 0;
    unsafe extern "C" fn get() -> *mut u8 { core::ptr::dangling_mut() }
    unsafe extern "C" fn available(cache: *mut u8, slot: u32) -> *mut u8 {
        assert_eq!(cache, core::ptr::dangling_mut());
        assert_eq!(slot, 1);
        unsafe { QUERIES += 1; if AVAILABLE { core::ptr::dangling_mut() } else { core::ptr::null_mut() } }
    }
    unsafe extern "C" fn activate(cache: *mut u8, slot: u32) {
        assert_eq!(cache, core::ptr::dangling_mut());
        assert_eq!(slot, 1);
        unsafe { ACTIVATIONS += 1; }
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
            assert_eq!(f.controller.highlight, 2);
            assert_eq!(ACTIVATIONS, f.expected_activations);
            assert_eq!(core::slice::from_raw_parts(*message, f.expected.len()), f.expected);
            assert_eq!(free_log().0, 0);
            cxx_string_copy_ctor(&mut f.retained, message);
        }
    }
    #[test]
    fn branches_preserve_state_and_cow_lifetime() {
        let vtable = VideoHighlightVtable { unresolved_00_118: [0; 71], display };
        for (count, art, expected, queries, activations) in [
            (0, true, EMPTY, 0, 0), (1, false, NO_ART, 1, 0),
            (1, true, CONTENT, 1, 1), (u32::MAX, true, CONTENT, 1, 1),
        ] {
            let _heap = mock_heap();
            let mut object = [0u32; 266];
            object[265] = count;
            let mut allocation = [0u32; 16];
            let mut f = Fixture {
                controller: VideoHighlightController { vtable: &vtable, opaque_04_af: [0xdeadbeef; 43], highlight: 0xff },
                expected, expected_activations: activations, retained: core::ptr::null_mut(),
            };
            unsafe {
                let old = core::ptr::addr_of!(HOST_OPS).read();
                HOST_OPS = HostOps { get, available, activate };
                VIDEO_HIGHLIGHT_OBJECT = object.as_ptr();
                AVAILABLE = art; QUERIES = 0; ACTIVATIONS = 0;
                let rep = allocation.as_mut_ptr().cast::<StringRep>();
                set_alloc_ret(rep.cast());
                assert_eq!(show_video_highlight(&mut f.controller), 1);
                assert_eq!(QUERIES, queries);
                assert_eq!(f.controller.opaque_04_af, [0xdeadbeef; 43]);
                assert_eq!(object[265], count);
                assert_eq!((*rep).refcount, 0);
                assert_eq!(core::slice::from_raw_parts(f.retained, expected.len()), expected);
                cxx_string_release(&mut f.retained);
                assert_eq!(free_log(), (1, rep.cast(), 2));
                HOST_OPS = old;
                VIDEO_HIGHLIGHT_OBJECT = core::ptr::null();
            }
        }
    }
}
