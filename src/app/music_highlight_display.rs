//! Music highlight layout dispatch.
//!
//! `show_music_highlight` — `FUN_0822e160` @ `0x0822e160`.
//! True extent: 208 bytes, `0x0822e160..0x0822e230`: 144 instruction
//! bytes, one global-pointer literal and 60 bytes of padded strings.
//! Raw A32 verifies two inbound plain BLs (0x0822d768, 0x082308ec),
//! five outbound plain BLs, zero predicated BLs, and one virtual BLX.
//! Sets controller byte +0xb0 to 1 before acquiring the class-0x7f80
//! singleton. Zero global object word +0x3f8 selects EmptyMusicHilited;
//! otherwise missing artwork slot 0 selects NoArtMusicHilited, or activates
//! slot 0 and selects MediaContentHilited. Displays a temporary COW string
//! through vtable +0x11c, releases it, and returns handled (1).
//! Deviations: unused input registers and allocator-tag stack residue omitted
//! as in the existing COW-string port. Reuses the checked target controller
//! layout with native-width host vtable pointers and host dependency overrides.
//! Activation remains the existing verified firmware seam at 0x081b6dd8.

use super::artwork_slot_available::artwork_slot_available;
use super::singletons::singleton_class_7f80;
use super::video_highlight_display::{artwork_slot_activate, VideoHighlightController};
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

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
pub static mut MUSIC_HIGHLIGHT_OBJECT: *const u32 = core::ptr::null();

const EMPTY: &[u8] = b"EmptyMusicHilited\0";
const NO_ART: &[u8] = b"NoArtMusicHilited\0";
const CONTENT: &[u8] = b"MediaContentHilited\0";

/// # Safety
/// The global object must be readable through +0x3f8; the controller must
/// have a valid display vtable and writable highlight byte. The singleton
/// must satisfy both artwork callees; display must not retain the slot itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn show_music_highlight(controller: *mut VideoHighlightController) -> u32 {
    unsafe { (*controller).highlight = 1 };
    #[cfg(target_os = "none")]
    let (get, available, activate) = (singleton_class_7f80, artwork_slot_available, artwork_slot_activate);
    #[cfg(not(target_os = "none"))]
    let (get, available, activate) = unsafe { (HOST_OPS.get, HOST_OPS.available, HOST_OPS.activate) };
    let cache = unsafe { get() };
    #[cfg(target_os = "none")]
    let object = unsafe { (0x089ca674 as *const *const u32).read() };
    #[cfg(not(target_os = "none"))]
    let object = unsafe { core::ptr::addr_of!(MUSIC_HIGHLIGHT_OBJECT).read() };
    let source = if unsafe { object.add(0x3f8 / 4).read() } == 0 {
        EMPTY
    } else if unsafe { available(cache, 0) }.is_null() {
        NO_ART
    } else {
        unsafe { activate(cache, 0) };
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
    use super::super::video_highlight_display::VideoHighlightVtable;
    use crate::cxx::string::{cxx_string_copy_ctor, StringRep};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    static mut CONTROLLER: *mut VideoHighlightController = core::ptr::null_mut();
    static mut AVAILABLE: bool = false;
    static mut QUERIES: u32 = 0;
    static mut ACTIVATIONS: u32 = 0;
    unsafe extern "C" fn get() -> *mut u8 {
        unsafe { assert_eq!((*CONTROLLER).highlight, 1); }
        core::ptr::dangling_mut()
    }
    unsafe extern "C" fn available(cache: *mut u8, slot: u32) -> *mut u8 {
        assert_eq!(cache, core::ptr::dangling_mut());
        assert_eq!(slot, 0);
        unsafe { QUERIES += 1; if AVAILABLE { core::ptr::dangling_mut() } else { core::ptr::null_mut() } }
    }
    unsafe extern "C" fn activate(cache: *mut u8, slot: u32) {
        assert_eq!(cache, core::ptr::dangling_mut());
        assert_eq!(slot, 0);
        unsafe { assert_eq!(QUERIES, 1); ACTIVATIONS += 1; }
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
            assert_eq!(f.controller.highlight, 1);
            assert_eq!(ACTIVATIONS, f.expected_activations);
            assert_eq!(core::slice::from_raw_parts(*message, f.expected.len()), f.expected);
            assert_eq!(free_log().0, 0);
            cxx_string_copy_ctor(&mut f.retained, message);
        }
    }
    #[test]
    fn branches_preserve_state_order_and_cow_lifetime() {
        let vtable = VideoHighlightVtable { unresolved_00_118: [0; 71], display };
        for (count, art, expected, queries, activations) in [
            (0, true, EMPTY, 0, 0), (0, false, EMPTY, 0, 0),
            (1, false, NO_ART, 1, 0), (1, true, CONTENT, 1, 1),
            (u32::MAX, true, CONTENT, 1, 1), (u32::MAX, false, NO_ART, 1, 0),
        ] {
            let _heap = mock_heap();
            let mut object = [0xa5a5a5a5u32; 266];
            object[0x3f8 / 4] = count;
            let original_object = object;
            let mut allocation = [0u32; 16];
            let mut f = Fixture {
                controller: VideoHighlightController { vtable: &vtable, opaque_04_af: [0xdeadbeef; 43], highlight: 0xff },
                expected, expected_activations: activations, retained: core::ptr::null_mut(),
            };
            unsafe {
                let old = core::ptr::addr_of!(HOST_OPS).read();
                HOST_OPS = HostOps { get, available, activate };
                MUSIC_HIGHLIGHT_OBJECT = object.as_ptr();
                CONTROLLER = &mut f.controller;
                AVAILABLE = art; QUERIES = 0; ACTIVATIONS = 0;
                let rep = allocation.as_mut_ptr().cast::<StringRep>();
                set_alloc_ret(rep.cast());
                assert_eq!(show_music_highlight(&mut f.controller), 1);
                assert_eq!(QUERIES, queries);
                assert_eq!(f.controller.opaque_04_af, [0xdeadbeef; 43]);
                assert_eq!(object, original_object);
                assert_eq!((*rep).refcount, 0);
                assert_eq!(core::slice::from_raw_parts(f.retained, expected.len()), expected);
                cxx_string_release(&mut f.retained);
                assert_eq!(free_log(), (1, rep.cast(), 2));
                HOST_OPS = old;
                MUSIC_HIGHLIGHT_OBJECT = core::ptr::null();
                CONTROLLER = core::ptr::null_mut();
            }
        }
    }
}
