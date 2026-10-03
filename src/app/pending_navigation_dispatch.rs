//! Pending navigation dispatch — FUN_082171e4 @ 0x082171e4.
//! True extent: 188 bytes through 0x082172a0 (156 code, 32 padded strings).
//! Raw words verify two inbound plain BLs, four outbound plain BLs, zero
//! predicated BLs, one virtual BLX and one virtual tail BX. Modes 1/2 display
//! PopNowPlaying/PopToMainMenu using a temporary COW string; modes 3/4 call
//! media-player interface slots +0xc0/+0xc4 with 3. Other modes clear +0xbf.
//! Deliberate deviations: omit unused registers and allocator-tag stack
//! residue as in cxx_string_from_cstr. Native-width host vtable pointers shift
//! the opaque prefix; target field offsets are checked. No NULL guards.
//! Uses the existing media-player getter (whose constructor caveat still applies).

use crate::app::singletons::media_player_interface_get;
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

#[repr(C)]
pub struct PendingNavigationController {
    pub vtable: *const PendingNavigationVtable,
    pub opaque_04_be: [u8; 0xbb],
    pub pending_navigation: u8,
}

#[repr(C)]
pub struct PendingNavigationVtable {
    pub unresolved_00_118: [usize; 71],
    pub display: unsafe extern "C" fn(*mut PendingNavigationController, *mut *mut u8),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xbf] = [0; core::mem::offset_of!(PendingNavigationController, pending_navigation)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x11c] = [0; core::mem::offset_of!(PendingNavigationVtable, display)];

#[inline(always)]
unsafe fn dispatch(controller: *mut PendingNavigationController, get_player: impl FnOnce() -> *mut u8) {
    let mode = (*controller).pending_navigation;
    match mode {
        1 | 2 => {
            let source: &[u8] = if mode == 1 { b"PopNowPlaying\0" } else { b"PopToMainMenu\0" };
            let mut message = core::ptr::null_mut();
            let slot = cxx_string_from_cstr(&mut message, source.as_ptr());
            ((*(*controller).vtable).display)(controller, slot);
            cxx_string_release(&mut message);
        }
        3 | 4 => {
            let player = get_player();
            let vtable = player.cast::<*const usize>().read();
            let method: unsafe extern "C" fn(*mut u8, u32) =
                core::mem::transmute(vtable.add(if mode == 3 { 48 } else { 49 }).read());
            method(player, 3);
        }
        _ => (*controller).pending_navigation = 0,
    }
}

/// Dispatches the pending navigation action without clearing recognized modes.
///
/// # Safety
/// `controller` must be writable; selected display/player vtable slots must be
/// valid. Display may retain the COW string data, but not its temporary slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_pending_navigation(controller: *mut PendingNavigationController) {
    dispatch(controller, || media_player_interface_get());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string::{cxx_string_copy_ctor, StringRep};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    #[repr(C)]
    struct Fixture {
        controller: PendingNavigationController,
        retained: *mut u8,
    }

    unsafe extern "C" fn display(controller: *mut PendingNavigationController, slot: *mut *mut u8) {
        let fixture = &mut *controller.cast::<Fixture>();
        let expected = if fixture.controller.pending_navigation == 1 { b"PopNowPlaying\0" } else { b"PopToMainMenu\0" };
        assert_eq!(core::slice::from_raw_parts(*slot, expected.len()), expected);
        assert_eq!(free_log().0, 0);
        cxx_string_copy_ctor(&mut fixture.retained, slot);
    }

    #[test]
    fn layout_string_remains_alive_when_display_retains_it() {
        let vtable = PendingNavigationVtable { unresolved_00_118: [0; 71], display };
        for mode in [1, 2] {
            let mut fixture = Fixture {
                controller: PendingNavigationController { vtable: &vtable, opaque_04_be: [0xa5; 0xbb], pending_navigation: mode },
                retained: core::ptr::null_mut(),
            };
            let _heap = mock_heap();
            let mut allocation = [0u32; 16];
            unsafe {
                let rep = allocation.as_mut_ptr().cast::<StringRep>();
                set_alloc_ret(rep.cast());
                // Exercise the exported function; these modes must never fetch a player.
                dispatch_pending_navigation(&mut fixture.controller);
                assert_eq!(fixture.controller.pending_navigation, mode);
                assert_eq!(fixture.controller.opaque_04_be, [0xa5; 0xbb]);
                assert_eq!((*rep).refcount, 0);
                let expected = if mode == 1 { b"PopNowPlaying\0" } else { b"PopToMainMenu\0" };
                assert_eq!(core::slice::from_raw_parts(fixture.retained, expected.len()), expected);
                cxx_string_release(&mut fixture.retained);
                assert_eq!((*rep).refcount, -1);
                assert_eq!(free_log().1, rep.cast());
            }
        }
    }

    #[repr(C)]
    struct Player { vtable: *const usize, selected: u32, reason: u32 }
    unsafe extern "C" fn slot_c0(player: *mut u8, reason: u32) {
        (*player.cast::<Player>()).selected = 0xc0;
        (*player.cast::<Player>()).reason = reason;
    }
    unsafe extern "C" fn slot_c4(player: *mut u8, reason: u32) {
        (*player.cast::<Player>()).selected = 0xc4;
        (*player.cast::<Player>()).reason = reason;
    }

    #[test]
    fn recognized_player_modes_preserve_state_and_select_distinct_actions() {
        let mut vtable = [0usize; 50];
        vtable[48] = slot_c0 as *const () as usize;
        vtable[49] = slot_c4 as *const () as usize;
        let mut player = Player { vtable: vtable.as_ptr(), selected: 0, reason: 0 };
        let mut controller = PendingNavigationController { vtable: core::ptr::null(), opaque_04_be: [0xa5; 0xbb], pending_navigation: 3 };
        for (mode, selected) in [(3, 0xc0), (4, 0xc4)] {
            controller.pending_navigation = mode;
            unsafe { dispatch(&mut controller, || core::ptr::addr_of_mut!(player).cast()); }
            assert_eq!((player.selected, player.reason), (selected, 3));
            assert_eq!(controller.pending_navigation, mode);
            assert_eq!(controller.opaque_04_be, [0xa5; 0xbb]);
        }
    }

    #[test]
    fn every_unrecognized_byte_clears_only_pending_action_without_dispatch() {
        let mut controller = PendingNavigationController { vtable: core::ptr::null(), opaque_04_be: [0xa5; 0xbb], pending_navigation: 0 };
        for mode in (0..=255u8).filter(|mode| !(1..=4).contains(mode)) {
            controller.pending_navigation = mode;
            unsafe { dispatch_pending_navigation(&mut controller); }
            assert_eq!(controller.pending_navigation, 0);
            assert_eq!(controller.opaque_04_be, [0xa5; 0xbb]);
        }
    }
}
