//! Select a media-player index — FUN_081ffcf4 @ 0x081ffcf4.
//! True extent: 96 bytes, ending at the next prologue at 0x081ffd54.
//! Verified inbound calls: two plain BL, zero predicated BL. Outgoing:
//! three plain BL (two player getters, one settings getter), three BLX.
//! Reject index >= the unsigned result of player slot +0xec with status 4.
//! Otherwise invoke settings slot +0xb8, reacquire the player, invoke slot
//! +0xa4 with (index, 0, 0, 0), and return 0 regardless of virtual results.
//! Deliberate deviations: host vtables use native pointer-width entries at
//! the same word indices. Tests replace only singleton lookup, not dispatch.
//! Existing singleton constructors are not hook-ready; this port inherits
//! that prerequisite. Virtual target identities are deliberately unresolved.

use core::mem::transmute;

type Getter = unsafe extern "C" fn() -> *mut u8;

unsafe fn slot(object: *mut u8, index: usize) -> usize {
    let vtable = unsafe { *(object as *const *const usize) };
    unsafe { *vtable.add(index) }
}

#[inline(always)]
unsafe fn select(index: u32, player_get: Getter, settings_get: Getter) -> u32 {
    let player = unsafe { player_get() };
    let count: unsafe extern "C" fn(*mut u8) -> u32 =
        unsafe { transmute(slot(player, 0xec / 4)) };
    if index >= unsafe { count(player) } {
        return 4;
    }
    let settings = unsafe { settings_get() };
    let prepare: unsafe extern "C" fn(*mut u8) =
        unsafe { transmute(slot(settings, 0xb8 / 4)) };
    unsafe { prepare(settings) };
    let player = unsafe { player_get() };
    let apply: unsafe extern "C" fn(*mut u8, u32, u32, u32, u32) =
        unsafe { transmute(slot(player, 0xa4 / 4)) };
    unsafe { apply(player, index, 0, 0, 0) };
    0
}

/// # Safety
/// Singleton objects and their recovered virtual slots must be valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_index_select(_unused: *mut u8, index: u32) -> u32 {
    unsafe { select(index, crate::app::singletons::media_player_interface_get,
        crate::cxx::settings::settings_get) }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[repr(C)]
    struct Player {
        vtable: *const usize,
        count: u32,
        selected: u32,
        arguments: [u32; 3],
    }
    #[repr(C)]
    struct Settings {
        vtable: *const usize,
        prepared: bool,
    }
    static mut FIRST: Player = Player { vtable: core::ptr::null(), count: 0, selected: u32::MAX, arguments: [1; 3] };
    static mut SECOND: Player = Player { vtable: core::ptr::null(), count: 0, selected: u32::MAX, arguments: [1; 3] };
    static mut SETTINGS: Settings = Settings { vtable: core::ptr::null(), prepared: false };

    unsafe extern "C" fn player_get() -> *mut u8 {
        if unsafe { (*core::ptr::addr_of!(SETTINGS)).prepared } {
            core::ptr::addr_of_mut!(SECOND).cast()
        } else {
            core::ptr::addr_of_mut!(FIRST).cast()
        }
    }
    unsafe extern "C" fn settings_get() -> *mut u8 { core::ptr::addr_of_mut!(SETTINGS).cast() }
    unsafe extern "C" fn count(player: *mut u8) -> u32 { unsafe { (*(player as *const Player)).count } }
    unsafe extern "C" fn prepare(settings: *mut u8) { unsafe { (*(settings as *mut Settings)).prepared = true } }
    unsafe extern "C" fn apply(player: *mut u8, index: u32, a: u32, b: u32, c: u32) {
        unsafe { (*(player as *mut Player)).selected = index; (*(player as *mut Player)).arguments = [a, b, c]; }
    }

    #[test]
    fn unsigned_bounds_and_reacquisition_after_settings_change() {
        let mut player_vtable = [0usize; 0xec / 4 + 1];
        player_vtable[0xec / 4] = count as *const () as usize;
        player_vtable[0xa4 / 4] = apply as *const () as usize;
        let mut settings_vtable = [0usize; 0xb8 / 4 + 1];
        settings_vtable[0xb8 / 4] = prepare as *const () as usize;
        for (limit, index) in [(0, 0), (1, 0), (1, 1), (3, 2), (3, 3),
            (3, u32::MAX), (u32::MAX, u32::MAX - 1), (u32::MAX, u32::MAX)] {
            unsafe {
                FIRST = Player { vtable: player_vtable.as_ptr(), count: limit, selected: u32::MAX, arguments: [1; 3] };
                SECOND = Player { vtable: player_vtable.as_ptr(), count: 0, selected: u32::MAX, arguments: [1; 3] };
                SETTINGS = Settings { vtable: settings_vtable.as_ptr(), prepared: false };
                assert_eq!(select(index, player_get, settings_get), if index < limit { 0 } else { 4 });
                assert_eq!((*core::ptr::addr_of!(FIRST)).selected, u32::MAX);
                assert_eq!((*core::ptr::addr_of!(SETTINGS)).prepared, index < limit);
                assert_eq!((*core::ptr::addr_of!(SECOND)).selected, if index < limit { index } else { u32::MAX });
                assert_eq!((*core::ptr::addr_of!(SECOND)).arguments, if index < limit { [0; 3] } else { [1; 3] });
            }
        }
    }
}
