//! `media_player_enabled_update` — original: `FUN_081ffc68` @
//! **0x081ffc68** (**140 bytes**, exactly `0x081ffc68..0x081ffcf4`; the next
//! function begins at `0x081ffcf4`).
//!
//! # Algorithm
//!
//! Canonicalizes `enabled` to zero or one, reads the media-player interface's
//! vtable `+0x90` state query, then clears registration slot 13 when `kind` is
//! zero or registers `{kind, value, 0}` there otherwise. If the queried state
//! differs from `enabled`, it invokes the vtable `+0x8c` state setter. Returns
//! zero regardless of either slot-table helper's result.
//!
//! Raw-word decoding finds three unconditional direct `bl` instructions
//! (`media_player_interface_get`, `slot_table_register`, and
//! `slot_table_clear`), no predicated direct `bl`, one unconditional dynamic
//! `blx` at `+0x90`, and one predicated dynamic `blxne` at `+0x8c`.
//!
//! # Deliberate deviations
//!
//! Retail's target-width vtable occupies 32-bit words. Host fixtures use
//! native-width function pointers and a getter seam; target builds call the
//! existing singleton getter and recover the two function words by their
//! verified target offsets.

use crate::app::slot_table::{slot_table_clear, slot_table_register};

const SLOT: i32 = 13;
const SET_ENABLED_SLOT: usize = 0x8c / 4;
const ENABLED_SLOT: usize = 0x90 / 4;

type SetEnabled = unsafe extern "C" fn(*mut u8, u32);
type Enabled = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe fn media_player_enabled(interface: *mut u8) -> u32 {
    let vtable = interface.cast::<u32>().read_volatile() as usize as *const u32;
    let enabled: Enabled = core::mem::transmute(vtable.add(ENABLED_SLOT).read_volatile() as usize);
    enabled(interface)
}

#[cfg(target_os = "none")]
unsafe fn set_media_player_enabled(interface: *mut u8, enabled: u32) {
    let vtable = interface.cast::<u32>().read_volatile() as usize as *const u32;
    let set_enabled: SetEnabled = core::mem::transmute(vtable.add(SET_ENABLED_SLOT).read_volatile() as usize);
    set_enabled(interface, enabled);
}

#[cfg(target_os = "none")]
unsafe fn media_player_interface() -> *mut u8 {
    unsafe { super::singletons::media_player_interface_get() }
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostMediaPlayerEnabledVtable {
    pub unresolved_00_to_88: [usize; SET_ENABLED_SLOT],
    pub set_enabled: SetEnabled,
    pub enabled: Enabled,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostMediaPlayerEnabledInterface {
    pub vtable: *const HostMediaPlayerEnabledVtable,
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct MediaPlayerEnabledUpdateOps {
    pub get_interface: unsafe extern "C" fn() -> *mut HostMediaPlayerEnabledInterface,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_interface() -> *mut HostMediaPlayerEnabledInterface {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEDIA_PLAYER_ENABLED_UPDATE_OPS: MediaPlayerEnabledUpdateOps =
    MediaPlayerEnabledUpdateOps { get_interface: missing_interface };

#[cfg(not(target_os = "none"))]
pub static mut MEDIA_PLAYER_ENABLED_UPDATE_OPS: MediaPlayerEnabledUpdateOps =
    DEFAULT_MEDIA_PLAYER_ENABLED_UPDATE_OPS;

#[cfg(not(target_os = "none"))]
unsafe fn media_player_interface() -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_PLAYER_ENABLED_UPDATE_OPS.get_interface))().cast()
}

#[cfg(not(target_os = "none"))]
unsafe fn media_player_enabled(interface: *mut u8) -> u32 {
    let interface = &*interface.cast::<HostMediaPlayerEnabledInterface>();
    ((*interface.vtable).enabled)(interface as *const _ as *mut u8)
}

#[cfg(not(target_os = "none"))]
unsafe fn set_media_player_enabled(interface: *mut u8, enabled: u32) {
    let interface = &*interface.cast::<HostMediaPlayerEnabledInterface>();
    ((*interface.vtable).set_enabled)(interface as *const _ as *mut u8, enabled);
}

/// Updates slot 13 and the media-player enabled state.
///
/// # Safety
///
/// On target, the singleton getter must return an interface with a readable
/// vtable and callable `+0x8c`/`+0x90` slots. `this` is forwarded to the slot
/// table but otherwise not dereferenced, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_enabled_update(
    this: *mut u8, enabled: u32, kind: i32, value: u32,
) -> u32 {
    let enabled = u32::from(enabled != 0);
    let interface = media_player_interface();
    let was_enabled = media_player_enabled(interface);

    if kind == 0 {
        slot_table_clear(this, SLOT);
    } else {
        slot_table_register(this, SLOT, kind, value, 0);
    }

    if was_enabled != enabled {
        set_media_player_enabled(interface, enabled);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::slot_table::{Slot, SLOT_KIND_FREE, SLOTS};
    use core::ptr;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INTERFACE: *mut HostMediaPlayerEnabledInterface = ptr::null_mut();
    static mut ENABLED: u32 = 0;
    static mut SET_CALLS: u32 = 0;

    unsafe extern "C" fn get_interface() -> *mut HostMediaPlayerEnabledInterface { INTERFACE }
    unsafe extern "C" fn enabled(_: *mut u8) -> u32 { ENABLED }
    unsafe extern "C" fn set_enabled(_: *mut u8, value: u32) {
        SET_CALLS += 1;
        ENABLED = value;
    }

    static VTABLE: HostMediaPlayerEnabledVtable = HostMediaPlayerEnabledVtable {
        unresolved_00_to_88: [0; SET_ENABLED_SLOT], set_enabled, enabled,
    };

    unsafe fn reset_slot() {
        let slot = (ptr::addr_of_mut!(SLOTS) as *mut Slot).add(SLOT as usize);
        ptr::write(slot, Slot { occupied: 0, reserved: [0; 3], kind: SLOT_KIND_FREE, value_a: 0, value_b: 0 });
    }

    #[test]
    fn registers_slot_and_canonicalizes_nonzero_enabled() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = unsafe { ptr::read_volatile(ptr::addr_of!(MEDIA_PLAYER_ENABLED_UPDATE_OPS)) };
        let mut interface = HostMediaPlayerEnabledInterface { vtable: &VTABLE };
        unsafe {
            INTERFACE = &mut interface;
            ENABLED = 0;
            SET_CALLS = 0;
            MEDIA_PLAYER_ENABLED_UPDATE_OPS = MediaPlayerEnabledUpdateOps { get_interface };
            reset_slot();
            assert_eq!(media_player_enabled_update(ptr::null_mut(), 0xfeed, 2, 0x1234_5678), 0);
            let slot = &*(ptr::addr_of!(SLOTS) as *const Slot).add(SLOT as usize);
            assert_eq!((slot.occupied, slot.kind, slot.value_a, slot.value_b), (1, 2, 0x1234_5678, 0));
            assert_eq!((ENABLED, SET_CALLS), (1, 1));
            reset_slot();
            MEDIA_PLAYER_ENABLED_UPDATE_OPS = previous;
        }
    }

    #[test]
    fn clears_slot_and_skips_setter_when_state_matches() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = unsafe { ptr::read_volatile(ptr::addr_of!(MEDIA_PLAYER_ENABLED_UPDATE_OPS)) };
        let mut interface = HostMediaPlayerEnabledInterface { vtable: &VTABLE };
        unsafe {
            INTERFACE = &mut interface;
            ENABLED = 0;
            SET_CALLS = 0;
            MEDIA_PLAYER_ENABLED_UPDATE_OPS = MediaPlayerEnabledUpdateOps { get_interface };
            let slot = (ptr::addr_of_mut!(SLOTS) as *mut Slot).add(SLOT as usize);
            ptr::write(slot, Slot { occupied: 1, reserved: [0; 3], kind: 2, value_a: 3, value_b: 4 });
            assert_eq!(media_player_enabled_update(ptr::null_mut(), 0, 0, 0xdead_beef), 0);
            assert_eq!(((*slot).occupied, (*slot).kind, (*slot).value_a, (*slot).value_b), (0, SLOT_KIND_FREE, 0, 0));
            assert_eq!((ENABLED, SET_CALLS), (0, 0));
            MEDIA_PLAYER_ENABLED_UPDATE_OPS = previous;
        }
    }
}
