//! `media_player_set_volume` — original: `FUN_081116e0` @ **0x081116e0**.
//!
//! Raw `osos.dec` establishes the **164-byte** instruction extent
//! `0x081116e0..0x08111784`; four literal-pool words follow and the next real
//! function begins at `0x08111794`. Raw ARM decoding finds **3 plain
//! unconditional `bl` callers and 0 predicated `bl` callers**. The body itself
//! has five direct `bl` instructions: two calls to `instance_of_class_6000`,
//! and one each to the unported class-0x6000 helper, an empty function, and
//! `resource_chain_write`.
//! # Algorithm
//!
//! Store the requested volume at `player + 0x464`, invoke the unported helper
//! at `0x08172004` on the class-0x6000 singleton, conditionally change
//! `player + 0x494` from zero to ten, and write `(raw kind 0x70724944, id
//! 0x6031, value 0x6035, flags 4)` to the singleton's resource-provider chain.
//! Finally dispatch player vtable slot `+0x58` with the two verified opaque
//! words `0x089ca660` and `0x63f9`.
//!
//! # Deliberate deviations
//!
//! `FUN_082898dc` is an empty body and is omitted. The helper at `0x08172004`
//! and terminal virtual dispatch have no established semantic identity, so
//! host builds expose them as seams while target builds call their verified
//! ABI shapes directly.

#[cfg(target_os = "none")]
use crate::app::registry::instance_of_class_6000;
use crate::app::resource_chain::ResourceKind;
#[cfg(target_os = "none")]
use crate::app::resource_chain::{resource_chain_write, ResourceProvider};

const VOLUME_OFFSET: usize = 0x464;
const RESOURCE_WRITE_GATE_OFFSET: usize = 0x488;
const RETRY_STATE_OFFSET: usize = 0x494;
const RESOURCE_KIND_RAW: u32 = 0x7072_4944;
const RESOURCE_ID: u32 = 0x6031;
const RESOURCE_VALUE: u32 = 0x6035;
const RESOURCE_FLAGS: u32 = 4;
const TERMINAL_FIRST: u32 = 0x089c_a660;
const TERMINAL_SECOND: u32 = 0x63f9;

#[cfg(not(target_os = "none"))]
pub type Class6000Update = unsafe extern "C" fn(*mut u8, u32);
#[cfg(not(target_os = "none"))]
pub type ResourceWrite = unsafe extern "C" fn(*mut u8, ResourceKind, u32, u32, u32);
#[cfg(not(target_os = "none"))]
pub type TerminalDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct MediaPlayerSetVolumeOps {
    pub instance: unsafe extern "C" fn() -> *mut u8,
    pub class6000_update: Class6000Update,
    pub resource_write: ResourceWrite,
    pub terminal_dispatch: TerminalDispatch,
    pub gate: *const u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_instance() -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(_: *mut u8, _: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_write(_: *mut u8, _: ResourceKind, _: u32, _: u32, _: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_: *mut u8, _: u32, _: u32) {}
#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEDIA_PLAYER_SET_VOLUME_OPS: MediaPlayerSetVolumeOps = MediaPlayerSetVolumeOps {
    instance: missing_instance, class6000_update: missing_update, resource_write: missing_write,
    terminal_dispatch: missing_dispatch, gate: core::ptr::null(),
};
#[cfg(not(target_os = "none"))]
pub static mut MEDIA_PLAYER_SET_VOLUME_OPS: MediaPlayerSetVolumeOps = DEFAULT_MEDIA_PLAYER_SET_VOLUME_OPS;

#[cfg(target_os = "none")]
unsafe fn class6000_update(store: *mut u8, volume: u32) {
    let update: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(0x0817_2004usize);
    update(store, volume);
}

#[cfg(target_os = "none")]
unsafe fn terminal_dispatch(player: *mut u8) {
    let vtable = player.cast::<*const usize>().read_volatile();
    let dispatch: unsafe extern "C" fn(*mut u8, u32, u32) = core::mem::transmute(vtable.add(0x58 / 4).read_volatile());
    dispatch(player, TERMINAL_FIRST, TERMINAL_SECOND);
}

/// Sets the media player's stored volume and publishes the associated resource update.
///
/// # Safety
/// `player` must be a writable retail media-player object through `+0x494`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_set_volume(player: *mut u8, volume: u32) {
    player.add(VOLUME_OFFSET).cast::<u32>().write_volatile(volume);
    #[cfg(target_os = "none")]
    let store = instance_of_class_6000();
    #[cfg(not(target_os = "none"))]
    let operations = core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_PLAYER_SET_VOLUME_OPS));
    #[cfg(not(target_os = "none"))]
    let store = (operations.instance)();
    #[cfg(target_os = "none")]
    class6000_update(store, volume);
    #[cfg(not(target_os = "none"))]
    (operations.class6000_update)(store, volume);

    let should_write = player.add(RESOURCE_WRITE_GATE_OFFSET).cast::<u32>().read_volatile() == 0
        || {
            #[cfg(target_os = "none")]
            let enabled = (TERMINAL_FIRST as *const u8).read_volatile() != 0;
            #[cfg(not(target_os = "none"))]
            let enabled = !operations.gate.is_null() && operations.gate.read_volatile() != 0;
            if enabled && player.add(RETRY_STATE_OFFSET).cast::<u32>().read_volatile() == 0 {
                player.add(RETRY_STATE_OFFSET).cast::<u32>().write_volatile(10);
                true
            } else { false }
        };
    if should_write {
        #[cfg(target_os = "none")]
        resource_chain_write(store.cast::<ResourceProvider>(), ResourceKind(RESOURCE_KIND_RAW), RESOURCE_ID, RESOURCE_VALUE, RESOURCE_FLAGS);
        #[cfg(not(target_os = "none"))]
        (operations.resource_write)(store, ResourceKind(RESOURCE_KIND_RAW), RESOURCE_ID, RESOURCE_VALUE, RESOURCE_FLAGS);
    }
    #[cfg(target_os = "none")]
    terminal_dispatch(player);
    #[cfg(not(target_os = "none"))]
    (operations.terminal_dispatch)(player, TERMINAL_FIRST, TERMINAL_SECOND);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicU32, Ordering};
    static WRITES: AtomicU32 = AtomicU32::new(0);
    static UPDATES: AtomicU32 = AtomicU32::new(0);
    static DISPATCHES: AtomicU32 = AtomicU32::new(0);
    static GATE: u8 = 1;
    unsafe extern "C" fn instance() -> *mut u8 { 0x1234usize as *mut u8 }
    unsafe extern "C" fn update(_: *mut u8, value: u32) { assert_eq!(value, 77); UPDATES.fetch_add(1, Ordering::Relaxed); }
    unsafe extern "C" fn write(_: *mut u8, kind: ResourceKind, id: u32, value: u32, flags: u32) { assert_eq!((kind.0, id, value, flags), (RESOURCE_KIND_RAW, RESOURCE_ID, RESOURCE_VALUE, RESOURCE_FLAGS)); WRITES.fetch_add(1, Ordering::Relaxed); }
    unsafe extern "C" fn dispatch(_: *mut u8, first: u32, second: u32) { assert_eq!((first, second), (TERMINAL_FIRST, TERMINAL_SECOND)); DISPATCHES.fetch_add(1, Ordering::Relaxed); }
    #[test]
    fn writes_only_for_the_clear_gate_or_an_enabled_first_retry() {
        let Some(player) = try_map_u32_slab(hints::MEDIA_PLAYER_SET_VOLUME, 0x500) else { return };
        unsafe { MEDIA_PLAYER_SET_VOLUME_OPS = MediaPlayerSetVolumeOps { instance, class6000_update: update, resource_write: write, terminal_dispatch: dispatch, gate: core::ptr::addr_of!(GATE) }; }
        WRITES.store(0, Ordering::Relaxed); UPDATES.store(0, Ordering::Relaxed); DISPATCHES.store(0, Ordering::Relaxed);
        unsafe { player.add(RESOURCE_WRITE_GATE_OFFSET).cast::<u32>().write_volatile(1); player.add(RETRY_STATE_OFFSET).cast::<u32>().write_volatile(9); media_player_set_volume(player, 77); }
        assert_eq!(WRITES.load(Ordering::Relaxed), 0, "occupied retry state blocks a nonzero gate");
        unsafe { player.add(RETRY_STATE_OFFSET).cast::<u32>().write_volatile(0); media_player_set_volume(player, 77); }
        assert_eq!(unsafe { player.add(VOLUME_OFFSET).cast::<u32>().read_volatile() }, 77);
        assert_eq!(unsafe { player.add(RETRY_STATE_OFFSET).cast::<u32>().read_volatile() }, 10);
        assert_eq!(WRITES.load(Ordering::Relaxed), 1);
        unsafe { player.add(RESOURCE_WRITE_GATE_OFFSET).cast::<u32>().write_volatile(0); media_player_set_volume(player, 77); }
        assert_eq!((UPDATES.load(Ordering::Relaxed), WRITES.load(Ordering::Relaxed), DISPATCHES.load(Ordering::Relaxed)), (3, 2, 3));
    }
}
