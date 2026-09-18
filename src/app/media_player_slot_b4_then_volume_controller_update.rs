//! `media_player_slot_b4_then_volume_controller_update` — original:
//! `FUN_081f77d4` @ **0x081f77d4** (**40 bytes**;
//! `0x081f77d4..0x081f77fc`, followed by a separately linked function).
//!
//! # Algorithm
//!
//! Obtains the global media-player interface, invokes its unresolved vtable
//! slot `+0xb4` with a zero second argument, discards that result, then tail
//! dispatches the original volume-controller pointer to `FUN_081f9020`.
//! Neither dynamic operation has a recovered semantic identity, so the name
//! retains the verified structural roles.
//!
//! Raw ARM words establish the extent: `push {r4,lr}` opens at 0x081f77d4 and
//! the next `push {r4,lr}` opens at 0x081f77fc. There are **4 direct `bl`
//! callers, 0 predicated** (`0x08216900`, `0x08217194`, `0x0821c834`,
//! `0x0821e584`); this body has one outbound direct `bl`, one indirect `blx`,
//! and one direct tail branch.
//!
//! # Deliberate deviations
//!
//! The host build supplies getter and tail-dispatch seams for firmware-owned
//! state and code. The ARM build retains the retail getter, `+0xb4` virtual
//! call with zero argument, and tail branch sequence.

/// Media-player interface object as far as the `+0xb4` slot is recovered.
#[repr(C)]
pub struct MediaPlayerInterfaceSlotB4 {
    pub vtable: *const MediaPlayerInterfaceSlotB4Vtable,
}

/// Media-player interface vtable prefix consumed by this wrapper.
#[repr(C)]
pub struct MediaPlayerInterfaceSlotB4Vtable {
    /// Slots `+0x000..+0xb0`; their identities are not established here.
    pub unresolved_000_b0: [usize; 45],
    /// `+0xb4`: operation invoked with zero before the volume-controller update.
    pub dispatch: unsafe extern "C" fn(this: *mut MediaPlayerInterfaceSlotB4, arg: u32),
}

#[cfg(target_arch = "arm")]
const _: [u8; 0xb4] = [0; core::mem::offset_of!(MediaPlayerInterfaceSlotB4Vtable, dispatch)];

/// Getter ABI for the global media-player interface.
pub type MediaPlayerInterfaceSlotB4Getter = unsafe extern "C" fn() -> *mut MediaPlayerInterfaceSlotB4;
/// Tail target ABI for retail `FUN_081f9020`.
pub type VolumeControllerUpdate = unsafe extern "C" fn(volume_controller: *mut u8) -> u32;

/// Host replacements for firmware-owned dependencies.
#[derive(Clone, Copy)]
pub struct MediaPlayerSlotB4ThenVolumeControllerUpdateOps {
    pub get_interface: MediaPlayerInterfaceSlotB4Getter,
    pub update_volume_controller: VolumeControllerUpdate,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_interface() -> *mut MediaPlayerInterfaceSlotB4 { core::ptr::null_mut() }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_volume_controller_update(_: *mut u8) -> u32 { 0 }

/// Host default before a fixture installs firmware dependency seams.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_MEDIA_PLAYER_SLOT_B4_THEN_VOLUME_CONTROLLER_UPDATE_OPS:
    MediaPlayerSlotB4ThenVolumeControllerUpdateOps = MediaPlayerSlotB4ThenVolumeControllerUpdateOps {
        get_interface: missing_interface,
        update_volume_controller: missing_volume_controller_update,
    };

/// Host seams for the firmware-owned global interface and tail target.
#[cfg(not(target_arch = "arm"))]
pub static mut MEDIA_PLAYER_SLOT_B4_THEN_VOLUME_CONTROLLER_UPDATE_OPS:
    MediaPlayerSlotB4ThenVolumeControllerUpdateOps =
    DEFAULT_MEDIA_PLAYER_SLOT_B4_THEN_VOLUME_CONTROLLER_UPDATE_OPS;

/// Calls media-player interface slot `+0xb4` with zero, then updates `volume_controller`.
///
/// # Safety
///
/// The getter must return a non-NULL interface with a readable vtable and
/// callable `+0xb4` entry. `volume_controller` is passed unchanged to retail
/// `FUN_081f9020`, which owns its validity requirements.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_slot_b4_then_volume_controller_update(volume_controller: *mut u8) -> u32 {
    let ops = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_PLAYER_SLOT_B4_THEN_VOLUME_CONTROLLER_UPDATE_OPS))
    };
    let interface = unsafe { (ops.get_interface)() };
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*interface).vtable)) };
    unsafe { ((*vtable).dispatch)(interface, 0) };
    unsafe { (ops.update_volume_controller)(volume_controller) }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl media_player_slot_b4_then_volume_controller_update
    .type media_player_slot_b4_then_volume_controller_update, %function
media_player_slot_b4_then_volume_controller_update:
    push    {{r4, lr}}
    mov     r4, r0
    bl      media_player_interface_get
    ldr     r1, [r0]
    ldr     r2, [r1, #0xb4]
    mov     r1, #0
    blx     r2
    mov     r0, r4
    pop     {{r4, lr}}
    b       retail_volume_controller_update_b4
    .size media_player_slot_b4_then_volume_controller_update, . - media_player_slot_b4_then_volume_controller_update

retail_volume_controller_update_b4:
    ldr     pc, [pc, #-4]
    .word   0x081f9020
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut GETTER_CALLS: u32 = 0;
    static mut DISPATCH_CALLS: u32 = 0;
    static mut UPDATE_CALLS: u32 = 0;
    static mut SEEN_INTERFACE: *mut MediaPlayerInterfaceSlotB4 = core::ptr::null_mut();
    static mut SEEN_ARGUMENT: u32 = 1;
    static mut SEEN_VOLUME_CONTROLLER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_dispatch(interface: *mut MediaPlayerInterfaceSlotB4, argument: u32) {
        unsafe { DISPATCH_CALLS += 1; SEEN_INTERFACE = interface; SEEN_ARGUMENT = argument; }
    }
    static VTABLE: MediaPlayerInterfaceSlotB4Vtable = MediaPlayerInterfaceSlotB4Vtable {
        unresolved_000_b0: [0; 45], dispatch: record_dispatch,
    };
    static mut INTERFACE: MediaPlayerInterfaceSlotB4 = MediaPlayerInterfaceSlotB4 { vtable: &VTABLE };
    unsafe extern "C" fn record_get_interface() -> *mut MediaPlayerInterfaceSlotB4 {
        unsafe { GETTER_CALLS += 1; addr_of_mut!(INTERFACE) }
    }
    unsafe extern "C" fn record_update(volume_controller: *mut u8) -> u32 {
        unsafe { UPDATE_CALLS += 1; SEEN_VOLUME_CONTROLLER = volume_controller; 0x1234_5678 }
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(GETTER_CALLS).write(0); addr_of_mut!(DISPATCH_CALLS).write(0);
            addr_of_mut!(UPDATE_CALLS).write(0); addr_of_mut!(SEEN_INTERFACE).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_ARGUMENT).write(1); addr_of_mut!(SEEN_VOLUME_CONTROLLER).write(core::ptr::null_mut());
            addr_of_mut!(INTERFACE).write(MediaPlayerInterfaceSlotB4 { vtable: &VTABLE });
            addr_of_mut!(MEDIA_PLAYER_SLOT_B4_THEN_VOLUME_CONTROLLER_UPDATE_OPS).write(
                MediaPlayerSlotB4ThenVolumeControllerUpdateOps { get_interface: record_get_interface, update_volume_controller: record_update },
            );
        }
        guard
    }
    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(MEDIA_PLAYER_SLOT_B4_THEN_VOLUME_CONTROLLER_UPDATE_OPS).write(DEFAULT_MEDIA_PLAYER_SLOT_B4_THEN_VOLUME_CONTROLLER_UPDATE_OPS); }
        drop(guard);
    }

    #[test]
    fn dispatches_slot_b4_with_zero_then_updates_the_original_volume_controller() {
        let guard = install_recorder();
        let mut volume_controller = [0u8; 1];
        let volume_controller = volume_controller.as_mut_ptr();
        assert_eq!(unsafe { media_player_slot_b4_then_volume_controller_update(volume_controller) }, 0x1234_5678);
        unsafe {
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1); assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(UPDATE_CALLS).read(), 1); assert_eq!(addr_of!(SEEN_INTERFACE).read(), addr_of_mut!(INTERFACE));
            assert_eq!(addr_of!(SEEN_ARGUMENT).read(), 0); assert_eq!(addr_of!(SEEN_VOLUME_CONTROLLER).read(), volume_controller);
        }
        restore_default(guard);
    }
}
