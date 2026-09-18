//! `media_player_slot_b0_then_volume_controller_update` — original:
//! `FUN_081f9220` @ **0x081f9220** (**40 bytes**;
//! `0x081f9220..0x081f9248`, with the next separately linked function at
//! `0x081f9248`).
//!
//! # Algorithm
//!
//! Calls the global media-player interface's unresolved vtable slot `+0xb0`,
//! passing zero as its second argument and discarding its result, then
//! tail-dispatches the incoming volume-controller pointer to retail
//! `FUN_081f9020`. Neither dynamic operation has a recoverable semantic
//! identity, so their names deliberately retain their verified structural roles.
//!
//! Raw ARM decoding establishes the true 40-byte extent: `push {r4, lr}` opens
//! at 0x081f9220 and the next `push {r4, lr}` opens at 0x081f9248. There are
//! **4 direct `bl` callers, 0 predicated** (`0x08216f50`, `0x082174a4`,
//! `0x0821d6d0`, `0x0821f1f0`) and one direct tail branch to 0x081f9020.
//!
//! # Deliberate deviations
//!
//! The host build substitutes explicit getter and tail-dispatch seams for the
//! firmware-owned global and `FUN_081f9020`. The ARM build retains the exact
//! getter, `+0xb0` virtual call with zero argument, and tail branch sequence.

/// Media-player interface object as far as the `+0xb0` slot is recovered.
#[repr(C)]
pub struct MediaPlayerInterfaceSlotB0 {
    pub vtable: *const MediaPlayerInterfaceSlotB0Vtable,
}

/// Media-player interface vtable as far as this wrapper decodes it.
#[repr(C)]
pub struct MediaPlayerInterfaceSlotB0Vtable {
    /// Slots `+0x000..+0xac`; their identities are not established here.
    pub unresolved_000_ac: [usize; 44],
    /// `+0xb0`: operation invoked with zero before the volume-controller update.
    pub dispatch: unsafe extern "C" fn(this: *mut MediaPlayerInterfaceSlotB0, arg: u32),
}

#[cfg(target_arch = "arm")]
const _: [u8; 0xb0] = [0; core::mem::offset_of!(MediaPlayerInterfaceSlotB0Vtable, dispatch)];

/// Getter ABI for the global media-player interface.
pub type MediaPlayerInterfaceSlotB0Getter = unsafe extern "C" fn() -> *mut MediaPlayerInterfaceSlotB0;
/// Tail target ABI for retail `FUN_081f9020`.
pub type VolumeControllerUpdate = unsafe extern "C" fn(volume_controller: *mut u8) -> u32;

/// Host replacements for firmware-owned dependencies.
#[derive(Clone, Copy)]
pub struct MediaPlayerSlotB0ThenVolumeControllerUpdateOps {
    pub get_interface: MediaPlayerInterfaceSlotB0Getter,
    pub update_volume_controller: VolumeControllerUpdate,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_interface() -> *mut MediaPlayerInterfaceSlotB0 {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_volume_controller_update(_: *mut u8) -> u32 {
    0
}

/// Host default before a fixture installs firmware dependency seams.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_MEDIA_PLAYER_SLOT_B0_THEN_VOLUME_CONTROLLER_UPDATE_OPS:
    MediaPlayerSlotB0ThenVolumeControllerUpdateOps = MediaPlayerSlotB0ThenVolumeControllerUpdateOps {
        get_interface: missing_interface,
        update_volume_controller: missing_volume_controller_update,
    };

/// Host seams for the firmware-owned global interface and tail target.
#[cfg(not(target_arch = "arm"))]
pub static mut MEDIA_PLAYER_SLOT_B0_THEN_VOLUME_CONTROLLER_UPDATE_OPS:
    MediaPlayerSlotB0ThenVolumeControllerUpdateOps =
    DEFAULT_MEDIA_PLAYER_SLOT_B0_THEN_VOLUME_CONTROLLER_UPDATE_OPS;

/// Calls media-player interface slot `+0xb0` with zero, then updates `volume_controller`.
///
/// # Safety
///
/// The media-player getter must return a non-NULL interface with a readable
/// vtable and `+0xb0` entry. `volume_controller` is passed unchanged to retail
/// `FUN_081f9020`, which owns its validity requirements.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_slot_b0_then_volume_controller_update(volume_controller: *mut u8) -> u32 {
    let ops = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_PLAYER_SLOT_B0_THEN_VOLUME_CONTROLLER_UPDATE_OPS))
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
    .globl media_player_slot_b0_then_volume_controller_update
    .type media_player_slot_b0_then_volume_controller_update, %function
media_player_slot_b0_then_volume_controller_update:
    push    {{r4, lr}}
    mov     r4, r0
    bl      media_player_interface_get
    ldr     r1, [r0]
    ldr     r2, [r1, #0xb0]
    mov     r1, #0
    blx     r2
    mov     r0, r4
    pop     {{r4, lr}}
    b       retail_volume_controller_update_b0
    .size media_player_slot_b0_then_volume_controller_update, . - media_player_slot_b0_then_volume_controller_update

retail_volume_controller_update_b0:
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
    static mut SEEN_INTERFACE: *mut MediaPlayerInterfaceSlotB0 = core::ptr::null_mut();
    static mut SEEN_ARGUMENT: u32 = 1;
    static mut SEEN_VOLUME_CONTROLLER: *mut u8 = core::ptr::null_mut();
    static mut UPDATE_RESULT: u32 = 0;

    unsafe extern "C" fn record_dispatch(interface: *mut MediaPlayerInterfaceSlotB0, argument: u32) {
        unsafe {
            DISPATCH_CALLS += 1;
            SEEN_INTERFACE = interface;
            SEEN_ARGUMENT = argument;
        }
    }

    static VTABLE: MediaPlayerInterfaceSlotB0Vtable = MediaPlayerInterfaceSlotB0Vtable {
        unresolved_000_ac: [0; 44],
        dispatch: record_dispatch,
    };
    static mut INTERFACE: MediaPlayerInterfaceSlotB0 = MediaPlayerInterfaceSlotB0 { vtable: &VTABLE };

    unsafe extern "C" fn record_get_interface() -> *mut MediaPlayerInterfaceSlotB0 {
        unsafe {
            GETTER_CALLS += 1;
            addr_of_mut!(INTERFACE)
        }
    }

    unsafe extern "C" fn record_update(volume_controller: *mut u8) -> u32 {
        unsafe {
            UPDATE_CALLS += 1;
            SEEN_VOLUME_CONTROLLER = volume_controller;
            UPDATE_RESULT
        }
    }

    fn install_recorder(result: u32) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(GETTER_CALLS).write(0);
            addr_of_mut!(DISPATCH_CALLS).write(0);
            addr_of_mut!(UPDATE_CALLS).write(0);
            addr_of_mut!(SEEN_INTERFACE).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_ARGUMENT).write(1);
            addr_of_mut!(SEEN_VOLUME_CONTROLLER).write(core::ptr::null_mut());
            addr_of_mut!(UPDATE_RESULT).write(result);
            addr_of_mut!(INTERFACE).write(MediaPlayerInterfaceSlotB0 { vtable: &VTABLE });
            addr_of_mut!(MEDIA_PLAYER_SLOT_B0_THEN_VOLUME_CONTROLLER_UPDATE_OPS).write(
                MediaPlayerSlotB0ThenVolumeControllerUpdateOps {
                    get_interface: record_get_interface,
                    update_volume_controller: record_update,
                },
            );
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(MEDIA_PLAYER_SLOT_B0_THEN_VOLUME_CONTROLLER_UPDATE_OPS)
                .write(DEFAULT_MEDIA_PLAYER_SLOT_B0_THEN_VOLUME_CONTROLLER_UPDATE_OPS);
        }
        drop(guard);
    }

    #[test]
    fn dispatches_slot_b0_with_zero_then_updates_the_original_volume_controller() {
        let guard = install_recorder(0x1234_5678);
        let mut volume_controller = [0u8; 1];
        let volume_controller = volume_controller.as_mut_ptr();

        assert_eq!(unsafe { media_player_slot_b0_then_volume_controller_update(volume_controller) }, 0x1234_5678);
        unsafe {
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(UPDATE_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_INTERFACE).read(), addr_of_mut!(INTERFACE));
            assert_eq!(addr_of!(SEEN_ARGUMENT).read(), 0);
            assert_eq!(addr_of!(SEEN_VOLUME_CONTROLLER).read(), volume_controller);
        }
        restore_default(guard);
    }

    #[test]
    fn returns_the_tail_update_result_unchanged() {
        let guard = install_recorder(0);
        let mut volume_controller = [0u8; 1];

        assert_eq!(unsafe { media_player_slot_b0_then_volume_controller_update(volume_controller.as_mut_ptr()) }, 0);
        unsafe {
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(UPDATE_CALLS).read(), 1);
        }
        restore_default(guard);
    }
}
