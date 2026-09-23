//! `media_player_slot_ac_dispatch` — original: `FUN_081f9008` @
//! **0x081f9008** (**24 bytes**; `0x081f9008..0x081f9020`, with the next
//! separately linked function opening at `0x081f9020`).
//!
//! # Algorithm
//!
//! Gets the global media-player interface, loads its vtable slot `+0xac`, and
//! tail-dispatches it with the interface as `this`. The incoming `r0` is
//! deliberately overwritten by the getter before the virtual call. Raw ARM
//! words establish one outbound plain `bl`, no predicated outbound `bl`, and
//! three inbound direct `bl` callers.
//!
//! # Deliberate deviations
//!
//! The host build substitutes the firmware-owned media-player getter with an
//! explicit seam. The ARM build retains the exact getter, `+0xac` load, and
//! `bx` tail-dispatch sequence.

/// Media-player interface object as far as slot `+0xac` is recovered.
#[repr(C)]
pub struct MediaPlayerInterfaceSlotAc {
    pub vtable: *const MediaPlayerInterfaceSlotAcVtable,
}

/// Media-player interface vtable as far as this dispatch decodes it.
#[repr(C)]
pub struct MediaPlayerInterfaceSlotAcVtable {
    /// Slots `+0x000..+0xa8`; their identities are not established here.
    pub unresolved_000_a8: [usize; 43],
    /// `+0xac`: operation dispatched by this wrapper.
    pub dispatch: unsafe extern "C" fn(this: *mut MediaPlayerInterfaceSlotAc) -> u32,
}

#[cfg(target_arch = "arm")]
const _: [u8; 0xac] = [0; core::mem::offset_of!(MediaPlayerInterfaceSlotAcVtable, dispatch)];

/// Getter ABI for the global media-player interface.
pub type MediaPlayerInterfaceSlotAcGetter = unsafe extern "C" fn() -> *mut MediaPlayerInterfaceSlotAc;

/// Host replacement for the firmware-owned media-player getter.
#[derive(Clone, Copy)]
pub struct MediaPlayerSlotAcDispatchOps {
    pub get_interface: MediaPlayerInterfaceSlotAcGetter,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_interface() -> *mut MediaPlayerInterfaceSlotAc {
    core::ptr::null_mut()
}

/// Host default before a fixture installs the firmware dependency seam.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_MEDIA_PLAYER_SLOT_AC_DISPATCH_OPS: MediaPlayerSlotAcDispatchOps =
    MediaPlayerSlotAcDispatchOps { get_interface: missing_interface };

/// Host seam for the firmware-owned global interface.
#[cfg(not(target_arch = "arm"))]
pub static mut MEDIA_PLAYER_SLOT_AC_DISPATCH_OPS: MediaPlayerSlotAcDispatchOps =
    DEFAULT_MEDIA_PLAYER_SLOT_AC_DISPATCH_OPS;

/// Dispatches the media-player interface vtable slot `+0xac`.
///
/// # Safety
///
/// The installed getter must return a non-NULL interface with a readable
/// vtable and `+0xac` entry.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_slot_ac_dispatch() -> u32 {
    let ops = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_PLAYER_SLOT_AC_DISPATCH_OPS))
    };
    let interface = unsafe { (ops.get_interface)() };
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*interface).vtable)) };
    unsafe { ((*vtable).dispatch)(interface) }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl media_player_slot_ac_dispatch
    .type media_player_slot_ac_dispatch, %function
media_player_slot_ac_dispatch:
    push    {{r4, lr}}
    bl      media_player_interface_get
    ldr     r1, [r0]
    ldr     r1, [r1, #0xac]
    pop     {{r4, lr}}
    bx      r1
    .size media_player_slot_ac_dispatch, . - media_player_slot_ac_dispatch
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
    static mut SEEN_INTERFACE: *mut MediaPlayerInterfaceSlotAc = core::ptr::null_mut();
    static mut DISPATCH_RESULT: u32 = 0;

    unsafe extern "C" fn record_dispatch(interface: *mut MediaPlayerInterfaceSlotAc) -> u32 {
        unsafe {
            DISPATCH_CALLS += 1;
            SEEN_INTERFACE = interface;
            DISPATCH_RESULT
        }
    }

    static VTABLE: MediaPlayerInterfaceSlotAcVtable = MediaPlayerInterfaceSlotAcVtable {
        unresolved_000_a8: [0; 43],
        dispatch: record_dispatch,
    };
    static mut INTERFACE: MediaPlayerInterfaceSlotAc = MediaPlayerInterfaceSlotAc { vtable: &VTABLE };

    unsafe extern "C" fn record_get_interface() -> *mut MediaPlayerInterfaceSlotAc {
        unsafe {
            GETTER_CALLS += 1;
            addr_of_mut!(INTERFACE)
        }
    }

    fn install_recorder(result: u32) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(GETTER_CALLS).write(0);
            addr_of_mut!(DISPATCH_CALLS).write(0);
            addr_of_mut!(SEEN_INTERFACE).write(core::ptr::null_mut());
            addr_of_mut!(DISPATCH_RESULT).write(result);
            addr_of_mut!(INTERFACE).write(MediaPlayerInterfaceSlotAc { vtable: &VTABLE });
            addr_of_mut!(MEDIA_PLAYER_SLOT_AC_DISPATCH_OPS).write(MediaPlayerSlotAcDispatchOps {
                get_interface: record_get_interface,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(MEDIA_PLAYER_SLOT_AC_DISPATCH_OPS)
                .write(DEFAULT_MEDIA_PLAYER_SLOT_AC_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn dispatches_slot_ac_with_the_interface() {
        let guard = install_recorder(0x1234_5678);

        assert_eq!(unsafe { media_player_slot_ac_dispatch() }, 0x1234_5678);
        unsafe {
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_INTERFACE).read(), addr_of_mut!(INTERFACE));
        }
        restore_default(guard);
    }

    #[test]
    fn returns_the_virtual_dispatch_result_unchanged() {
        let guard = install_recorder(0);

        assert_eq!(unsafe { media_player_slot_ac_dispatch() }, 0);
        unsafe {
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
        }
        restore_default(guard);
    }
}
