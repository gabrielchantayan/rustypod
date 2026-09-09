//! `media_player_interface_slot_11c` — original: `FUN_081f9d78` @
//! **0x081f9d78** (**24 bytes**; `0x081f9d78..0x081f9d90`, with the next
//! function beginning at `0x081f9d90`).
//!
//! # Algorithm
//!
//! Raw ARM:
//!
//! ```text
//! push {r4, lr}
//! bl   media_player_interface_get
//! ldr  r1, [r0]
//! ldr  r1, [r1, #0x11c]
//! pop  {r4, lr}
//! bx   r1
//! ```
//!
//! The wrapper discards its incoming `r0`, gets the global media-player
//! interface, and tail-dispatches its vtable slot `+0x11c` with that interface
//! as the sole argument. The dynamic callee has no recoverable static identity,
//! so this port names the verified vtable operation rather than inventing one.
//! The tail result becomes this wrapper's result; Ghidra's recovered `void`
//! signature is wrong because its callers branch on that result.
//!
//! Decoding every ARM B/BL word in `osos.dec` finds **13 direct call sites**:
//! all are unconditional `bl`, with **0 predicated forms** and **0 plain-B
//! tails**. The callers use the result as a state predicate.
//!
//! # Deliberate deviations
//!
//! Host vtables use a native-width function pointer so their `+0x11c` role can
//! be exercised without truncating a host address to a firmware `u32`. The ARM
//! build retains the direct getter call and tail branch in assembly, preserving
//! the retail 32-bit vtable layout and return edge.

/// Interface object obtained from [`crate::app::singletons::media_player_interface_get`].
#[repr(C)]
pub struct MediaPlayerInterfaceSlot11c {
    pub vtable: *const MediaPlayerInterfaceSlot11cVtable,
}

/// The media-player interface vtable as far as this wrapper decodes it.
#[repr(C)]
pub struct MediaPlayerInterfaceSlot11cVtable {
    /// Slots `+0x000..+0x118`; their identities are not established here.
    pub unresolved_000_118: [usize; 71],
    /// `+0x11c`: state-query operation tail-dispatched by this wrapper.
    pub dispatch: unsafe extern "C" fn(this: *mut MediaPlayerInterfaceSlot11c) -> u32,
}

#[cfg(target_arch = "arm")]
const _: [u8; 0x11c] = [0; core::mem::offset_of!(MediaPlayerInterfaceSlot11cVtable, dispatch)];

/// Getter ABI for the global media-player interface.
pub type MediaPlayerInterfaceSlot11cGetter = unsafe extern "C" fn() -> *mut MediaPlayerInterfaceSlot11c;

/// Host-side replacement for the global interface getter.
#[derive(Clone, Copy)]
pub struct MediaPlayerInterfaceSlot11cOps {
    pub get_interface: MediaPlayerInterfaceSlot11cGetter,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_media_player_interface() -> *mut MediaPlayerInterfaceSlot11c {
    core::ptr::null_mut()
}

/// Host default before a fixture installs the process-global interface.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_MEDIA_PLAYER_INTERFACE_SLOT_11C_OPS: MediaPlayerInterfaceSlot11cOps =
    MediaPlayerInterfaceSlot11cOps { get_interface: missing_media_player_interface };

/// Host seam for the otherwise firmware-owned global media-player interface.
#[cfg(not(target_arch = "arm"))]
pub static mut MEDIA_PLAYER_INTERFACE_SLOT_11C_OPS: MediaPlayerInterfaceSlot11cOps =
    DEFAULT_MEDIA_PLAYER_INTERFACE_SLOT_11C_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn media_player_interface() -> *mut MediaPlayerInterfaceSlot11c {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_PLAYER_INTERFACE_SLOT_11C_OPS.get_interface))()
    }
}

/// `media_player_interface_slot_11c` — original: `FUN_081f9d78` @
/// **0x081f9d78** (**24 bytes; 13 unconditional `bl` call sites, 0
/// predicated forms**, verified from raw ARM B/BL words in `osos.dec`).
///
/// Gets the global media-player interface and invokes its `+0x11c` virtual
/// state-query slot. The original ignores its incoming `r0`; this recovered
/// ABI consequently has no arguments and returns the slot's `r0` result.
///
/// # Safety
///
/// The global getter must yield a non-NULL interface whose vtable and `+0x11c`
/// entry are readable. The retail wrapper has no NULL guard before either load.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_interface_slot_11c() -> u32 {
    let interface = unsafe { media_player_interface() };
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*interface).vtable)) };
    unsafe { ((*vtable).dispatch)(interface) }
}

// Keep the getter call and virtual tail dispatch as the retail six-instruction
// ARM sequence. A Rust call would create a local return edge after the slot.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl media_player_interface_slot_11c
    .type media_player_interface_slot_11c, %function
media_player_interface_slot_11c:
    push    {{r4, lr}}
    bl      media_player_interface_get
    ldr     r1, [r0]
    ldr     r1, [r1, #0x11c]
    pop     {{r4, lr}}
    bx      r1
    .size media_player_interface_slot_11c, . - media_player_interface_slot_11c
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
    static mut SEEN_INTERFACE: *mut MediaPlayerInterfaceSlot11c = core::ptr::null_mut();
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_dispatch(interface: *mut MediaPlayerInterfaceSlot11c) -> u32 {
        unsafe {
            DISPATCH_CALLS += 1;
            SEEN_INTERFACE = interface;
            RESULT
        }
    }

    static VTABLE: MediaPlayerInterfaceSlot11cVtable = MediaPlayerInterfaceSlot11cVtable {
        unresolved_000_118: [0; 71],
        dispatch: record_dispatch,
    };
    static mut INTERFACE: MediaPlayerInterfaceSlot11c = MediaPlayerInterfaceSlot11c { vtable: &VTABLE };

    unsafe extern "C" fn record_get_interface() -> *mut MediaPlayerInterfaceSlot11c {
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
            addr_of_mut!(RESULT).write(result);
            addr_of_mut!(INTERFACE).write(MediaPlayerInterfaceSlot11c { vtable: &VTABLE });
            addr_of_mut!(MEDIA_PLAYER_INTERFACE_SLOT_11C_OPS).write(MediaPlayerInterfaceSlot11cOps {
                get_interface: record_get_interface,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(MEDIA_PLAYER_INTERFACE_SLOT_11C_OPS)
                .write(DEFAULT_MEDIA_PLAYER_INTERFACE_SLOT_11C_OPS);
        }
        drop(guard);
    }

    #[test]
    fn gets_the_global_interface_once_and_dispatches_slot_11c() {
        let guard = install_recorder(0x1234_5678);

        let result = unsafe { media_player_interface_slot_11c() };

        unsafe {
            assert_eq!(result, 0x1234_5678);
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_INTERFACE).read(), addr_of_mut!(INTERFACE));
        }
        restore_default(guard);
    }

    #[test]
    fn forwards_a_zero_slot_result_unchanged() {
        let guard = install_recorder(0);

        assert_eq!(unsafe { media_player_interface_slot_11c() }, 0);

        unsafe {
            assert_eq!(addr_of!(GETTER_CALLS).read(), 1);
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
        }
        restore_default(guard);
    }
}
