//! `owner_slot_0c_vtable_slot_28_dispatch` — original: `FUN_081d85d8` @
//! `0x081d85d8` (16 bytes).
//!
//! # Algorithm
//!
//! Loads the interface at `owner+0x0c`, loads its first-word vtable, and
//! tail-dispatches vtable slot `+0x28` with that interface as `r0`. Raw ARM
//! decoding establishes the extent `0x081d85d8..0x081d85e7`; it has no direct
//! calls, only the terminal indirect `bx r1`. Three inbound calls are plain
//! `bl` instructions (`0x08209620`, `0x082096fc`, `0x082097a8`); none are
//! predicated.
//!
//! Deliberate deviation: the host representation widens target pointer words
//! to host pointers, so it expresses the `+0x0c` owner field and `+0x28`
//! vtable slot structurally. The target build retains the four retail words
//! verbatim, including its tail dispatch.

/// Interface whose vtable supplies the dispatched `+0x28` method.
#[repr(C)]
pub struct OwnerSlot0cInterface {
    pub vtable: *const OwnerSlot0cVtable,
}

/// Recovered portion of the interface vtable.
#[repr(C)]
pub struct OwnerSlot0cVtable {
    /// Slots `+0x00..+0x24` are not used by this wrapper.
    pub unresolved_00_24: [usize; 10],
    /// Slot `+0x28`, called with the interface as its sole argument.
    pub dispatch: unsafe extern "C" fn(*mut OwnerSlot0cInterface) -> u32,
}

/// Host representation of the owner field accessed at target offset `+0x0c`.
#[repr(C)]
pub struct OwnerWithInterfaceSlot0c {
    pub unresolved_00_08: [u32; 3],
    pub interface: *mut OwnerSlot0cInterface,
}

/// Tail-dispatches the vtable `+0x28` method of the interface at `owner+0x0c`.
///
/// # Safety
///
/// `owner` must provide a readable interface field, and that interface must
/// provide a readable vtable with a valid `+0x28` entry.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_slot_0c_vtable_slot_28_dispatch(
    owner: *mut OwnerWithInterfaceSlot0c,
) -> u32 {
    let interface = core::ptr::read_volatile(core::ptr::addr_of!((*owner).interface));
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*interface).vtable));
    ((*vtable).dispatch)(interface)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl owner_slot_0c_vtable_slot_28_dispatch
    .type owner_slot_0c_vtable_slot_28_dispatch, %function
owner_slot_0c_vtable_slot_28_dispatch:
    ldr     r0, [r0, #0x0c]
    ldr     r1, [r0]
    ldr     r1, [r1, #0x28]
    bx      r1
    .size owner_slot_0c_vtable_slot_28_dispatch, . - owner_slot_0c_vtable_slot_28_dispatch
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: u32 = 0;
    static mut SEEN_INTERFACE: *mut OwnerSlot0cInterface = core::ptr::null_mut();

    unsafe extern "C" fn record_dispatch(interface: *mut OwnerSlot0cInterface) -> u32 {
        DISPATCH_CALLS += 1;
        SEEN_INTERFACE = interface;
        0x8bad_f00d
    }

    static VTABLE: OwnerSlot0cVtable = OwnerSlot0cVtable {
        unresolved_00_24: [0; 10],
        dispatch: record_dispatch,
    };

    #[test]
    fn dispatches_slot_28_with_the_owner_interface_and_returns_its_result() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut interface = OwnerSlot0cInterface { vtable: &VTABLE };
        let mut owner = OwnerWithInterfaceSlot0c {
            unresolved_00_08: [0x11, 0x22, 0x33],
            interface: &mut interface,
        };

        unsafe {
            addr_of_mut!(DISPATCH_CALLS).write(0);
            addr_of_mut!(SEEN_INTERFACE).write(core::ptr::null_mut());
            assert_eq!(owner_slot_0c_vtable_slot_28_dispatch(&mut owner), 0x8bad_f00d);
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_INTERFACE).read() as usize, (&mut interface) as *mut _ as usize);
            assert_eq!(owner.unresolved_00_08, [0x11, 0x22, 0x33]);
        }
    }
}
