//! `owner_link_is_current` — FUN_08168758 @ 0x08168758, true size 12 bytes.
//!
//! Raw A32: mov r1,r0; ldr r0,[r0,#4]; b 0x081682dc. The next real
//! function is owner_link_base_construct at 0x08168764. Two inbound plain
//! BL sites (0x080fcabc, 0x080fcb44), zero predicated BL sites; no outbound
//! BL, one unconditional tail branch. Ghidra's 68-byte body expands the
//! destination's counted-lock comparison into this wrapper incorrectly.
//! Load the owner word and ask whether its current link is this receiver.
//! The unported destination locks owner+4, compares owner+0x20 with the
//! receiver, unlocks, and returns 0 or 1 (raw bytes 0x081682dc..0x08168314).
//! Deliberate deviations: host execution requires an injected destination;
//! target execution retains the exact retail destination. No NULL guards.

use super::owner_link_base_construct::OwnerLinkBase;

type OwnerCurrentQuery = unsafe extern "C" fn(u32, *const OwnerLinkBase) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_current_query(_: u32, _: *const OwnerLinkBase) -> u32 {
    panic!("install owner-current query for host execution")
}

/// Host dispatch for the unported counted-lock query at 0x081682dc.
/// Install only while no other thread is using this module.
#[cfg(not(target_os = "none"))]
pub static mut OWNER_CURRENT_QUERY: OwnerCurrentQuery = missing_owner_current_query;

/// `receiver` must be readable and aligned; its owner must be valid for the
/// retail counted-lock query. The vtable and trailing receiver fields are unused.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_link_is_current(receiver: *const OwnerLinkBase) -> u32 {
    #[cfg(target_os = "none")]
    let query: OwnerCurrentQuery = core::mem::transmute(0x0816_82dcusize);
    #[cfg(not(target_os = "none"))]
    let query = core::ptr::read_volatile(core::ptr::addr_of!(OWNER_CURRENT_QUERY));
    query((*receiver).owner, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::cell::Cell;
    std::thread_local! {
        static CURRENT: Cell<*const OwnerLinkBase> = const { Cell::new(core::ptr::null()) };
    }
    unsafe extern "C" fn reference_query(owner: u32, receiver: *const OwnerLinkBase) -> u32 {
        assert_eq!(owner, 0x08a7_62a0);
        CURRENT.with(|current| u32::from(current.get() == receiver))
    }

    // Explicit wrapper contract tests requested by the port assignment.
    #[test]
    fn distinguishes_current_link_from_another_link_with_the_same_owner() {
        let first = OwnerLinkBase { vtable: 0, owner: 0x08a7_62a0 };
        let second = OwnerLinkBase { vtable: u32::MAX, owner: first.owner };
        unsafe {
            let previous = OWNER_CURRENT_QUERY;
            OWNER_CURRENT_QUERY = reference_query;
            CURRENT.with(|current| current.set(&first));
            assert_eq!(owner_link_is_current(&first), 1);
            assert_eq!(owner_link_is_current(&second), 0);
            CURRENT.with(|current| current.set(&second));
            assert_eq!(owner_link_is_current(&first), 0);
            assert_eq!(owner_link_is_current(&second), 1);
            CURRENT.with(|current| current.set(core::ptr::null()));
            assert_eq!(owner_link_is_current(&first), 0);
            OWNER_CURRENT_QUERY = previous;
        }
        assert_eq!(first.vtable, 0);
        assert_eq!(second.vtable, u32::MAX);
    }
}
