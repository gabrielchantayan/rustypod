//! `media_player_interface_status` — original: `FUN_0813921c` @
//! **0x0813921c** (**204 bytes**, exactly `0x0813921c..0x081392e8`; the next
//! separately linked function begins at `0x081392e8`).
//!
//! # Algorithm
//!
//! Gets the global media-player interface, invokes its vtable `+0x13c` slot,
//! and stores that result's low byte through the optional second argument.
//! It then calls slots `+0x120`, `+0x114`, `+0x118`, `+0x10c`, and `+0x110`,
//! in that order until one is nonzero. The optional third output receives the
//! corresponding reason: `0`, `3`, `4`, `1`, or `2`; no nonzero result from
//! `+0x120` remains reason zero. The incoming first argument is ignored.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds **six direct inbound
//! `bl` sites**, all unconditional: `0x0818f6dc`, `0x081a9cdc`, `0x081ab574`,
//! `0x081fda3c`, `0x08200388`, and `0x08200568`. There are no predicated
//! direct calls and no plain-`b` tail sites. The body additionally has one
//! direct getter `bl`, one predicated `bleq heap_panic`, and six dynamic
//! `blx` calls; their targets are runtime vtable data, not recoverable static
//! function entries.
//!
//! # Deliberate deviations
//!
//! Host fixtures use native-width vtable function pointers and a getter seam;
//! the ARM layout is asserted at each recovered slot offset. On device the
//! existing `media_player_interface_get` port is called directly. A NULL
//! getter result reaches `heap_panic`, matching the raw `movs`/`bleq` pair.

use core::ptr::addr_of;

const SLOT_10C_INDEX: usize = 0x10c / 4;
const SLOT_124_138_LEN: usize = (0x13c - 0x124) / 4;

/// Media-player interface object as far as this status query observes it.
#[repr(C)]
pub struct MediaPlayerInterfaceStatus {
    pub vtable: *const MediaPlayerInterfaceStatusVtable,
}

/// Recovered status-query slots in the media-player interface vtable.
#[repr(C)]
pub struct MediaPlayerInterfaceStatusVtable {
    /// Slots `+0x000..+0x108`, whose identities are not established here.
    pub unresolved_000_108: [usize; SLOT_10C_INDEX],
    /// `+0x10c`: fourth status predicate, mapped to reason 1.
    pub predicate_10c: unsafe extern "C" fn(*mut MediaPlayerInterfaceStatus) -> u32,
    /// `+0x110`: fifth status predicate, mapped to reason 2.
    pub predicate_110: unsafe extern "C" fn(*mut MediaPlayerInterfaceStatus) -> u32,
    /// `+0x114`: second status predicate, mapped to reason 3.
    pub predicate_114: unsafe extern "C" fn(*mut MediaPlayerInterfaceStatus) -> u32,
    /// `+0x118`: third status predicate, mapped to reason 4.
    pub predicate_118: unsafe extern "C" fn(*mut MediaPlayerInterfaceStatus) -> u32,
    /// `+0x11c`, not observed by this routine.
    pub unresolved_11c: usize,
    /// `+0x120`: first status predicate; a nonzero result leaves reason 0.
    pub predicate_120: unsafe extern "C" fn(*mut MediaPlayerInterfaceStatus) -> u32,
    /// Slots `+0x124..+0x138`, whose identities are not established here.
    pub unresolved_124_138: [usize; SLOT_124_138_LEN],
    /// `+0x13c`: byte-valued interface status query.
    pub status_byte: unsafe extern "C" fn(*mut MediaPlayerInterfaceStatus) -> u32,
}

#[cfg(target_os = "none")]
const _: [u8; 0x10c] = [0; core::mem::offset_of!(MediaPlayerInterfaceStatusVtable, predicate_10c)];
#[cfg(target_os = "none")]
const _: [u8; 0x110] = [0; core::mem::offset_of!(MediaPlayerInterfaceStatusVtable, predicate_110)];
#[cfg(target_os = "none")]
const _: [u8; 0x114] = [0; core::mem::offset_of!(MediaPlayerInterfaceStatusVtable, predicate_114)];
#[cfg(target_os = "none")]
const _: [u8; 0x118] = [0; core::mem::offset_of!(MediaPlayerInterfaceStatusVtable, predicate_118)];
#[cfg(target_os = "none")]
const _: [u8; 0x120] = [0; core::mem::offset_of!(MediaPlayerInterfaceStatusVtable, predicate_120)];
#[cfg(target_os = "none")]
const _: [u8; 0x13c] = [0; core::mem::offset_of!(MediaPlayerInterfaceStatusVtable, status_byte)];

/// Host-side replacement for the firmware-owned interface getter.
#[derive(Clone, Copy)]
pub struct MediaPlayerInterfaceStatusOps {
    pub get_interface: unsafe extern "C" fn() -> *mut MediaPlayerInterfaceStatus,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_media_player_interface() -> *mut MediaPlayerInterfaceStatus {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEDIA_PLAYER_INTERFACE_STATUS_OPS: MediaPlayerInterfaceStatusOps =
    MediaPlayerInterfaceStatusOps { get_interface: missing_media_player_interface };

/// Host seam for the existing target singleton accessor.
#[cfg(not(target_os = "none"))]
pub static mut MEDIA_PLAYER_INTERFACE_STATUS_OPS: MediaPlayerInterfaceStatusOps =
    DEFAULT_MEDIA_PLAYER_INTERFACE_STATUS_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn media_player_interface() -> *mut MediaPlayerInterfaceStatus {
    unsafe { core::ptr::read_volatile(addr_of!(MEDIA_PLAYER_INTERFACE_STATUS_OPS.get_interface))() }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn media_player_interface() -> *mut MediaPlayerInterfaceStatus {
    unsafe { super::singletons::media_player_interface_get().cast() }
}

/// Gets the interface status byte and its highest-priority active reason.
///
/// # Safety
///
/// The global getter must yield a non-NULL interface with a readable vtable
/// and callable recovered slots. `status_out` and `reason_out`, when non-NULL,
/// must point to writable bytes. The first argument is ignored exactly as in
/// retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_interface_status(
    _unused: *mut u8,
    status_out: *mut u8,
    reason_out: *mut u8,
) -> u32 {
    let interface = unsafe { media_player_interface() };
    if interface.is_null() {
        unsafe { crate::heap::veneers::heap_panic() };
    }
    let vtable = unsafe { core::ptr::read_volatile(addr_of!((*interface).vtable)) };
    let status = unsafe { ((*vtable).status_byte)(interface) } as u8;
    let mut reason = 0;

    if unsafe { ((*vtable).predicate_120)(interface) } == 0 {
        if unsafe { ((*vtable).predicate_114)(interface) } != 0 {
            reason = 3;
        } else if unsafe { ((*vtable).predicate_118)(interface) } != 0 {
            reason = 4;
        } else if unsafe { ((*vtable).predicate_10c)(interface) } != 0 {
            reason = 1;
        } else if unsafe { ((*vtable).predicate_110)(interface) } != 0 {
            reason = 2;
        }
    }

    if !status_out.is_null() {
        unsafe { status_out.write(status) };
    }
    if !reason_out.is_null() {
        unsafe { reason_out.write(reason) };
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INTERFACE: *mut MediaPlayerInterfaceStatus = core::ptr::null_mut();
    static mut STATUS: u32 = 0;
    static mut PREDICATES: [u32; 5] = [0; 5];
    static mut CALLS: [u16; 6] = [0; 6];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn getter() -> *mut MediaPlayerInterfaceStatus {
        unsafe { INTERFACE }
    }

    unsafe fn record(slot: u16, value: u32) -> u32 {
        unsafe {
            CALLS[CALL_COUNT] = slot;
            CALL_COUNT += 1;
        }
        value
    }

    unsafe extern "C" fn status_byte(_interface: *mut MediaPlayerInterfaceStatus) -> u32 {
        unsafe { record(0x13c, STATUS) }
    }
    unsafe extern "C" fn predicate_120(_interface: *mut MediaPlayerInterfaceStatus) -> u32 {
        unsafe { record(0x120, PREDICATES[0]) }
    }
    unsafe extern "C" fn predicate_114(_interface: *mut MediaPlayerInterfaceStatus) -> u32 {
        unsafe { record(0x114, PREDICATES[1]) }
    }
    unsafe extern "C" fn predicate_118(_interface: *mut MediaPlayerInterfaceStatus) -> u32 {
        unsafe { record(0x118, PREDICATES[2]) }
    }
    unsafe extern "C" fn predicate_10c(_interface: *mut MediaPlayerInterfaceStatus) -> u32 {
        unsafe { record(0x10c, PREDICATES[3]) }
    }
    unsafe extern "C" fn predicate_110(_interface: *mut MediaPlayerInterfaceStatus) -> u32 {
        unsafe { record(0x110, PREDICATES[4]) }
    }

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        previous_ops: MediaPlayerInterfaceStatusOps,
    }

    impl Fixture {
        fn new(interface: *mut MediaPlayerInterfaceStatus) -> Self {
            let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let previous_ops = unsafe { addr_of!(MEDIA_PLAYER_INTERFACE_STATUS_OPS).read_volatile() };
            unsafe {
                INTERFACE = interface;
                STATUS = 0;
                PREDICATES = [0; 5];
                CALLS = [0; 6];
                CALL_COUNT = 0;
                addr_of_mut!(MEDIA_PLAYER_INTERFACE_STATUS_OPS)
                    .write_volatile(MediaPlayerInterfaceStatusOps { get_interface: getter });
            }
            Self { _guard: guard, previous_ops }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(MEDIA_PLAYER_INTERFACE_STATUS_OPS).write_volatile(self.previous_ops);
                INTERFACE = core::ptr::null_mut();
            }
        }
    }

    fn calls() -> std::vec::Vec<u16> {
        unsafe { CALLS[..CALL_COUNT].to_vec() }
    }

    #[test]
    fn returns_status_and_observes_predicate_priority() {
        let vtable = MediaPlayerInterfaceStatusVtable {
            unresolved_000_108: [0; SLOT_10C_INDEX],
            predicate_10c,
            predicate_110,
            predicate_114,
            predicate_118,
            unresolved_11c: 0,
            predicate_120,
            unresolved_124_138: [0; SLOT_124_138_LEN],
            status_byte,
        };
        let mut interface = MediaPlayerInterfaceStatus { vtable: &vtable };
        let _fixture = Fixture::new(&mut interface);

        for (predicates, expected_reason, expected_calls) in [
            ([9, 0, 0, 0, 0], 0, &[0x13c, 0x120][..]),
            ([0, 7, 8, 9, 10], 3, &[0x13c, 0x120, 0x114][..]),
            ([0, 0, 8, 9, 10], 4, &[0x13c, 0x120, 0x114, 0x118][..]),
            ([0, 0, 0, 9, 10], 1, &[0x13c, 0x120, 0x114, 0x118, 0x10c][..]),
            ([0, 0, 0, 0, 10], 2, &[0x13c, 0x120, 0x114, 0x118, 0x10c, 0x110][..]),
            ([0, 0, 0, 0, 0], 0, &[0x13c, 0x120, 0x114, 0x118, 0x10c, 0x110][..]),
        ] {
            unsafe {
                STATUS = 0x1a2;
                PREDICATES = predicates;
                CALLS = [0; 6];
                CALL_COUNT = 0;
            }
            let mut status = 0;
            let mut reason = 0xff;
            assert_eq!(unsafe { media_player_interface_status(core::ptr::null_mut(), &mut status, &mut reason) }, 0);
            assert_eq!(status, 0xa2);
            assert_eq!(reason, expected_reason);
            assert_eq!(calls(), expected_calls);
        }
    }

    #[test]
    fn permits_either_optional_output_to_be_null() {
        let vtable = MediaPlayerInterfaceStatusVtable {
            unresolved_000_108: [0; SLOT_10C_INDEX],
            predicate_10c,
            predicate_110,
            predicate_114,
            predicate_118,
            unresolved_11c: 0,
            predicate_120,
            unresolved_124_138: [0; SLOT_124_138_LEN],
            status_byte,
        };
        let mut interface = MediaPlayerInterfaceStatus { vtable: &vtable };
        let _fixture = Fixture::new(&mut interface);
        unsafe {
            STATUS = 0x3c;
            PREDICATES = [0, 0, 0, 1, 0];
        }

        let mut reason = 0;
        assert_eq!(unsafe { media_player_interface_status(core::ptr::null_mut(), core::ptr::null_mut(), &mut reason) }, 0);
        assert_eq!(reason, 1);
        unsafe { CALL_COUNT = 0 };

        let mut status = 0;
        assert_eq!(unsafe { media_player_interface_status(core::ptr::null_mut(), &mut status, core::ptr::null_mut()) }, 0);
        assert_eq!(status, 0x3c);
    }
}
