//! Conditional release of an opaque virtual handle.
//!
//! `opaque_handle_release_if_valid` — retailOS `FUN_0805a594` at
//! **0x0805a594** (32 bytes). Raw ARM establishes the exact extent from
//! `cmn r0,#1` at 0x0805a594 through `pop {r4,pc}` at 0x0805a5b0; the next
//! independently linked function begins at 0x0805a5b4 with
//! `push {r3,r4,r5,lr}`. Decoding every immediate ARM B/BL word in `osos.dec`
//! finds six inbound calls: five unconditional plain `bl` at 0x08049018,
//! 0x0805b6f0, 0x0806e568, 0x080a7574, and 0x080beca0, plus one `bleq` at
//! 0x080aa654. There are no direct tail branches or aligned raw data-word
//! references.
//!
//! Algorithm: NULL and the 32-bit `0xffffffff` absent-handle sentinel return
//! zero without dereferencing the handle. Every other handle is dispatched
//! through its vtable's +0x04 slot with the handle retained in r0; the virtual
//! result is ignored and this wrapper returns zero. Its six callers pass the
//! acquisition result from `FUN_0805a634`, so this is the release operation for
//! that still-opaque handle type. The concrete virtual method remains
//! unrecovered and is deliberately not invented.
//!
//! Deliberate deviation: the target stores four-byte vtable words; host
//! fixtures use a typed native-width callback slot. `repr(C)` plus target-only
//! layout assertions retain the verified ARM offsets. Rust expresses `blxne`
//! as a typed call and intentionally discards its return value.

use core::ptr::{addr_of, read_volatile};

/// The 32-bit absent-handle sentinel tested by `cmn r0,#1`.
const ABSENT_HANDLE: usize = 0xffff_ffff;

/// ABI of the opaque handle's vtable +0x04 release slot.
pub type OpaqueHandleRelease = unsafe extern "C" fn(*mut OpaqueHandle) -> usize;

/// Prefix of the opaque vtable consumed by [`opaque_handle_release_if_valid`].
#[repr(C)]
pub struct OpaqueHandleVtable {
    /// `+0x00`: unrecovered virtual slot.
    pub unresolved_slot_00: usize,
    /// `+0x04` on ARMv5TE: releases this handle.
    pub release: OpaqueHandleRelease,
}

/// Prefix of the acquired handle consumed by this release wrapper.
#[repr(C)]
pub struct OpaqueHandle {
    /// `+0x00`: virtual method table.
    pub vtable: *const OpaqueHandleVtable,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0] = [0; core::mem::offset_of!(OpaqueHandle, vtable)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 4] = [0; core::mem::offset_of!(OpaqueHandleVtable, release)];

/// `opaque_handle_release_if_valid` — original: `FUN_0805a594` @ 0x0805a594
/// (32 bytes).
///
/// Releases `handle` through vtable slot +0x04 unless it is NULL or the target
/// absent-handle sentinel. The virtual return value is discarded; this wrapper
/// always returns zero.
///
/// # Safety
/// A non-NULL, non-sentinel `handle` must contain a readable vtable pointer,
/// and its vtable must contain a valid callable release entry at +0x04.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_handle_release_if_valid(handle: *mut OpaqueHandle) -> u32 {
    if handle.is_null() || handle as usize == ABSENT_HANDLE {
        return 0;
    }

    let vtable = unsafe { read_volatile(addr_of!((*handle).vtable)) };
    let release = unsafe { read_volatile(addr_of!((*vtable).release)) };
    unsafe { release(handle) };
    0
}
#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    use super::{opaque_handle_release_if_valid, OpaqueHandle, OpaqueHandleVtable};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_CALLS: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;
    static mut RECEIVED_HANDLE: *mut OpaqueHandle = ptr::null_mut();

    unsafe extern "C" fn wrong_slot(_handle: *mut OpaqueHandle) -> usize {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0xfeed_face
    }

    unsafe extern "C" fn recording_release(handle: *mut OpaqueHandle) -> usize {
        unsafe {
            RELEASE_CALLS += 1;
            RECEIVED_HANDLE = handle;
        }
        0xdead_beef
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock();
        unsafe {
            RELEASE_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
            RECEIVED_HANDLE = ptr::null_mut();
        }
        Bench { _lock: lock }
    }

    #[test]
    fn releases_only_valid_handles_through_vtable_slot_4() {
        let _bench = bench();
        let vtable = OpaqueHandleVtable {
            unresolved_slot_00: wrong_slot as usize,
            release: recording_release,
        };
        let mut handle = OpaqueHandle { vtable: &vtable };

        let result = unsafe { opaque_handle_release_if_valid(&mut handle) };

        assert_eq!(result, 0, "the wrapper discards the virtual return value");
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x04 dispatches");
        assert_eq!(unsafe { RECEIVED_HANDLE }, ptr::addr_of_mut!(handle));
    }

    #[test]
    fn null_and_absent_handles_do_not_dispatch() {
        let _bench = bench();

        let null_result = unsafe { opaque_handle_release_if_valid(ptr::null_mut()) };
        let absent_result = unsafe {
            opaque_handle_release_if_valid(super::ABSENT_HANDLE as *mut OpaqueHandle)
        };

        assert_eq!(null_result, 0);
        assert_eq!(absent_result, 0);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0);
    }
}
