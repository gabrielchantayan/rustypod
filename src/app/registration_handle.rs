//! `registration_handle_destroy` — original: `FUN_081d9734` @ `0x081d9734`
//! (40 bytes, `0x081d9734..0x081d975c`; the literal vtable word is at
//! `0x081d975c`, and the separately linked next function opens at
//! `0x081d9760`).
//!
//! Restores the registration handle's base vtable, then releases its claimed
//! manager-table slot unless `slot_index` is exactly -1. The original invokes
//! `FUN_081d9918(owner, slot_index)` with no owner NULL guard and returns
//! `this` regardless of the release result.
//!
//! **18 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`; there
//! are no direct `b` tail callers and no aligned data words containing this
//! address. The call sites are 0x081af5e8, 0x081af5f8, 0x081af6c8,
//! 0x081af6e4, 0x081c8394, 0x081c83a8, 0x081c851c, 0x081c8538,
//! 0x081c85a4, 0x081c85b8, 0x081c8624, 0x081c8638, 0x081c8730,
//! 0x081c87d0, 0x081c8830, 0x081c8854, 0x081c8934, and 0x081c8948.
//!
//! Deliberate deviation: the manager's slot-release helper `FUN_081d9918`
//! is not ported. Firmware builds dispatch to its fixed retailOS address;
//! host tests install a volatile seam. `RegistrationHandle` uses named fields
//! so its ARM layout remains the three target words while its host pointer
//! field stays naturally wide.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// Vtable written before the optional manager-slot release.
pub const REGISTRATION_HANDLE_VTABLE: u32 = 0x089a_74bc;
const REGISTRATION_SLOT_RELEASE_ADDRESS: usize = 0x081d_9918;

/// A manager-table registration represented by its owning manager and slot.
///
/// On ARM these fields are respectively at offsets +0, +4, and +8.
#[repr(C)]
pub struct RegistrationHandle {
    pub vtable: u32,
    pub owner: *mut u8,
    pub slot_index: i32,
}

/// ABI of the unported manager-table slot-release helper.
pub type RegistrationSlotRelease = unsafe extern "C" fn(*mut u8, u32) -> i32;

/// Host seam for the unported manager-table slot-release helper.
#[derive(Clone, Copy)]
pub struct RegistrationHandleOps {
    pub release_slot: RegistrationSlotRelease,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_release_slot(owner: *mut u8, slot_index: u32) -> i32 {
    let release_slot: RegistrationSlotRelease = core::mem::transmute(REGISTRATION_SLOT_RELEASE_ADDRESS);
    release_slot(owner, slot_index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_slot(_owner: *mut u8, _slot_index: u32) -> i32 {
    panic!("install registration-handle host operations before releasing a slot")
}

/// Host default before a test installs the retail helper equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_REGISTRATION_HANDLE_OPS: RegistrationHandleOps = RegistrationHandleOps {
    release_slot: missing_release_slot,
};

/// Host-side manager slot-release seam. Firmware builds always call
/// `FUN_081d9918` at `0x081d9918`.
#[cfg(not(target_os = "none"))]
pub static mut REGISTRATION_HANDLE_OPS: RegistrationHandleOps = DEFAULT_REGISTRATION_HANDLE_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_release_slot(owner: *mut u8, slot_index: u32) -> i32 {
    let release_slot = core::ptr::read_volatile(addr_of!(REGISTRATION_HANDLE_OPS.release_slot));
    release_slot(owner, slot_index)
}

/// Restores the registration-handle vtable and releases its claimed slot.
///
/// Only the exact `-1` sentinel skips the release. Other negative values are
/// passed to the helper as their raw `u32` bit patterns, matching `cmn r1,#1`
/// and the untouched `r1` argument in the ARM body.
///
/// # Safety
///
/// `registration` must be valid and aligned. When `slot_index != -1`, its
/// `owner` must meet `FUN_081d9918`'s requirements; stock code has no NULL
/// guard for it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_handle_destroy(
    registration: *mut RegistrationHandle,
) -> *mut RegistrationHandle {
    (*registration).vtable = REGISTRATION_HANDLE_VTABLE;
    let slot_index = (*registration).slot_index;
    if slot_index != -1 {
        #[cfg(target_os = "none")]
        retail_release_slot((*registration).owner, slot_index as u32);
        #[cfg(not(target_os = "none"))]
        host_release_slot((*registration).owner, slot_index as u32);
    }
    registration
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_CALL: Option<(*mut u8, u32)> = None;

    unsafe extern "C" fn record_release(owner: *mut u8, slot_index: u32) -> i32 {
        addr_of_mut!(RELEASE_CALL).write(Some((owner, slot_index)));
        0x7f
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(RELEASE_CALL).write(None);
            REGISTRATION_HANDLE_OPS = RegistrationHandleOps { release_slot: record_release };
        }
        guard
    }

    #[test]
    fn zero_index_reinstalls_vtable_releases_owner_and_returns_this() {
        let _guard = install_recorder();
        let owner = 0x1234_5678usize as *mut u8;
        let mut registration = RegistrationHandle {
            vtable: 0,
            owner,
            slot_index: 0,
        };

        let returned = unsafe { registration_handle_destroy(&mut registration) };

        assert!(core::ptr::eq(returned, &mut registration));
        assert_eq!(registration.vtable, REGISTRATION_HANDLE_VTABLE);
        assert_eq!(unsafe { addr_of!(RELEASE_CALL).read() }, Some((owner, 0)));
    }

    #[test]
    fn minus_one_sentinel_reinstalls_vtable_without_releasing() {
        let _guard = install_recorder();
        let mut registration = RegistrationHandle {
            vtable: 0xdead_beef,
            owner: core::ptr::null_mut(),
            slot_index: -1,
        };

        let returned = unsafe { registration_handle_destroy(&mut registration) };

        assert!(core::ptr::eq(returned, &mut registration));
        assert_eq!(registration.vtable, REGISTRATION_HANDLE_VTABLE);
        assert_eq!(unsafe { addr_of!(RELEASE_CALL).read() }, None);
    }

    #[test]
    fn other_negative_indices_reach_the_release_helper_unchanged() {
        let _guard = install_recorder();
        let owner = 0x8765_4321usize as *mut u8;
        let mut registration = RegistrationHandle {
            vtable: 0,
            owner,
            slot_index: -2,
        };

        unsafe { registration_handle_destroy(&mut registration) };

        assert_eq!(unsafe { addr_of!(RELEASE_CALL).read() }, Some((owner, u32::MAX - 1)));
    }
}
