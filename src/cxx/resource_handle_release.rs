//! `resource_handle_release_if_owned` — retailOS `FUN_08262138` at
//! `0x08262138` (32 bytes; `0x08262138..0x08262158`).
//!
//! Raw ARM establishes the extent: `pop {r4,pc}` at `0x08262154` is followed
//! immediately by the distinct function beginning `push {r4,lr}` at
//! `0x08262158`; there is no literal pool. Decoding every ARM B/BL word in
//! `osos.dec` finds 14 direct call sites, all unconditional plain `bl` (at
//! `0x08165330`, `0x081654c0`, `0x081939d8`, `0x081d7788`, `0x081d77f8`,
//! `0x081e6c10`, `0x082011a0`, `0x082628b0`, `0x0839e938`, `0x0839e958`,
//! `0x0839eaa4`, `0x0839eac4`, `0x0839f480`, and `0x0839f4a0`). There are no
//! predicated calls and no word-aligned DATA references to this address.
//!
//! The handle's byte at target offset +0x08 suppresses disposal when nonzero.
//! When it is zero, the function calls the still-unported immediate helper
//! `FUN_082620d8` at `0x082620d8`, which reloads the resource pointer at +0x00
//! and transfers it to the resource release body at `0x082e817c`. The helper's
//! return value is intentionally discarded; this wrapper always returns the
//! original handle pointer.
//!
//! Deliberate deviation: the immediate helper is absent from `names.yaml`, so
//! target builds call its fixed retailOS address. Host builds use a volatile
//! seam solely to prove this wrapper's ownership gate and return value.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_RESOURCE_HANDLE_RELEASE: usize = 0x0826_20d8;

/// Target-layout prefix read by `resource_handle_release_if_owned`.
///
/// `resource_address` is a 32-bit target pointer, retained as `u32` so the
/// state byte remains at target offset +0x08 in 64-bit host fixtures.
#[repr(C)]
pub struct ResourceHandle {
    pub resource_address: u32,
    pub operation_status: u32,
    pub skip_release: u8,
}

/// ABI of the unported `FUN_082620d8` helper.
pub type ResourceHandleRelease = unsafe extern "C" fn(*mut ResourceHandle) -> u32;

/// Host operation replacing the retail helper at `0x082620d8`.
#[derive(Clone, Copy)]
pub struct ResourceHandleReleaseOps {
    pub release: ResourceHandleRelease,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_resource_handle_release(handle: *mut ResourceHandle) -> u32 {
    let release: ResourceHandleRelease = core::mem::transmute(RETAIL_RESOURCE_HANDLE_RELEASE);
    release(handle)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_handle_release(_handle: *mut ResourceHandle) -> u32 {
    panic!("install resource-handle release host operations before calling this wrapper")
}

/// Default host operation, which makes an unexpected release visible.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_RESOURCE_HANDLE_RELEASE_OPS: ResourceHandleReleaseOps =
    ResourceHandleReleaseOps { release: missing_resource_handle_release };

/// Host-only seam for the unported resource-handle release helper.
#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_HANDLE_RELEASE_OPS: ResourceHandleReleaseOps =
    DEFAULT_RESOURCE_HANDLE_RELEASE_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_resource_handle_release(handle: *mut ResourceHandle) -> u32 {
    let release = core::ptr::read_volatile(addr_of!(RESOURCE_HANDLE_RELEASE_OPS.release));
    release(handle)
}

/// Releases `handle`'s resource unless the handle marks release as skipped.
///
/// `handle` must be valid and readable through +0x08. The unported helper has
/// the stronger validity requirements for its resource pointer when called.
/// The function returns `handle` in both paths, matching the raw final
/// `mov r0,r4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_handle_release_if_owned(
    handle: *mut ResourceHandle,
) -> *mut ResourceHandle {
    if (*handle).skip_release == 0 {
        #[cfg(target_os = "none")]
        retail_resource_handle_release(handle);
        #[cfg(not(target_os = "none"))]
        host_resource_handle_release(handle);
    }
    handle
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASED_HANDLE: *mut ResourceHandle = core::ptr::null_mut();
    static mut RELEASE_CALLS: u32 = 0;

    unsafe extern "C" fn record_release(handle: *mut ResourceHandle) -> u32 {
        RELEASED_HANDLE = handle;
        RELEASE_CALLS += 1;
        0x1a
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(RELEASED_HANDLE).write(core::ptr::null_mut());
            addr_of_mut!(RELEASE_CALLS).write(0);
            addr_of_mut!(RESOURCE_HANDLE_RELEASE_OPS).write(ResourceHandleReleaseOps {
                release: record_release,
            });
        }
        guard
    }

    #[test]
    fn releases_an_owned_handle_and_returns_it() {
        let _guard = install_recorder();
        let mut handle = ResourceHandle {
            resource_address: 0x08aa_1234,
            operation_status: 0x7654_3210,
            skip_release: 0,
        };

        let result = unsafe { resource_handle_release_if_owned(&mut handle) };

        assert_eq!(result, core::ptr::addr_of_mut!(handle));
        unsafe {
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 1);
            assert_eq!(addr_of!(RELEASED_HANDLE).read(), result);
        }
    }

    #[test]
    fn skips_release_for_every_nonzero_gate_value() {
        let _guard = install_recorder();
        for skip_release in [1, 0xff] {
            let mut handle = ResourceHandle {
                resource_address: 0,
                operation_status: 0,
                skip_release,
            };

            let result = unsafe { resource_handle_release_if_owned(&mut handle) };

            assert_eq!(result, core::ptr::addr_of_mut!(handle));
        }
        unsafe {
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 0);
            assert!(addr_of!(RELEASED_HANDLE).read().is_null());
        }
    }
}
