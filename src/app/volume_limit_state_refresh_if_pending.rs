//! `volume_limit_state_refresh_if_pending` — original: `FUN_0827f6a8` @
//! **0x0827f6a8** (36 bytes exactly, 0x0827f6a8..0x0827f6cb).
//!
//! Raw A32 decoding establishes that `push {r4,lr}` begins the body and
//! `pop {r4,pc}` ends it; the next separately entered function starts at
//! 0x0827f6cc. The body has **zero plain `bl` calls** and **one predicated
//! `bleq` call** (to the unnamed resident routine at 0x0827fae0). Whole-image
//! decoding finds three incoming plain `bl` call sites and no predicated
//! incoming `bl` calls.
//!
//! ## Algorithm
//!
//! Read the opaque volume-limit state word at `object + 0xb4`. If it is 3,
//! invoke the unnamed resident refresh routine with `object` and
//! `object + 0xac`; then reread and return the state word.
//!
//! ## Deliberate deviation
//!
//! The resident callee at 0x0827fae0 has no verified semantic name, so the
//! target build calls its exact address and host builds expose a narrow seam.

#[cfg(not(target_os = "none"))]
use core::ptr;

const PENDING_STATE: u32 = 3;
const STATE_OFFSET: usize = 0xb4;
const REFRESH_ARGUMENT_OFFSET: usize = 0xac;
const FIRMWARE_REFRESH_ADDRESS: usize = 0x0827_fae0;

type VolumeLimitStateRefresh = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn firmware_refresh(object: *mut u8) {
    let refresh: VolumeLimitStateRefresh = unsafe { core::mem::transmute(FIRMWARE_REFRESH_ADDRESS) };
    unsafe { refresh(object, object.add(REFRESH_ARGUMENT_OFFSET)) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh(_object: *mut u8, _argument: *mut u8) {
    panic!("volume_limit_state_refresh_if_pending requires 0x0827fae0")
}

#[cfg(not(target_os = "none"))]
pub static mut VOLUME_LIMIT_STATE_REFRESH: VolumeLimitStateRefresh = missing_refresh;

/// Refreshes a pending volume-limit state and returns its resulting state word.
///
/// # Safety
///
/// `object` must address a retail object with an aligned, readable state word
/// at +0xb4. When that word is 3, it must also be valid for the resident
/// routine at 0x0827fae0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_limit_state_refresh_if_pending(object: *mut u8) -> u32 {
    let state = unsafe { object.add(STATE_OFFSET).cast::<u32>().read_volatile() };
    if state == PENDING_STATE {
        #[cfg(target_os = "none")]
        unsafe { firmware_refresh(object) };
        #[cfg(not(target_os = "none"))]
        {
            let refresh = unsafe { ptr::addr_of!(VOLUME_LIMIT_STATE_REFRESH).read_volatile() };
            unsafe { refresh(object, object.add(REFRESH_ARGUMENT_OFFSET)) };
        }
    }
    unsafe { object.add(STATE_OFFSET).cast::<u32>().read_volatile() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static CALL: Mutex<Option<(usize, usize)>> = Mutex::new(None);
    static OPS_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn record_refresh(object: *mut u8, argument: *mut u8) {
        *CALL.lock().unwrap_or_else(|poison| poison.into_inner()) = Some((object as usize, argument as usize));
        unsafe { object.add(STATE_OFFSET).cast::<u32>().write_volatile(1) };
    }

    struct RefreshGuard {
        saved: VolumeLimitStateRefresh,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for RefreshGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(VOLUME_LIMIT_STATE_REFRESH).write_volatile(self.saved) };
            *CALL.lock().unwrap_or_else(|poison| poison.into_inner()) = None;
        }
    }

    fn install() -> RefreshGuard {
        let lock = OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let saved = unsafe { ptr::addr_of!(VOLUME_LIMIT_STATE_REFRESH).read_volatile() };
        unsafe { ptr::addr_of_mut!(VOLUME_LIMIT_STATE_REFRESH).write_volatile(record_refresh) };
        *CALL.lock().unwrap_or_else(|poison| poison.into_inner()) = None;
        RefreshGuard { saved, _lock: lock }
    }

    #[test]
    fn returns_non_pending_state_without_refreshing() {
        let _guard = install();
        let mut object = [0u32; (STATE_OFFSET + 4) / 4];
        object[STATE_OFFSET / 4] = 2;

        let result = unsafe { volume_limit_state_refresh_if_pending(object.as_mut_ptr().cast()) };

        assert_eq!(result, 2);
        assert_eq!(*CALL.lock().unwrap_or_else(|poison| poison.into_inner()), None);
    }

    #[test]
    fn refreshes_pending_state_and_returns_reloaded_value() {
        let _guard = install();
        let mut object = [0u32; (STATE_OFFSET + 4) / 4];
        object[STATE_OFFSET / 4] = PENDING_STATE;
        let object_ptr = object.as_mut_ptr().cast::<u8>();

        let result = unsafe { volume_limit_state_refresh_if_pending(object_ptr) };

        assert_eq!(result, 1);
        assert_eq!(
            *CALL.lock().unwrap_or_else(|poison| poison.into_inner()),
            Some((object_ptr as usize, unsafe { object_ptr.add(REFRESH_ARGUMENT_OFFSET) } as usize))
        );
    }
}
