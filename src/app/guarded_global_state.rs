//! `guarded_global_state_get` — original: `FUN_081a8fd0` @ **0x081a8fd0**.
//!
//! Raw ARM establishes a 60-byte instruction extent,
//! `0x081a8fd0..0x081a900c`; its two-word literal pool occupies
//! `0x081a900c..0x081a9014`, and the next real function begins at
//! `0x081a9014`. The body has one plain unconditional `bl`
//! (`cxa_guard_acquire` @ `0x082ab31c`) and one predicated `blne`
//! (`cxa_guard_release` @ `0x082ab338`). Three inbound direct call sites are
//! plain `bl`; there are no predicated inbound call sites.
//!
//! Algorithm: test bit zero of guard `0x08a0e6e4`. If clear and acquisition
//! succeeds, clear word `+0x14` of the fixed global state at `0x08b20b3c`,
//! then release the guard. Every path returns that global state address.
//!
//! Deliberate deviations: no semantic identity for the fixed global state has
//! been recovered, so its only named field is the observed reset word. Host
//! builds model the fixed firmware RAM with statics.

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

const FIRMWARE_GUARD: usize = 0x08a0_e6e4;
const FIRMWARE_GLOBAL_STATE: usize = 0x08b2_0b3c;
const RESET_WORD_INDEX: usize = 0x14 / core::mem::size_of::<u32>();

type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

/// A volatile binding preserves the predicated retail release call boundary;
/// its current ADS implementation is otherwise a no-op.
static mut GUARDED_GLOBAL_STATE_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[cfg(not(target_os = "none"))]
static mut GUARDED_GLOBAL_STATE_GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut GUARDED_GLOBAL_STATE: [u32; RESET_WORD_INDEX + 1] = [0; RESET_WORD_INDEX + 1];

#[inline(always)]
unsafe fn guarded_global_state_release() -> CxaGuardRelease {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GUARDED_GLOBAL_STATE_CXA_GUARD_RELEASE)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn guarded_global_state_guard() -> *mut u32 {
    FIRMWARE_GUARD as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn guarded_global_state_guard() -> *mut u32 {
    core::ptr::addr_of_mut!(GUARDED_GLOBAL_STATE_GUARD)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn guarded_global_state() -> *mut u32 {
    FIRMWARE_GLOBAL_STATE as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn guarded_global_state() -> *mut u32 {
    core::ptr::addr_of_mut!(GUARDED_GLOBAL_STATE).cast::<u32>()
}

/// Clears the observed reset word once and returns the fixed global state.
///
/// # Safety
///
/// On target, the fixed firmware guard and global-state addresses must remain
/// valid and writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn guarded_global_state_get() -> *mut u32 {
    let guard = unsafe { guarded_global_state_guard() };
    let state = unsafe { guarded_global_state() };
    if unsafe { core::ptr::read_volatile(guard) } & 1 == 0 && unsafe { cxa_guard_acquire(guard) } != 0 {
        unsafe {
            core::ptr::write_volatile(state.add(RESET_WORD_INDEX), 0);
            guarded_global_state_release()(guard);
        }
    }
    state
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static GUARDED_GLOBAL_STATE_LOCK: Mutex<()> = Mutex::new(());

    fn reset() -> MutexGuard<'static, ()> {
        let lock = GUARDED_GLOBAL_STATE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            GUARDED_GLOBAL_STATE_GUARD = 0;
            GUARDED_GLOBAL_STATE = [0xaaaa_aaaa; RESET_WORD_INDEX + 1];
        }
        lock
    }

    #[test]
    fn first_call_clears_only_the_observed_reset_word() {
        let _lock = reset();
        unsafe {
            let state = guarded_global_state_get();
            assert_eq!(state, guarded_global_state());
            assert_eq!(GUARDED_GLOBAL_STATE_GUARD, 1);
            assert_eq!(*state.add(RESET_WORD_INDEX), 0);
            assert_eq!(*state.add(RESET_WORD_INDEX - 1), 0xaaaa_aaaa);
        }
    }

    #[test]
    fn initialized_guard_preserves_global_state() {
        let _lock = reset();
        unsafe {
            GUARDED_GLOBAL_STATE_GUARD = 1;
            let state = guarded_global_state_get();
            assert_eq!(*state.add(RESET_WORD_INDEX), 0xaaaa_aaaa);
        }
    }

    #[test]
    fn bit_zero_clear_nonzero_guard_is_refused_by_acquire() {
        let _lock = reset();
        unsafe {
            GUARDED_GLOBAL_STATE_GUARD = 2;
            let state = guarded_global_state_get();
            assert_eq!(GUARDED_GLOBAL_STATE_GUARD, 2);
            assert_eq!(*state.add(RESET_WORD_INDEX), 0xaaaa_aaaa);
        }
    }
}
