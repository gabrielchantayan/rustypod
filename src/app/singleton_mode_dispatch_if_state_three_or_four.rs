//! `singleton_mode_dispatch_if_state_three_or_four` — original:
//! `FUN_0817df88` @ `0x0817df88`.
//!
//! Raw ARM establishes the true **36-byte** extent `0x0817df88..0x0817dfac`;
//! `0x0817dfac` begins the next function with `push {r4,lr}`. It has two plain
//! `bl` instructions (`0x0829cf40`, `0x081ded14`) and no predicated `bl` forms.
//!
//! The function only obtains the lazy 0x28-byte singleton and tail-dispatches
//! its supplied mode when the state byte is 3 or 4.
//!
//! # Deliberate deviations
//!
//! The final target at `0x081df0e4` has no verified identity, so target builds
//! call its verified retailOS address and host builds expose that boundary as a
//! replaceable seam. The two ported callees are invoked directly rather than as
//! retailOS `bl` instructions.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_SINGLETON_MODE_DISPATCH: usize = 0x081d_f0e4;

pub type SingletonModeDispatch = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn singleton_mode_dispatch(singleton: *mut u8, mode: u32) {
    let call: SingletonModeDispatch = unsafe { core::mem::transmute(RETAIL_SINGLETON_MODE_DISPATCH) };
    unsafe { call(singleton, mode) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_singleton_mode_dispatch(_singleton: *mut u8, _mode: u32) {}

/// Host seam for the unported retailOS tail-dispatch target.
#[cfg(not(target_os = "none"))]
pub static mut SINGLETON_MODE_DISPATCH: SingletonModeDispatch = missing_singleton_mode_dispatch;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_singleton_mode_dispatch() -> SingletonModeDispatch {
    unsafe { core::ptr::read_volatile(addr_of!(SINGLETON_MODE_DISPATCH)) }
}

/// Tail-dispatches `mode` through the lazy singleton only for state bytes 3 or 4.
///
/// # Safety
/// `state` must point to a readable byte. On target, the lazy singleton and its
/// retail dispatch target must be valid firmware objects.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_mode_dispatch_if_state_three_or_four(state: *const u8, mode: u32) {
    if unsafe { crate::util::value_predicate::byte_is_three_or_four(state) } == 0 { return; }

    let singleton = unsafe { crate::app::singletons::lazy_singleton_0x28() };
    #[cfg(target_os = "none")]
    unsafe { singleton_mode_dispatch(singleton, mode) };
    #[cfg(not(target_os = "none"))]
    unsafe { host_singleton_mode_dispatch()(singleton, mode) };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static SINGLETON: AtomicUsize = AtomicUsize::new(0);
    static MODE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_dispatch(singleton: *mut u8, mode: u32) {
        CALLS.fetch_add(1, Ordering::SeqCst);
        SINGLETON.store(singleton as usize, Ordering::SeqCst);
        MODE.store(mode as usize, Ordering::SeqCst);
    }

    #[test]
    fn dispatches_only_for_states_three_and_four() {
        let _guard = crate::testing::SINGLETON_MODE_DISPATCH_TEST_LOCK.lock();
        let original = unsafe { SINGLETON_MODE_DISPATCH };
        unsafe { SINGLETON_MODE_DISPATCH = record_dispatch };
        for (state, should_dispatch) in [(0u8, false), (2, false), (3, true), (4, true), (5, false)] {
            CALLS.store(0, Ordering::SeqCst);
            unsafe { singleton_mode_dispatch_if_state_three_or_four(&state, 0xfeed_beef) };
            assert_eq!(CALLS.load(Ordering::SeqCst), usize::from(should_dispatch));
            if should_dispatch {
                assert_ne!(SINGLETON.load(Ordering::SeqCst), 0);
                assert_eq!(MODE.load(Ordering::SeqCst), 0xfeed_beef);
            }
        }
        unsafe { SINGLETON_MODE_DISPATCH = original };
    }
}
