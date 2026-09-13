//! Polls a Genius request until it is ready or its one-second window expires.
//!
//! `genius_request_wait_ready` — original: `FUN_0816ec88` @ **0x0816ec88**
//! (**80 bytes**, exactly `0x0816ec88..0x0816ecd8`; the next separately linked
//! function begins at `0x0816ecd8`).
//!
//! **7 direct `bl` call sites, all unconditional; 0 predicated `bl` and 0
//! direct tail-`b` call sites**, verified by decoding every aligned ARM
//! `B`/`BL` immediate in `osos.dec`: 0x0821d994, 0x08222b5c, 0x08226008,
//! 0x08226224, 0x08235448, 0x08238600, and 0x082387e0.
//!
//! ## Algorithm
//!
//! Takes an initial sample from the ported Timer E millisecond counter, then
//! checks the request with 0x0816ecd8. An unready request is advanced by
//! 0x0816ee74; a zero result from that helper is still a successful result.
//! Otherwise it samples the counter again and returns zero only when unsigned
//! elapsed time reaches 1000. The subtraction deliberately wraps exactly as
//! the ARM `sub`/`cmp` pair does.
//!
//! ## Dispatch boundary
//!
//! 0x0816ecd8 and 0x0816ee74 have no `ported` entries in `names.yaml`, so the
//! target defaults call their fixed retailOS addresses and host tests replace
//! them through a volatile operation table. Their identities are limited to
//! the observed ready predicate and request-advance roles; no deeper callee
//! identity is claimed. The Timer E reader is already ported and called
//! directly. No deliberate behavioral deviations.

use core::ffi::c_void;
use core::ptr;

use crate::drivers::timer::usec_timer_read_seconds;

/// Tests whether a Genius request has reached its expected completion state.
pub type GeniusRequestReady = unsafe extern "C" fn(request: *mut c_void) -> u32;

/// Advances an unready Genius request. A zero status ends the wait successfully.
pub type GeniusRequestAdvance = unsafe extern "C" fn(request: *mut c_void) -> u32;

#[derive(Clone, Copy)]
pub struct GeniusRequestWaitOps {
    pub is_ready: GeniusRequestReady,
    pub advance: GeniusRequestAdvance,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_request_is_ready(request: *mut c_void) -> u32 {
    let predicate: GeniusRequestReady = unsafe { core::mem::transmute(0x0816_ecd8usize) };
    unsafe { predicate(request) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_request_is_ready(_request: *mut c_void) -> u32 {
    panic!("genius_request_wait_ready requires 0x0816ecd8")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_request_advance(request: *mut c_void) -> u32 {
    let advance: GeniusRequestAdvance = unsafe { core::mem::transmute(0x0816_ee74usize) };
    unsafe { advance(request) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_request_advance(_request: *mut c_void) -> u32 {
    panic!("genius_request_wait_ready requires 0x0816ee74")
}

/// The two unported helpers called by [`genius_request_wait_ready`].
///
/// Target builds dispatch directly to retailOS; host tests install recording
/// implementations before exercising the port.
pub static mut GENIUS_REQUEST_WAIT_OPS: GeniusRequestWaitOps = GeniusRequestWaitOps {
    is_ready: firmware_request_is_ready,
    advance: firmware_request_advance,
};

#[inline(always)]
unsafe fn request_wait_ops() -> GeniusRequestWaitOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(GENIUS_REQUEST_WAIT_OPS)) }
}

const WAIT_TICKS: u32 = 1_000;

#[inline(always)]
unsafe fn wait_for_request_ready_with_clock<F>(
    request: *mut c_void,
    mut clock: F,
) -> u32
where
    F: FnMut() -> u32,
{
    let ops = unsafe { request_wait_ops() };
    let started = clock();

    loop {
        if unsafe { (ops.is_ready)(request) } != 0 {
            return 1;
        }
        if unsafe { (ops.advance)(request) } == 0 {
            return 1;
        }
        if clock().wrapping_sub(started) >= WAIT_TICKS {
            return 0;
        }
    }
}

/// Waits for a Genius request to become ready.
///
/// Original: `FUN_0816ec88` @ 0x0816ec88 (80 bytes; 7 unconditional direct
/// `bl` call sites). Samples the millisecond counter before every readiness
/// check/advance cycle and returns one for ready or terminal requests; returns
/// zero after 1000 wrapped unsigned ticks of still-advancing work.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn genius_request_wait_ready(request: *mut c_void) -> u32 {
    unsafe { wait_for_request_ready_with_clock(request, || usec_timer_read_seconds()) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ffi::c_void;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::{
        genius_request_wait_ready, wait_for_request_ready_with_clock, GeniusRequestWaitOps,
        GENIUS_REQUEST_WAIT_OPS,
    };

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static READY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ADVANCE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static READY_ON_CALL: AtomicUsize = AtomicUsize::new(0);
    static ADVANCE_RESULT: AtomicUsize = AtomicUsize::new(1);
    static LAST_READY_REQUEST: AtomicUsize = AtomicUsize::new(0);
    static LAST_ADVANCE_REQUEST: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_ready(request: *mut c_void) -> u32 {
        LAST_READY_REQUEST.store(request as usize, Ordering::Relaxed);
        let call = READY_CALLS.fetch_add(1, Ordering::Relaxed);
        (call >= READY_ON_CALL.load(Ordering::Relaxed)) as u32
    }

    unsafe extern "C" fn record_advance(request: *mut c_void) -> u32 {
        LAST_ADVANCE_REQUEST.store(request as usize, Ordering::Relaxed);
        ADVANCE_CALLS.fetch_add(1, Ordering::Relaxed);
        ADVANCE_RESULT.load(Ordering::Relaxed) as u32
    }

    struct OpsRestore(GeniusRequestWaitOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(GENIUS_REQUEST_WAIT_OPS), self.0) }
        }
    }

    fn install_ops(ready_on_call: usize, advance_result: u32) -> OpsRestore {
        READY_CALLS.store(0, Ordering::Relaxed);
        ADVANCE_CALLS.store(0, Ordering::Relaxed);
        READY_ON_CALL.store(ready_on_call, Ordering::Relaxed);
        ADVANCE_RESULT.store(advance_result as usize, Ordering::Relaxed);
        LAST_READY_REQUEST.store(0, Ordering::Relaxed);
        LAST_ADVANCE_REQUEST.store(0, Ordering::Relaxed);

        unsafe {
            let previous = ptr::read_volatile(ptr::addr_of!(GENIUS_REQUEST_WAIT_OPS));
            ptr::write_volatile(
                ptr::addr_of_mut!(GENIUS_REQUEST_WAIT_OPS),
                GeniusRequestWaitOps {
                    is_ready: record_ready,
                    advance: record_advance,
                },
            );
            OpsRestore(previous)
        }
    }

    #[test]
    fn ready_request_succeeds_without_advancing() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_ops(0, 1);
        let request = 0x1234usize as *mut c_void;

        assert_eq!(unsafe { genius_request_wait_ready(request) }, 1);
        assert_eq!(READY_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(ADVANCE_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(LAST_READY_REQUEST.load(Ordering::Relaxed), request as usize);
    }

    #[test]
    fn unready_request_advances_until_ready() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_ops(2, 1);
        let request = 0x5678usize as *mut c_void;
        let mut ticks = [10, 509, 1_009].into_iter();

        assert_eq!(
            unsafe { wait_for_request_ready_with_clock(request, || ticks.next().unwrap()) },
            1
        );
        assert_eq!(READY_CALLS.load(Ordering::Relaxed), 3);
        assert_eq!(ADVANCE_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(LAST_READY_REQUEST.load(Ordering::Relaxed), request as usize);
        assert_eq!(LAST_ADVANCE_REQUEST.load(Ordering::Relaxed), request as usize);
    }

    #[test]
    fn terminal_advance_succeeds_without_another_clock_sample() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_ops(usize::MAX, 0);
        let mut samples = 0;

        assert_eq!(
            unsafe {
                wait_for_request_ready_with_clock(ptr::null_mut(), || {
                    samples += 1;
                    17
                })
            },
            1
        );
        assert_eq!(samples, 1);
        assert_eq!(READY_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(ADVANCE_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn timeout_uses_wrapped_unsigned_elapsed_time_at_exact_threshold() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install_ops(usize::MAX, 1);
        let mut ticks = [u32::MAX - 15, 984].into_iter();

        assert_eq!(
            unsafe { wait_for_request_ready_with_clock(ptr::null_mut(), || ticks.next().unwrap()) },
            0
        );
        assert_eq!(READY_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(ADVANCE_CALLS.load(Ordering::Relaxed), 1);
    }
}
