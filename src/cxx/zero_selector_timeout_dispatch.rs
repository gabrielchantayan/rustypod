//! `zero_selector_timeout_dispatch` — original: `FUN_082620cc` @ **0x082620cc**
//! (12 bytes).
//!
//! Raw ARM is `mov r0,r1; mov r1,#0; b 0x082dadb8`. The next distinct
//! function starts at 0x082620d8. The body has no `bl`; whole-image ARM
//! decoding finds five plain incoming `bl` call sites (0x08165328, 0x081654b8,
//! 0x081d7780, 0x081d77f0, 0x08201198) and zero predicated forms, despite
//! Ghidra extending this function through later, distinct bodies.
//!
//! Algorithm: discard the first argument, pass the timeout object as the
//! second argument of a zero-selector request, and tail-dispatch it through
//! 0x082dadb8. That relay supplies the remaining zero arguments before it
//! tail-branches to the common request dispatcher.
//!
//! Deliberate deviation: 0x082dadb8 is unported. Target builds call its fixed
//! retailOS address; host builds use a volatile callback seam to prove the
//! exact transformed argument tuple and returned status.

#[cfg(not(target_os = "none"))]
use core::ptr;

const RETAIL_ZERO_SELECTOR_TIMEOUT_RELAY: usize = 0x082d_adb8;

type ZeroSelectorTimeoutRelay = unsafe extern "C" fn(u32, u32, *mut u8, u32) -> u32;

#[cfg(not(target_os = "none"))]
pub struct ZeroSelectorTimeoutDispatchOps {
    pub relay: ZeroSelectorTimeoutRelay,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_zero_selector_timeout_relay(
    _selector: u32,
    _mode: u32,
    _timeout: *mut u8,
    _context: u32,
) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
pub static mut ZERO_SELECTOR_TIMEOUT_DISPATCH_OPS: ZeroSelectorTimeoutDispatchOps = ZeroSelectorTimeoutDispatchOps {
    relay: missing_zero_selector_timeout_relay,
};

#[inline(always)]
unsafe fn zero_selector_timeout_relay(timeout: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        let relay: ZeroSelectorTimeoutRelay = core::mem::transmute(RETAIL_ZERO_SELECTOR_TIMEOUT_RELAY);
        relay(0, 0, timeout, 0)
    }
    #[cfg(not(target_os = "none"))]
    {
        let relay = unsafe { ptr::read_volatile(ptr::addr_of!(ZERO_SELECTOR_TIMEOUT_DISPATCH_OPS.relay)) };
        relay(0, 0, timeout, 0)
    }
}

/// Discards `handle` and dispatches a zero-selector request with `timeout`.
///
/// # Safety
/// `timeout` is forwarded to unported retailOS code, which determines its
/// required object layout and lifetime. `handle` is retained in the ABI but is
/// not read by the decoded ARM body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.zero_selector_timeout_dispatch")]
#[inline(never)]
pub unsafe extern "C" fn zero_selector_timeout_dispatch(_handle: *mut u8, timeout: *mut u8) -> u32 {
    unsafe { zero_selector_timeout_relay(timeout) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SELECTOR: AtomicU32 = AtomicU32::new(u32::MAX);
    static MODE: AtomicU32 = AtomicU32::new(u32::MAX);
    static TIMEOUT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static CONTEXT: AtomicU32 = AtomicU32::new(u32::MAX);

    unsafe extern "C" fn record_relay(selector: u32, mode: u32, timeout: *mut u8, context: u32) -> u32 {
        SELECTOR.store(selector, Ordering::SeqCst);
        MODE.store(mode, Ordering::SeqCst);
        TIMEOUT.store(timeout as usize, Ordering::SeqCst);
        CONTEXT.store(context, Ordering::SeqCst);
        0x1a
    }

    #[test]
    fn discards_handle_and_forwards_timeout_in_zero_selector_request() {
        let _guard = TEST_LOCK.lock();
        unsafe { ZERO_SELECTOR_TIMEOUT_DISPATCH_OPS = ZeroSelectorTimeoutDispatchOps { relay: record_relay } };
        let mut handle = [0xa5; 12];
        let mut timeout = [0x5a; 8];

        let status = unsafe { zero_selector_timeout_dispatch(handle.as_mut_ptr(), timeout.as_mut_ptr()) };

        assert_eq!(status, 0x1a);
        assert_eq!(SELECTOR.load(Ordering::SeqCst), 0);
        assert_eq!(MODE.load(Ordering::SeqCst), 0);
        assert_eq!(TIMEOUT.load(Ordering::SeqCst), timeout.as_mut_ptr() as usize);
        assert_eq!(CONTEXT.load(Ordering::SeqCst), 0);
    }
}
