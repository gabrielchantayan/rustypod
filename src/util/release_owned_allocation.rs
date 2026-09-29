//! Releases an owned allocation and reports success.
//!
//! Original: `FUN_082d73e4` at `0x082d73e4` (164 bytes, including the
//! six-word literal pool through `0x082d7484`; next function starts at
//! `0x082d7488`). Raw ARM decoding finds one outbound plain `bl`, to
//! `FUN_0830a234`, and no predicated `bl`; that helper conditionally calls the
//! already ported ADS `free` entry `FUN_0802edc8` at `0x0802edc8`. It has two
//! inbound plain `bl` sites (`0x08078bb4` and `0x080fda70`) and no predicated
//! inbound calls.
//!
//! The literal-driven state machines reduce to: if `allocation` is non-NULL,
//! call `free(allocation)`; then return zero. Deliberate deviation: the port
//! expresses that observable behavior directly instead of retaining the
//! opaque arithmetic and control-flow obfuscation around the call.

use crate::runtime::malloc_rt::free;

#[inline(always)]
unsafe fn release_owned_allocation_with(
    allocation: *mut u8,
    release: unsafe extern "C" fn(*mut u8),
) -> u32 {
    if !allocation.is_null() {
        release(allocation);
    }
    0
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_owned_allocation(allocation: *mut u8) -> u32 {
    release_owned_allocation_with(allocation, free)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_ALLOCATION: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(allocation: *mut u8) {
        RELEASE_COUNT.fetch_add(1, Ordering::Relaxed);
        RELEASED_ALLOCATION.store(allocation as usize, Ordering::Relaxed);
    }

    #[test]
    fn null_allocation_is_not_released_and_returns_zero() {
        RELEASE_COUNT.store(0, Ordering::Relaxed);
        assert_eq!(unsafe { release_owned_allocation_with(core::ptr::null_mut(), record_release) }, 0);
        assert_eq!(RELEASE_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn owned_allocation_is_released_once_and_returns_zero() {
        const ALLOCATION: usize = 0x1234_5000;
        RELEASE_COUNT.store(0, Ordering::Relaxed);
        RELEASED_ALLOCATION.store(0, Ordering::Relaxed);
        assert_eq!(unsafe { release_owned_allocation_with(ALLOCATION as *mut u8, record_release) }, 0);
        assert_eq!(RELEASE_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(RELEASED_ALLOCATION.load(Ordering::Relaxed), ALLOCATION);
    }
}
