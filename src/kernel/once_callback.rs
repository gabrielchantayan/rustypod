//! Atomic callback-once control used before kernel object creation.

/// State already claimed (not necessarily finished).
pub const ONCE_CLAIMED: u32 = 0x4f4e_4345;
/// State accepted for the first callback invocation.
pub const ONCE_INITIAL: u32 = ONCE_CLAIMED + 14;

/// Original `FUN_080f4f74` at 0x080f4f74: 72 bytes through 0x080f4fbc,
/// comprising 64 instruction bytes and two literals. Raw whole-image decoding
/// verifies two inbound plain BLs (0x08086034, 0x0808b1d0), zero predicated
/// BLs. The body has zero plain/predicated BLs and one BLX r1.
///
/// Reject a null callback with 0x1a without touching control. Otherwise atomically
/// exchange control with ONCE_CLAIMED. A previous ONCE_INITIAL invokes callback
/// and returns zero; ONCE_CLAIMED returns zero without invoking it; all other
/// states return 0x1a but are still overwritten. No waiting or completion store:
/// reentrant and concurrent observers may succeed before callback finishes.
///
/// Deliberate deviations: host uses a relaxed AtomicU32 exchange in place of
/// ARMv5 SWP. Callback takes no semantic arguments; stock scratch r0/r2 values
/// are not part of its contract. No stronger completion guarantee is added.
///
/// # Safety
/// For a non-null callback, control must be aligned, live writable u32 storage;
/// concurrent access must use atomic operations. Callback must be callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn once_callback(
    control: *mut u32,
    callback: Option<unsafe extern "C" fn()>,
) -> u32 {
    let Some(callback) = callback else { return 0x1a; };
    let previous: u32;
    #[cfg(target_arch = "arm")]
    core::arch::asm!(
        "swp {previous}, {claimed}, [{control}]",
        previous = out(reg) previous,
        claimed = in(reg) ONCE_CLAIMED,
        control = in(reg) control,
        options(nostack, preserves_flags),
    );
    #[cfg(not(target_arch = "arm"))]
    {
        previous = core::sync::atomic::AtomicU32::from_ptr(control)
            .swap(ONCE_CLAIMED, core::sync::atomic::Ordering::Relaxed);
    }
    match previous {
        ONCE_CLAIMED => 0,
        ONCE_INITIAL => { callback(); 0 }
        _ => 0x1a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static CALLS: AtomicU32 = AtomicU32::new(0);
    extern crate std;
    static CONTROL: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());

    unsafe extern "C" fn record() { CALLS.fetch_add(1, Ordering::Relaxed); }
    unsafe extern "C" fn reenter() {
        record();
        let control = CONTROL.load(Ordering::Relaxed);
        assert_eq!(AtomicU32::from_ptr(control).load(Ordering::Relaxed), ONCE_CLAIMED);
        assert_eq!(once_callback(control, Some(record)), 0);
    }

    #[test]
    fn null_callback_does_not_access_control() {
        assert_eq!(unsafe { once_callback(core::ptr::null_mut(), None) }, 0x1a);
        let mut control = ONCE_INITIAL;
        assert_eq!(unsafe { once_callback(&mut control, None) }, 0x1a);
        assert_eq!(control, ONCE_INITIAL);
    }

    #[test]
    fn state_validation_claims_even_invalid_words() {
        let _lock = LOCK.lock();
        for state in [0, 1, u32::MAX, ONCE_INITIAL - 1, ONCE_INITIAL + 1, ONCE_CLAIMED] {
            CALLS.store(0, Ordering::Relaxed);
            let mut control = state;
            let expected = if state == ONCE_CLAIMED { 0 } else { 0x1a };
            assert_eq!(unsafe { once_callback(&mut control, Some(record)) }, expected);
            assert_eq!(control, ONCE_CLAIMED);
            assert_eq!(CALLS.load(Ordering::Relaxed), 0);
            assert_eq!(unsafe { once_callback(&mut control, Some(record)) }, 0);
        }
    }

    #[test]
    fn callback_observes_claim_and_reentry_does_not_call_again() {
        let _lock = LOCK.lock();
        CALLS.store(0, Ordering::Relaxed);
        let mut control = ONCE_INITIAL;
        CONTROL.store(&mut control, Ordering::Relaxed);
        assert_eq!(unsafe { once_callback(&mut control, Some(reenter)) }, 0);
        assert_eq!(unsafe { once_callback(&mut control, Some(record)) }, 0);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        CONTROL.store(core::ptr::null_mut(), Ordering::Relaxed);
    }

    #[test]
    fn concurrent_claim_has_only_one_callback() {
        let _lock = LOCK.lock();
        CALLS.store(0, Ordering::Relaxed);
        let control = AtomicU32::new(ONCE_INITIAL);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let control = &control;
                scope.spawn(move || {
                    assert_eq!(unsafe { once_callback(control.as_ptr(), Some(record)) }, 0);
                });
            }
        });
        assert_eq!(control.load(Ordering::Relaxed), ONCE_CLAIMED);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    }
}
