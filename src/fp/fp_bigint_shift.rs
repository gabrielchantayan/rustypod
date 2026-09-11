//! Signed arbitrary-precision integer shift wrapper.
//!
//! The unported directional cores remain in retailOS. On device their exact
//! entry addresses are called through volatile hook slots; host tests replace
//! those slots to observe the wrapper ABI.

/// Host-only stand-in for an unported retailOS directional shift core.
///
/// The entry wrapper is only exercised on the host with its hook slots
/// replaced. Silently doing nothing is preferable to attempting to call a
/// retailOS load address in a host process.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_right_shift_core(_value: *mut u32, _amount: u32) {}

/// Calls the retailOS right-shift core at 0x0833bde8.
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_right_shift_core(value: *mut u32, amount: u32) {
    let core: unsafe extern "C" fn(*mut u32, u32) = core::mem::transmute(0x0833_bde8usize);
    core(value, amount);
}

/// Host-only stand-in for an unported retailOS directional shift core.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_left_shift_core(_amount: u32, _value: *mut u32) {}

/// Calls the retailOS left-shift core at 0x08360b88.
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_left_shift_core(amount: u32, value: *mut u32) {
    let core: unsafe extern "C" fn(u32, *mut u32) = core::mem::transmute(0x0836_0b88usize);
    core(amount, value);
}

/// Unported 0x0833bde8 directional core: `value >>= amount`.
///
/// `static mut` is patched only during firmware bring-up, as with the
/// retailOS hook tables. Volatile reads preserve the live dispatch boundary.
#[cfg(target_os = "none")]
pub static mut BIGINT_RIGHT_SHIFT_CORE: unsafe extern "C" fn(*mut u32, u32) =
    retail_right_shift_core;
#[cfg(not(target_os = "none"))]
pub static mut BIGINT_RIGHT_SHIFT_CORE: unsafe extern "C" fn(*mut u32, u32) =
    unavailable_right_shift_core;

/// Unported 0x08360b88 directional core: `value <<= amount`.
///
/// Its argument order is `(amount, value)`, recovered from the raw prologue.
/// `static mut` follows the firmware hook-table mutation discipline.
#[cfg(target_os = "none")]
pub static mut BIGINT_LEFT_SHIFT_CORE: unsafe extern "C" fn(u32, *mut u32) =
    retail_left_shift_core;
#[cfg(not(target_os = "none"))]
pub static mut BIGINT_LEFT_SHIFT_CORE: unsafe extern "C" fn(u32, *mut u32) =
    unavailable_left_shift_core;

/// `bigint_shift_signed` — original `FUN_08340ee0` at 0x08340ee0 (36 bytes;
/// 9 verified plain `bl` call sites, 0 predicated).
///
/// Dispatches a signed shift for the retailOS normalized multi-limb integer:
/// positive `shift` tail-calls the left core at 0x08360b88 as `(shift, value)`;
/// zero and negative shifts tail-call the right core at 0x0833bde8 as
/// `(value, -shift)`. Negation wraps for `i32::MIN`, exactly like ARM `rsb`.
/// The directional core identities are not inferred beyond their binary
/// behavior. Deliberate deviation: the two still-stock cores are volatile
/// dispatch slots; device defaults call their verified load addresses, while
/// host defaults are inert and tests install recorders.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bigint_shift_signed(value: *mut u32, shift: i32) {
    if shift <= 0 {
        let right_shift = core::ptr::read_volatile(&raw const BIGINT_RIGHT_SHIFT_CORE);
        right_shift(value, shift.wrapping_neg() as u32);
    } else {
        let left_shift = core::ptr::read_volatile(&raw const BIGINT_LEFT_SHIFT_CORE);
        left_shift(shift as u32, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static SHIFT_TEST_LOCK: Mutex<()> = Mutex::new(());
    static RIGHT_VALUE: AtomicUsize = AtomicUsize::new(0);
    static RIGHT_AMOUNT: AtomicUsize = AtomicUsize::new(0);
    static LEFT_VALUE: AtomicUsize = AtomicUsize::new(0);
    static LEFT_AMOUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_right(value: *mut u32, amount: u32) {
        RIGHT_VALUE.store(value as usize, Ordering::SeqCst);
        RIGHT_AMOUNT.store(amount as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_left(amount: u32, value: *mut u32) {
        LEFT_AMOUNT.store(amount as usize, Ordering::SeqCst);
        LEFT_VALUE.store(value as usize, Ordering::SeqCst);
    }

    #[test]
    fn dispatches_signed_shifts_with_arm_wrapping_negation() {
        let _guard = SHIFT_TEST_LOCK.lock();
        let old_right = unsafe { BIGINT_RIGHT_SHIFT_CORE };
        let old_left = unsafe { BIGINT_LEFT_SHIFT_CORE };
        unsafe {
            BIGINT_RIGHT_SHIFT_CORE = record_right;
            BIGINT_LEFT_SHIFT_CORE = record_left;
        }

        let value = 0x2468usize as *mut u32;
        for &(shift, expected_amount) in &[(0, 0), (-1, 1), (i32::MIN, 0x8000_0000)] {
            RIGHT_VALUE.store(0, Ordering::SeqCst);
            RIGHT_AMOUNT.store(usize::MAX, Ordering::SeqCst);
            unsafe { bigint_shift_signed(value, shift) };
            assert_eq!(RIGHT_VALUE.load(Ordering::SeqCst), value as usize);
            assert_eq!(RIGHT_AMOUNT.load(Ordering::SeqCst), expected_amount);
        }

        for &shift in &[1, i32::MAX] {
            LEFT_VALUE.store(0, Ordering::SeqCst);
            LEFT_AMOUNT.store(usize::MAX, Ordering::SeqCst);
            unsafe { bigint_shift_signed(value, shift) };
            assert_eq!(LEFT_VALUE.load(Ordering::SeqCst), value as usize);
            assert_eq!(LEFT_AMOUNT.load(Ordering::SeqCst), shift as usize);
        }

        unsafe {
            BIGINT_RIGHT_SHIFT_CORE = old_right;
            BIGINT_LEFT_SHIFT_CORE = old_left;
        }
    }
}
