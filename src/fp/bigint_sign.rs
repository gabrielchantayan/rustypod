//! Sign extraction for the retailOS encoded multi-limb integer.
//!
//! `bigint_sign` — original `FUN_082f7730` at `0x082f7730` (72 bytes:
//! 18 ARM words, including the multiplier literal at `0x082f7778`; 7 verified
//! direct `bl` call sites, all unconditional: `0x0830a85c`, `0x0831ef84`,
//! `0x0831ef90`, `0x08323464`, `0x08338658`, `0x0834d69c`, `0x08360bc0`).
//!
//! It first calls the still-stock `FUN_083276f0` zero predicate. A nonzero
//! predicate result returns zero. Otherwise it decodes the signed limb count
//! by multiplying the header word by the literal `0x4b6143ff`, returning one
//! when that wrapping product is positive and minus one otherwise. The raw
//! routine has no NULL guard. Deliberate deviation: host builds use a zero
//! predicate that reports zero because retailOS load address `0x083276f0`
//! cannot execute there; tests install a recorder through the volatile seam.

use core::ptr;

/// ABI of the still-stock normalized-multi-limb zero predicate at `0x083276f0`.
pub type BigintIsZero = unsafe extern "C" fn(*const u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_bigint_is_zero(value: *const u32) -> u32 {
    let is_zero: BigintIsZero = core::mem::transmute(0x0832_76f0usize);
    is_zero(value)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_bigint_is_zero(_value: *const u32) -> u32 {
    1
}

/// Volatile dispatch boundary for unported `FUN_083276f0`.
///
/// The device default calls its verified retailOS load address. Host tests
/// replace this slot because the retail image is not mapped in the process.
#[cfg(target_os = "none")]
pub static mut BIGINT_IS_ZERO: BigintIsZero = retail_bigint_is_zero;
#[cfg(not(target_os = "none"))]
pub static mut BIGINT_IS_ZERO: BigintIsZero = unavailable_bigint_is_zero;

/// Returns the sign of a normalized retailOS multi-limb integer.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bigint_sign")]
#[inline(never)]
pub unsafe extern "C" fn bigint_sign(value: *const u32) -> i32 {
    let is_zero = ptr::read_volatile(ptr::addr_of!(BIGINT_IS_ZERO));
    if is_zero(value) != 0 {
        return 0;
    }

    let encoded_count = value.read();
    let decoded_count = encoded_count.wrapping_mul(0x4b61_43ff) as i32;
    if decoded_count > 0 { 1 } else { -1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static BIGINT_SIGN_TEST_LOCK: Mutex<()> = Mutex::new(());
    static PREDICATE_RESULT: AtomicUsize = AtomicUsize::new(1);
    static PREDICATE_VALUE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_zero_predicate(value: *const u32) -> u32 {
        PREDICATE_VALUE.store(value as usize, Ordering::SeqCst);
        PREDICATE_RESULT.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn zero_predicate_gates_the_encoded_count() {
        let _guard = BIGINT_SIGN_TEST_LOCK.lock();
        let previous = unsafe { BIGINT_IS_ZERO };
        unsafe { BIGINT_IS_ZERO = record_zero_predicate };

        let value = [0xffff_ffffu32];
        PREDICATE_RESULT.store(7, Ordering::SeqCst);
        PREDICATE_VALUE.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { bigint_sign(value.as_ptr()) }, 0);
        assert_eq!(PREDICATE_VALUE.load(Ordering::SeqCst), value.as_ptr() as usize);

        unsafe { BIGINT_IS_ZERO = previous };
    }

    #[test]
    fn returns_sign_of_wrapping_decoded_count_when_nonzero() {
        let _guard = BIGINT_SIGN_TEST_LOCK.lock();
        let previous = unsafe { BIGINT_IS_ZERO };
        unsafe { BIGINT_IS_ZERO = record_zero_predicate };
        PREDICATE_RESULT.store(0, Ordering::SeqCst);

        for &(encoded_count, expected) in &[(1u32, 1), (u32::MAX, -1), (0, -1)] {
            let value = [encoded_count];
            assert_eq!(unsafe { bigint_sign(value.as_ptr()) }, expected);
        }

        unsafe { BIGINT_IS_ZERO = previous };
    }
}
