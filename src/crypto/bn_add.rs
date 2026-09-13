//! OpenSSL's `BN_add` — signed addition of two `BIGNUM`s in the
//! SSLeay-era libcrypto Apple vendored into retailOS.
//!
//! Port: `bn_add` — `FUN_0803e144` @ 0x0803e144 (188 bytes,
//! 0x0803e144..0x0803e200; **7 call sites**, binary-verified by
//! decoding every ARM B/BL word in osos.dec: all 7 are unconditional
//! `bl` (cond 0xe), with no predicated forms).
//!
//! # Algorithm
//!
//! Read both `neg` flags. Equal signs delegate to `BN_uadd` then
//! normalize that shared sign to 0 or 1. Different signs compare the
//! positive and negative magnitudes with [`bn_ucmp`], subtract the
//! smaller from the larger through `BN_usub`, and assign 0/1 according
//! to the magnitude that won. A worker failure returns 0 without
//! changing `result->neg`; success returns 1.
//!
//! Raw bytes confirm the 47-word extent: the next word @ 0x0803e200 is
//! a separate `push {r4-r6,lr}` prologue. `BN_uadd` @ 0x08040ce0 and
//! `BN_usub` @ 0x08040e34 are not yet ported, so their original direct
//! calls ride volatile dispatch slots. On-device each default reaches
//! its stock address; host tests install workers. This indirect seam is
//! the only deliberate deviation.

use super::bn_num_bits::BigNum;
use super::bn_ucmp::bn_ucmp;

/// Signature shared by the unsigned add/subtract workers.
pub type BnBinaryOpFn = unsafe extern "C" fn(
    result: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
) -> i32;

/// Target default: `BN_uadd` @ 0x08040ce0, retained until it is ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_uadd(
    result: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
) -> i32 {
    let worker: BnBinaryOpFn = unsafe { core::mem::transmute(0x0804_0ce0usize) };
    unsafe { worker(result, a, b) }
}

/// Host default: a missing worker must not look like allocation failure.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_uadd(
    _result: *mut BigNum,
    _a: *const BigNum,
    _b: *const BigNum,
) -> i32 {
    panic!("bn_add requires the BN_uadd worker 0x08040ce0")
}

/// Target default: `BN_usub` @ 0x08040e34, retained until it is ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_usub(
    result: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
) -> i32 {
    let worker: BnBinaryOpFn = unsafe { core::mem::transmute(0x0804_0e34usize) };
    unsafe { worker(result, a, b) }
}

/// Host default: a missing worker must not look like allocation failure.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_usub(
    _result: *mut BigNum,
    _a: *const BigNum,
    _b: *const BigNum,
) -> i32 {
    panic!("bn_add requires the BN_usub worker 0x08040e34")
}

/// Active `BN_uadd` worker. Host tests install a recorder.
#[cfg(target_os = "none")]
pub static mut BN_UADD: BnBinaryOpFn = firmware_bn_uadd;

/// Active `BN_uadd` worker. Host tests install a recorder.
#[cfg(not(target_os = "none"))]
pub static mut BN_UADD: BnBinaryOpFn = missing_bn_uadd;

/// Active `BN_usub` worker. Host tests install a recorder.
#[cfg(target_os = "none")]
pub static mut BN_USUB: BnBinaryOpFn = firmware_bn_usub;

/// Active `BN_usub` worker. Host tests install a recorder.
#[cfg(not(target_os = "none"))]
pub static mut BN_USUB: BnBinaryOpFn = missing_bn_usub;

#[inline(always)]
unsafe fn bn_uadd() -> BnBinaryOpFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_UADD)) }
}

#[inline(always)]
unsafe fn bn_usub() -> BnBinaryOpFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_USUB)) }
}

/// bn_add — original: `FUN_0803e144` @ 0x0803e144 (188 bytes; 7 call
/// sites, all unconditional `bl` — binary-verified).
///
/// OpenSSL `BN_add`: adds signed magnitudes through `BN_uadd` when the
/// input signs agree. Otherwise subtracts the smaller magnitude from
/// the larger through `BN_usub`; its sign follows that larger operand.
/// Every successful path normalizes `result->neg` to 0 or 1. No NULL
/// guards exist in the original.
///
/// # Safety
///
/// `result`, `a`, and `b` must name live [`BigNum`]s. Their limb
/// buffers and capacities must satisfy the selected unsigned worker's
/// requirements. [`BN_UADD`] and [`BN_USUB`] must be installed on host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_add(
    result: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
) -> i32 {
    let a_negative = unsafe { (*a).neg != 0 };
    let b_negative = unsafe { (*b).neg != 0 };

    if a_negative == b_negative {
        if unsafe { bn_uadd()(result, a, b) } == 0 {
            return 0;
        }
        unsafe { (*result).neg = i32::from(a_negative) };
        return 1;
    }

    let (positive, negative) = if a_negative { (b, a) } else { (a, b) };
    if unsafe { bn_ucmp(positive, negative) } >= 0 {
        if unsafe { bn_usub()(result, positive, negative) } == 0 {
            return 0;
        }
        unsafe { (*result).neg = 0 };
    } else {
        if unsafe { bn_usub()(result, negative, positive) } == 0 {
            return 0;
        }
        unsafe { (*result).neg = 1 };
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static WORKER_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(Operation, usize, usize)> = Vec::new();
    static mut SUCCEED: bool = true;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Operation {
        Add,
        Subtract,
    }

    unsafe fn record(operation: Operation, a: *const BigNum, b: *const BigNum) -> i32 {
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).push((operation, a as usize, b as usize));
            i32::from(*core::ptr::addr_of!(SUCCEED))
        }
    }

    unsafe extern "C" fn recording_uadd(
        _result: *mut BigNum,
        a: *const BigNum,
        b: *const BigNum,
    ) -> i32 {
        unsafe { record(Operation::Add, a, b) }
    }

    unsafe extern "C" fn recording_usub(
        _result: *mut BigNum,
        a: *const BigNum,
        b: *const BigNum,
    ) -> i32 {
        unsafe { record(Operation::Subtract, a, b) }
    }

    struct WorkerGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BN_UADD).write(missing_bn_uadd);
                core::ptr::addr_of_mut!(BN_USUB).write(missing_bn_usub);
                (*core::ptr::addr_of_mut!(CALLS)).clear();
            }
        }
    }

    fn install(succeed: bool) -> WorkerGuard {
        let guard = WORKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(SUCCEED).write(succeed);
            core::ptr::addr_of_mut!(BN_UADD).write(recording_uadd);
            core::ptr::addr_of_mut!(BN_USUB).write(recording_usub);
        }
        WorkerGuard(guard)
    }

    fn calls() -> Vec<(Operation, usize, usize)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    fn bignum(d: *const u32, top: i32, neg: i32) -> BigNum {
        BigNum { d, top, dmax: top, neg, flags: 0 }
    }

    #[test]
    fn equal_signs_use_unsigned_add_and_normalize_the_sign() {
        let _guard = install(true);
        let a_limbs = [2u32];
        let b_limbs = [3u32];
        let negative_a = bignum(a_limbs.as_ptr(), 1, -7);
        let negative_b = bignum(b_limbs.as_ptr(), 1, -7);
        let positive_a = bignum(a_limbs.as_ptr(), 1, 0);
        let positive_b = bignum(b_limbs.as_ptr(), 1, 0);
        let mut result = bignum(core::ptr::null(), 0, 99);

        assert_eq!(unsafe { bn_add(&mut result, &negative_a, &negative_b) }, 1);
        assert_eq!(result.neg, 1, "nonzero source signs normalize to one");
        assert_eq!(unsafe { bn_add(&mut result, &positive_a, &positive_b) }, 1);
        assert_eq!(result.neg, 0, "zero source signs normalize to zero");
        assert_eq!(calls(), std::vec![
            (Operation::Add, &negative_a as *const _ as usize, &negative_b as *const _ as usize),
            (Operation::Add, &positive_a as *const _ as usize, &positive_b as *const _ as usize),
        ]);
    }

    #[test]
    fn worker_failure_preserves_the_existing_result_sign() {
        let _guard = install(false);
        let limbs = [1u32];
        let a = bignum(limbs.as_ptr(), 1, 0);
        let b = bignum(limbs.as_ptr(), 1, 0);
        let mut result = bignum(core::ptr::null(), 0, -42);

        assert_eq!(unsafe { bn_add(&mut result, &a, &b) }, 0);
        assert_eq!(result.neg, -42, "the store follows a successful worker only");
        assert_eq!(calls(), std::vec![(Operation::Add, &a as *const _ as usize, &b as *const _ as usize)]);
    }

    #[test]
    fn different_signs_subtract_in_magnitude_order_and_keep_winner_sign() {
        let _guard = install(true);
        let large = [9u32];
        let small = [3u32];
        let mut result = bignum(core::ptr::null(), 0, 99);

        let positive_large_first = bignum(large.as_ptr(), 1, 0);
        let negative_small_first = bignum(small.as_ptr(), 1, 1);
        assert_eq!(unsafe { bn_add(&mut result, &positive_large_first, &negative_small_first) }, 1);
        assert_eq!(result.neg, 0);

        let positive_small_second = bignum(small.as_ptr(), 1, 0);
        let negative_large_second = bignum(large.as_ptr(), 1, 1);
        assert_eq!(unsafe { bn_add(&mut result, &positive_small_second, &negative_large_second) }, 1);
        assert_eq!(result.neg, 1);

        let negative_large_third = bignum(large.as_ptr(), 1, 1);
        let positive_small_third = bignum(small.as_ptr(), 1, 0);
        assert_eq!(unsafe { bn_add(&mut result, &negative_large_third, &positive_small_third) }, 1);
        assert_eq!(result.neg, 1);

        let negative_small_fourth = bignum(small.as_ptr(), 1, 1);
        let positive_large_fourth = bignum(large.as_ptr(), 1, 0);
        assert_eq!(unsafe { bn_add(&mut result, &negative_small_fourth, &positive_large_fourth) }, 1);
        assert_eq!(result.neg, 0);

        assert_eq!(calls(), std::vec![
            (Operation::Subtract, &positive_large_first as *const _ as usize, &negative_small_first as *const _ as usize),
            (Operation::Subtract, &negative_large_second as *const _ as usize, &positive_small_second as *const _ as usize),
            (Operation::Subtract, &negative_large_third as *const _ as usize, &positive_small_third as *const _ as usize),
            (Operation::Subtract, &positive_large_fourth as *const _ as usize, &negative_small_fourth as *const _ as usize),
        ]);
    }

    #[test]
    fn equal_magnitudes_with_different_signs_are_positive_zero() {
        let _guard = install(true);
        let limbs = [0xfeed_faceu32];
        let positive = bignum(limbs.as_ptr(), 1, 0);
        let negative = bignum(limbs.as_ptr(), 1, 1);
        let mut result = bignum(core::ptr::null(), 0, -11);

        assert_eq!(unsafe { bn_add(&mut result, &positive, &negative) }, 1);
        assert_eq!(result.neg, 0);
        assert_eq!(unsafe { bn_add(&mut result, &negative, &positive) }, 1);
        assert_eq!(result.neg, 0);
        assert_eq!(calls(), std::vec![
            (Operation::Subtract, &positive as *const _ as usize, &negative as *const _ as usize),
            (Operation::Subtract, &positive as *const _ as usize, &negative as *const _ as usize),
        ]);
    }
}
