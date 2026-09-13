//! OpenSSL's `BN_mod_mul_montgomery` — Montgomery-domain multiply/reduce.
//!
//! Port: `bn_mod_mul_montgomery` — `FUN_08040018` @ 0x08040018 (152 bytes,
//! 0x08040018..0x080400b0; **7 direct call sites**, binary-verified by
//! decoding every ARM B/BL word in osos.dec: all seven are unconditional
//! `bl`, with no predicated forms).
//!
//! # Algorithm
//!
//! Borrow one temporary [`BigNum`] from the supplied BN_CTX-compatible word
//! buffer pool. When both operands are the same object, square it through
//! `BN_sqr`; otherwise multiply them through `BN_mul`. On successful product,
//! reduce that temporary through `BN_from_montgomery` into `result`. Every
//! path releases the temporary-pool nesting and returns one only if both
//! workers succeed. The original has no NULL guards.
//!
//! `BN_sqr` @ 0x08040884, `BN_mul` @ 0x080400b0, and
//! `BN_from_montgomery` @ 0x0803ef28 are not ported, so their calls use
//! volatile dispatch slots. Target defaults call their retailOS addresses;
//! host tests install recording workers. This is the only deliberate
//! deviation.

use super::bn_num_bits::BigNum;
use crate::heap::tagged_word_buffer_pool::{
    tagged_word_buffer_pool_pop, tagged_word_buffer_pool_push, tagged_word_buffer_pool_take,
    TaggedWordBufferPool,
};

/// Opaque OpenSSL `BN_MONT_CTX`; this wrapper only forwards its pointer.
#[repr(C)]
pub struct MontgomeryContext {
    _private: [u8; 0],
}

/// `BN_sqr(result, a, ctx)` worker signature.
pub type BnSqrFn = unsafe extern "C" fn(
    result: *mut BigNum,
    a: *const BigNum,
    ctx: *mut TaggedWordBufferPool,
) -> i32;

/// `BN_mul(result, a, b, ctx)` worker signature.
pub type BnMulFn = unsafe extern "C" fn(
    result: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut TaggedWordBufferPool,
) -> i32;

/// `BN_from_montgomery(result, a, mont, ctx)` worker signature.
pub type BnFromMontgomeryFn = unsafe extern "C" fn(
    result: *mut BigNum,
    a: *const BigNum,
    mont: *const MontgomeryContext,
    ctx: *mut TaggedWordBufferPool,
) -> i32;

/// Target default: `BN_sqr` @ 0x08040884, retained until it is ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_sqr(
    result: *mut BigNum,
    a: *const BigNum,
    ctx: *mut TaggedWordBufferPool,
) -> i32 {
    let worker: BnSqrFn = unsafe { core::mem::transmute(0x0804_0884usize) };
    unsafe { worker(result, a, ctx) }
}

/// Host default: a missing worker must not look like multiplication failure.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_sqr(
    _result: *mut BigNum,
    _a: *const BigNum,
    _ctx: *mut TaggedWordBufferPool,
) -> i32 {
    panic!("bn_mod_mul_montgomery requires the BN_sqr worker 0x08040884")
}

/// Target default: `BN_mul` @ 0x080400b0, retained until it is ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_mul(
    result: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut TaggedWordBufferPool,
) -> i32 {
    let worker: BnMulFn = unsafe { core::mem::transmute(0x0804_00b0usize) };
    unsafe { worker(result, a, b, ctx) }
}

/// Host default: a missing worker must not look like multiplication failure.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_mul(
    _result: *mut BigNum,
    _a: *const BigNum,
    _b: *const BigNum,
    _ctx: *mut TaggedWordBufferPool,
) -> i32 {
    panic!("bn_mod_mul_montgomery requires the BN_mul worker 0x080400b0")
}

/// Target default: `BN_from_montgomery` @ 0x0803ef28, retained until ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_from_montgomery(
    result: *mut BigNum,
    a: *const BigNum,
    mont: *const MontgomeryContext,
    ctx: *mut TaggedWordBufferPool,
) -> i32 {
    let worker: BnFromMontgomeryFn = unsafe { core::mem::transmute(0x0803_ef28usize) };
    unsafe { worker(result, a, mont, ctx) }
}

/// Host default: a missing worker must not look like reduction failure.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_from_montgomery(
    _result: *mut BigNum,
    _a: *const BigNum,
    _mont: *const MontgomeryContext,
    _ctx: *mut TaggedWordBufferPool,
) -> i32 {
    panic!("bn_mod_mul_montgomery requires the BN_from_montgomery worker 0x0803ef28")
}

/// Active `BN_sqr` worker. Host tests install a recorder.
#[cfg(target_os = "none")]
pub static mut BN_SQR: BnSqrFn = firmware_bn_sqr;
/// Active `BN_sqr` worker. Host tests install a recorder.
#[cfg(not(target_os = "none"))]
pub static mut BN_SQR: BnSqrFn = missing_bn_sqr;

/// Active `BN_mul` worker. Host tests install a recorder.
#[cfg(target_os = "none")]
pub static mut BN_MUL: BnMulFn = firmware_bn_mul;
/// Active `BN_mul` worker. Host tests install a recorder.
#[cfg(not(target_os = "none"))]
pub static mut BN_MUL: BnMulFn = missing_bn_mul;

/// Active `BN_from_montgomery` worker. Host tests install a recorder.
#[cfg(target_os = "none")]
pub static mut BN_FROM_MONTGOMERY: BnFromMontgomeryFn = firmware_bn_from_montgomery;
/// Active `BN_from_montgomery` worker. Host tests install a recorder.
#[cfg(not(target_os = "none"))]
pub static mut BN_FROM_MONTGOMERY: BnFromMontgomeryFn = missing_bn_from_montgomery;

#[inline(always)]
unsafe fn bn_sqr() -> BnSqrFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_SQR)) }
}

#[inline(always)]
unsafe fn bn_mul() -> BnMulFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_MUL)) }
}

#[inline(always)]
unsafe fn bn_from_montgomery() -> BnFromMontgomeryFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_FROM_MONTGOMERY)) }
}

/// bn_mod_mul_montgomery — original: `FUN_08040018` @ 0x08040018 (152 bytes;
/// 7 direct call sites, all unconditional `bl` — binary-verified).
///
/// OpenSSL `BN_mod_mul_montgomery`: allocate one temporary BIGNUM in `ctx`,
/// select `BN_sqr` only for pointer-identical operands and `BN_mul` otherwise,
/// then convert the successful product out of the Montgomery domain. The pool
/// push/pop pair is unconditional around the allocation and worker calls.
///
/// # Safety
///
/// `result`, `a`, `b`, `mont`, and `ctx` must be the live firmware objects
/// expected by the forwarded workers. `ctx` must be a valid
/// [`TaggedWordBufferPool`]; no input receives a NULL guard in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_mod_mul_montgomery(
    result: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    mont: *const MontgomeryContext,
    ctx: *mut TaggedWordBufferPool,
) -> i32 {
    unsafe {
        tagged_word_buffer_pool_push(ctx);
        let temporary = tagged_word_buffer_pool_take(ctx).cast::<BigNum>();
        let mut succeeded = 0;

        if !temporary.is_null() {
            let product_succeeded = if core::ptr::eq(a, b) {
                bn_sqr()(temporary, a, ctx)
            } else {
                bn_mul()(temporary, a, b, ctx)
            };

            if product_succeeded != 0 && bn_from_montgomery()(result, temporary, mont, ctx) != 0 {
                succeeded = 1;
            }
        }

        tagged_word_buffer_pool_pop(ctx);
        succeeded
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::tagged_word_buffer_pool::TAGGED_WORD_BUFFER_POOL_CAPACITY;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static WORKER_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<Call> = Vec::new();
    static mut PRODUCT_SUCCEEDS: bool = true;
    static mut REDUCTION_SUCCEEDS: bool = true;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Square { temporary: usize, a: usize, ctx: usize },
        Multiply { temporary: usize, a: usize, b: usize, ctx: usize },
        Reduce { result: usize, temporary: usize, mont: usize, ctx: usize },
    }

    unsafe extern "C" fn recording_square(
        temporary: *mut BigNum,
        a: *const BigNum,
        ctx: *mut TaggedWordBufferPool,
    ) -> i32 {
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).push(Call::Square {
                temporary: temporary as usize,
                a: a as usize,
                ctx: ctx as usize,
            });
            i32::from(*core::ptr::addr_of!(PRODUCT_SUCCEEDS))
        }
    }

    unsafe extern "C" fn recording_multiply(
        temporary: *mut BigNum,
        a: *const BigNum,
        b: *const BigNum,
        ctx: *mut TaggedWordBufferPool,
    ) -> i32 {
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).push(Call::Multiply {
                temporary: temporary as usize,
                a: a as usize,
                b: b as usize,
                ctx: ctx as usize,
            });
            i32::from(*core::ptr::addr_of!(PRODUCT_SUCCEEDS))
        }
    }

    unsafe extern "C" fn recording_reduce(
        result: *mut BigNum,
        temporary: *const BigNum,
        mont: *const MontgomeryContext,
        ctx: *mut TaggedWordBufferPool,
    ) -> i32 {
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).push(Call::Reduce {
                result: result as usize,
                temporary: temporary as usize,
                mont: mont as usize,
                ctx: ctx as usize,
            });
            i32::from(*core::ptr::addr_of!(REDUCTION_SUCCEEDS))
        }
    }

    struct WorkerGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BN_SQR).write(missing_bn_sqr);
                core::ptr::addr_of_mut!(BN_MUL).write(missing_bn_mul);
                core::ptr::addr_of_mut!(BN_FROM_MONTGOMERY).write(missing_bn_from_montgomery);
                (*core::ptr::addr_of_mut!(CALLS)).clear();
            }
        }
    }

    fn install(product_succeeds: bool, reduction_succeeds: bool) -> WorkerGuard {
        let guard = WORKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(PRODUCT_SUCCEEDS).write(product_succeeds);
            core::ptr::addr_of_mut!(REDUCTION_SUCCEEDS).write(reduction_succeeds);
            core::ptr::addr_of_mut!(BN_SQR).write(recording_square);
            core::ptr::addr_of_mut!(BN_MUL).write(recording_multiply);
            core::ptr::addr_of_mut!(BN_FROM_MONTGOMERY).write(recording_reduce);
        }
        WorkerGuard(guard)
    }

    fn calls() -> Vec<Call> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    fn bignum() -> BigNum {
        BigNum { d: core::ptr::null(), top: 0, dmax: 0, neg: 0, flags: 0 }
    }

    fn pool() -> TaggedWordBufferPool {
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn identical_operands_square_then_reduce_through_the_first_pool_slot() {
        let _guard = install(true, true);
        let mut ctx = pool();
        let mut result = bignum();
        let a = bignum();
        let mont = core::ptr::null();
        let temporary = core::ptr::addr_of_mut!(ctx.slots[0]) as usize;

        assert_eq!(unsafe { bn_mod_mul_montgomery(&mut result, &a, &a, mont, &mut ctx) }, 1);
        assert_eq!(calls(), std::vec![
            Call::Square { temporary, a: &a as *const _ as usize, ctx: &mut ctx as *mut _ as usize },
            Call::Reduce {
                result: &mut result as *mut _ as usize,
                temporary,
                mont: mont as usize,
                ctx: &mut ctx as *mut _ as usize,
            },
        ]);
        assert_eq!(ctx.nesting_depth, 0);
        assert_eq!(ctx.slot_count, 0);
    }

    #[test]
    fn distinct_operands_multiply_then_propagate_reduction_failure() {
        let _guard = install(true, false);
        let mut ctx = pool();
        let mut result = bignum();
        let a = bignum();
        let b = bignum();
        let mont = core::ptr::null();
        let temporary = core::ptr::addr_of_mut!(ctx.slots[0]) as usize;

        assert_eq!(unsafe { bn_mod_mul_montgomery(&mut result, &a, &b, mont, &mut ctx) }, 0);
        assert_eq!(calls(), std::vec![
            Call::Multiply {
                temporary,
                a: &a as *const _ as usize,
                b: &b as *const _ as usize,
                ctx: &mut ctx as *mut _ as usize,
            },
            Call::Reduce {
                result: &mut result as *mut _ as usize,
                temporary,
                mont: mont as usize,
                ctx: &mut ctx as *mut _ as usize,
            },
        ]);
        assert_eq!(ctx.nesting_depth, 0);
        assert_eq!(ctx.slot_count, 0);
    }

    #[test]
    fn product_failure_skips_reduction_and_restores_the_pool() {
        let _guard = install(false, true);
        let mut ctx = pool();
        let mut result = bignum();
        let a = bignum();
        let b = bignum();
        let mont = core::ptr::null();
        let temporary = core::ptr::addr_of_mut!(ctx.slots[0]) as usize;

        assert_eq!(unsafe { bn_mod_mul_montgomery(&mut result, &a, &b, mont, &mut ctx) }, 0);
        assert_eq!(calls(), std::vec![Call::Multiply {
            temporary,
            a: &a as *const _ as usize,
            b: &b as *const _ as usize,
            ctx: &mut ctx as *mut _ as usize,
        }]);
        assert_eq!(ctx.nesting_depth, 0);
        assert_eq!(ctx.slot_count, 0);
    }

    #[test]
    fn exhausted_pool_calls_no_worker_and_preserves_its_cursor() {
        let _guard = install(true, true);
        let mut ctx = pool();
        ctx.slot_count = TAGGED_WORD_BUFFER_POOL_CAPACITY as u32;
        let mut result = bignum();
        let a = bignum();
        let b = bignum();

        assert_eq!(
            unsafe { bn_mod_mul_montgomery(&mut result, &a, &b, core::ptr::null(), &mut ctx) },
            0,
        );
        assert!(calls().is_empty());
        assert_eq!(ctx.nesting_depth, 0);
        assert_eq!(ctx.slot_count, TAGGED_WORD_BUFFER_POOL_CAPACITY as u32);
    }
}
