//! OpenSSL's `BN_mod_mul` — multiply or square then non-negative reduction.
//!
//! Port: `bn_mod_mul` — `FUN_0803ff80` @ 0x0803ff80 (152 bytes,
//! 0x0803ff80..0x08040018; 5 plain `bl` instructions and no predicated
//! calls, verified from raw `osos.dec` words). Ghidra's reported four BL call
//! sites omits the unconditional cleanup call at 0x0804000c.
//!
//! # Algorithm
//!
//! Push a [`TaggedWordBufferPool`] nesting level and take one temporary
//! [`BigNum`]. Pointer-identical operands use `BN_sqr`; other operands use
//! `BN_mul`. A successful product is non-negatively reduced modulo `modulus`
//! through [`BN_NNMOD`]. Pop the nesting level on every path and return one
//! only when both workers succeed. The original has no NULL guards.
//!
//! Deliberate deviation: unported `BN_sqr` @ 0x08040884, `BN_mul` @
//! 0x080400b0, and `BN_nnmod` @ 0x08040438 use volatile dispatch slots;
//! target defaults call retailOS.

use super::bn_mod_mul_montgomery::{BnMulFn, BnSqrFn, BN_MUL, BN_SQR};
use super::bn_num_bits::BigNum;
use crate::heap::tagged_word_buffer_pool::{
    tagged_word_buffer_pool_pop, tagged_word_buffer_pool_push, tagged_word_buffer_pool_take,
    TaggedWordBufferPool,
};

/// `BN_nnmod(result, numerator, modulus, ctx)` worker signature.
pub type BnNnmodFn = unsafe extern "C" fn(
    result: *mut BigNum,
    numerator: *const BigNum,
    modulus: *const BigNum,
    ctx: *mut TaggedWordBufferPool,
) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_nnmod(result: *mut BigNum, numerator: *const BigNum, modulus: *const BigNum, ctx: *mut TaggedWordBufferPool) -> i32 {
    let worker: BnNnmodFn = unsafe { core::mem::transmute(0x0804_0438usize) };
    unsafe { worker(result, numerator, modulus, ctx) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_nnmod(_result: *mut BigNum, _numerator: *const BigNum, _modulus: *const BigNum, _ctx: *mut TaggedWordBufferPool) -> i32 {
    panic!("bn_mod_mul requires the BN_nnmod worker 0x08040438")
}

#[cfg(target_os = "none")]
pub static mut BN_NNMOD: BnNnmodFn = firmware_bn_nnmod;
#[cfg(not(target_os = "none"))]
pub static mut BN_NNMOD: BnNnmodFn = missing_bn_nnmod;

#[inline(always)]
unsafe fn bn_sqr() -> BnSqrFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_SQR)) }
}

#[inline(always)]
unsafe fn bn_mul() -> BnMulFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_MUL)) }
}

#[inline(always)]
unsafe fn bn_nnmod() -> BnNnmodFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_NNMOD)) }
}

/// bn_mod_mul — original: `FUN_0803ff80` @ 0x0803ff80 (152 bytes; five plain
/// `bl` instructions, no predicated calls — binary-verified).
///
/// OpenSSL `BN_mod_mul`: allocate one temporary BIGNUM in `ctx`, select square
/// only for pointer-identical operands and multiply otherwise, then
/// non-negatively reduce the successful product modulo `modulus`. The pool
/// push/pop pair is unconditional around allocation and worker calls.
///
/// # Safety
///
/// `result`, `a`, `b`, `modulus`, and `ctx` must be live firmware objects
/// expected by the forwarded workers. `ctx` must be a valid
/// [`TaggedWordBufferPool`]; no input receives a NULL guard in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_mod_mul(result: *mut BigNum, a: *const BigNum, b: *const BigNum, modulus: *const BigNum, ctx: *mut TaggedWordBufferPool) -> i32 {
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
            if product_succeeded != 0 && bn_nnmod()(result, temporary, modulus, ctx) != 0 {
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
    use crate::crypto::bn_mod_mul_montgomery::BN_WORKER_LOCK;
    use crate::heap::tagged_word_buffer_pool::TAGGED_WORD_BUFFER_POOL_CAPACITY;
    use parking_lot::MutexGuard;
    use std::vec::Vec;

    static mut CALLS: Vec<&'static str> = Vec::new();
    static mut PRODUCT_SUCCEEDS: bool = true;
    static mut REDUCTION_SUCCEEDS: bool = true;

    unsafe extern "C" fn recording_square(result: *mut BigNum, _a: *const BigNum, _ctx: *mut TaggedWordBufferPool) -> i32 {
        unsafe { CALLS.push("square") };
        assert!(!result.is_null());
        unsafe { i32::from(PRODUCT_SUCCEEDS) }
    }

    unsafe extern "C" fn recording_multiply(result: *mut BigNum, _a: *const BigNum, _b: *const BigNum, _ctx: *mut TaggedWordBufferPool) -> i32 {
        unsafe { CALLS.push("multiply") };
        assert!(!result.is_null());
        unsafe { i32::from(PRODUCT_SUCCEEDS) }
    }

    unsafe extern "C" fn recording_reduce(_result: *mut BigNum, temporary: *const BigNum, _modulus: *const BigNum, _ctx: *mut TaggedWordBufferPool) -> i32 {
        unsafe { CALLS.push("reduce") };
        assert!(!temporary.is_null());
        unsafe { i32::from(REDUCTION_SUCCEEDS) }
    }

    struct Restore {
        square: BnSqrFn,
        multiply: BnMulFn,
        reduce: BnNnmodFn,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                BN_SQR = self.square;
                BN_MUL = self.multiply;
                BN_NNMOD = self.reduce;
            }
        }
    }

    fn install() -> Restore {
        let lock = BN_WORKER_LOCK.lock();
        unsafe {
            let square = BN_SQR;
            let multiply = BN_MUL;
            let reduce = BN_NNMOD;
            BN_SQR = recording_square;
            BN_MUL = recording_multiply;
            BN_NNMOD = recording_reduce;
            CALLS = Vec::new();
            PRODUCT_SUCCEEDS = true;
            REDUCTION_SUCCEEDS = true;
            Restore { square, multiply, reduce, _lock: lock }
        }
    }

    fn bignum() -> BigNum {
        BigNum { d: core::ptr::null(), top: 0, dmax: 0, neg: 0, flags: 0 }
    }

    fn pool(slot_count: u32) -> TaggedWordBufferPool {
        TaggedWordBufferPool {
            slot_count,
            slots: core::array::from_fn(|_| crate::heap::tagged_word_buffer::TaggedWordBuffer { data: 0, len: 0, capacity: 0, tag: 0, flags: 0 }),
            flags: 0,
            nesting_depth: 0,
            saved_slot_counts: [0; 12],
            overflow_reported: 0,
        }
    }

    #[test]
    fn identical_operands_square_then_reduce_and_restore_pool() {
        let _restore = install();
        let mut ctx = pool(7);
        let mut result = bignum();
        let a = bignum();

        assert_eq!(unsafe { bn_mod_mul(&mut result, &a, &a, core::ptr::null(), &mut ctx) }, 1);
        assert_eq!(unsafe { &*core::ptr::addr_of!(CALLS) }, &["square", "reduce"]);
        assert_eq!((ctx.nesting_depth, ctx.slot_count), (0, 7));
    }

    #[test]
    fn distinct_operands_multiply_then_reduce() {
        let _restore = install();
        let mut ctx = pool(3);
        let mut result = bignum();
        let a = bignum();
        let b = bignum();

        assert_eq!(unsafe { bn_mod_mul(&mut result, &a, &b, core::ptr::null(), &mut ctx) }, 1);
        assert_eq!(unsafe { &*core::ptr::addr_of!(CALLS) }, &["multiply", "reduce"]);
        assert_eq!((ctx.nesting_depth, ctx.slot_count), (0, 3));
    }

    #[test]
    fn product_failure_skips_reduction_and_restores_pool() {
        let _restore = install();
        unsafe { PRODUCT_SUCCEEDS = false };
        let mut ctx = pool(2);
        let mut result = bignum();
        let a = bignum();

        assert_eq!(unsafe { bn_mod_mul(&mut result, &a, &a, core::ptr::null(), &mut ctx) }, 0);
        assert_eq!(unsafe { &*core::ptr::addr_of!(CALLS) }, &["square"]);
        assert_eq!((ctx.nesting_depth, ctx.slot_count), (0, 2));
    }

    #[test]
    fn exhausted_pool_skips_workers_and_restores_pool() {
        let _restore = install();
        let mut ctx = pool(TAGGED_WORD_BUFFER_POOL_CAPACITY as u32);
        let mut result = bignum();
        let a = bignum();

        assert_eq!(unsafe { bn_mod_mul(&mut result, &a, &a, core::ptr::null(), &mut ctx) }, 0);
        assert!(unsafe { (&*core::ptr::addr_of!(CALLS)).is_empty() });
        assert_eq!((ctx.nesting_depth, ctx.slot_count), (0, TAGGED_WORD_BUFFER_POOL_CAPACITY as u32));
    }
}
