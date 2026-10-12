//! BN_BLINDING_convert — FUN_0803db58 @ 0x0803db58.
//! Raw extent 0x0803db58..0x0803dba8: 80 bytes, two plain outbound BL,
//! zero predicated BL; two plain inbound BL, zero predicated callers.
//! Require both factors, then multiply value in place by the first factor
//! modulo trailing[0]. Missing factors diagnose (3,100,107,0,0) and return
//! zero without accessing value or ctx. Factors are not advanced here.
//! No deliberate behavioral deviations; reuse the existing bn_mod_mul and
//! diagnostic ports, including their documented worker dispatch seams.

use super::bn_mod_mul::bn_mod_mul;
use super::bn_num_bits::BigNum;
use crate::heap::tagged_word_buffer_pool::TaggedWordBufferPool;
use crate::heap::two_buffer_owner::TwoBufferOwner;
use crate::kernel::diag_ring_record::diag_ring_record;

/// Apply the forward RSA blinding factor in place.
///
/// # Safety
/// `owner` must be non-NULL, readable and aligned. With both factors present,
/// its first and modulus words, `value`, and `ctx` must satisfy bn_mod_mul's
/// contract. The second factor is only tested for presence, not dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_blinding_convert(value: *mut BigNum, owner: *const TwoBufferOwner, ctx: *mut TaggedWordBufferPool) -> i32 {
    let first = unsafe { core::ptr::addr_of!((*owner).first).read() };
    let second = if first != 0 { unsafe { core::ptr::addr_of!((*owner).second).read() } } else { 0 };
    if first == 0 || second == 0 {
        unsafe { diag_ring_record(3, 100, 107, 0, 0) };
        return 0;
    }
    let modulus = unsafe { core::ptr::addr_of!((*owner).trailing[0]).read() };
    unsafe { bn_mod_mul(value, value, first as *const BigNum, modulus as *const BigNum, ctx) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::crypto::bn_mod_mul::{BnNnmodFn, BN_NNMOD};
    use crate::crypto::bn_mod_mul_montgomery::{BnMulFn, BN_MUL, BN_WORKER_LOCK};
    use crate::kernel::diag_ring_record::{DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture, DIAG_RING_TEST_LOCK};
    use core::cell::Cell;

    std::thread_local! {
        static RING: Cell<*mut DiagEventRing> = const { Cell::new(core::ptr::null_mut()) };
    }
    unsafe extern "C" fn ring_getter() -> *mut DiagEventRing { RING.with(|r| r.get()) }

    #[test]
    fn missing_either_factor_reports_error_without_accessing_value_or_context() {
        let _lock = DIAG_RING_TEST_LOCK.lock().unwrap();
        let mut ring: DiagEventRing = unsafe { core::mem::zeroed() };
        RING.with(|r| r.set(&mut ring));
        let saved = unsafe { DIAG_RING_BLOCK_GETTER };
        unsafe { DIAG_RING_BLOCK_GETTER = Some(ring_getter) };
        for (first, second) in [(0, 0), (0, u32::MAX), (u32::MAX, 0)] {
            let owner = TwoBufferOwner { reserved: 0, first, second, trailing: [u32::MAX; 2] };
            assert_eq!(unsafe { bn_blinding_convert(core::ptr::null_mut(), &owner, core::ptr::null_mut()) }, 0);
            assert_eq!(ring.tags[ring.head as usize], 0x0306_406b);
            assert_eq!((ring.data0[ring.head as usize], ring.data1[ring.head as usize]), (0, 0));
        }
        unsafe { DIAG_RING_BLOCK_GETTER = saved };
        RING.with(|r| r.set(core::ptr::null_mut()));
    }

    // Small nonnegative BIGNUM workers: top carries the fixture's integer.
    // Exercise the actual wrapper, temporary pool, and modular reduction.
    unsafe extern "C" fn multiply(out: *mut BigNum, a: *const BigNum, b: *const BigNum, _ctx: *mut TaggedWordBufferPool) -> i32 {
        unsafe { core::ptr::addr_of_mut!((*out).top).write_unaligned((*a).top * (*b).top) };
        1
    }
    unsafe extern "C" fn reduce(out: *mut BigNum, a: *const BigNum, modulus: *const BigNum, _ctx: *mut TaggedWordBufferPool) -> i32 {
        let modulus = unsafe { (*modulus).top };
        if modulus == 0 { return 0; }
        unsafe { (*out).top = core::ptr::addr_of!((*a).top).read_unaligned() % modulus };
        1
    }
    struct Restore(BnMulFn, BnNnmodFn);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { BN_MUL = self.0; BN_NNMOD = self.1; } }
    }

    #[test]
    fn converts_in_place_without_advancing_factors_and_preserves_value_on_failure() {
        let _lock = BN_WORKER_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::BN_BLINDING_CONVERT, 4096) else {
            note_missing_u32_fixture("bn_blinding_convert"); return;
        };
        let first = slab.cast::<BigNum>();
        let modulus = unsafe { first.add(1) };
        let _restore = unsafe { Restore(BN_MUL, BN_NNMOD) };
        unsafe { BN_MUL = multiply; BN_NNMOD = reduce; }
        let owner = TwoBufferOwner { reserved: 0, first: first as u32, second: u32::MAX,
            trailing: [modulus as u32, 0] };
        let mut ctx = TaggedWordBufferPool {
            slot_count: 0,
            slots: core::array::from_fn(|_| crate::heap::tagged_word_buffer::TaggedWordBuffer { data: 0, len: 0, capacity: 0, tag: 0, flags: 0 }),
            flags: 0, nesting_depth: 0, saved_slot_counts: [0; 12], overflow_reported: 0,
        };
        for (input, factor, divisor) in [(8, 5, 11), (0, 5, 11), (8, 0, 11), (8, 5, 1), (8, 5, 0)] {
            let make = |top| BigNum { d: core::ptr::null(), top, dmax: 0, neg: 0, flags: 0 };
            unsafe { first.write(make(factor)); modulus.write(make(divisor)); }
            let mut value = make(input);
            let result = unsafe { bn_blinding_convert(&mut value, &owner, &mut ctx) };
            assert_eq!(result, i32::from(divisor != 0));
            assert_eq!(value.top, if divisor == 0 { input } else { input * factor % divisor });
            assert_eq!(unsafe { (*first).top }, factor);
            assert_eq!((owner.second, owner.trailing[0]), (u32::MAX, modulus as u32));
            assert_eq!((ctx.slot_count, ctx.nesting_depth), (0, 0));
        }
    }
}
