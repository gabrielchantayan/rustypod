//! RSA blinding inversion: `FUN_0803dbd8` @ 0x0803dbd8.
//! True extent 0x0803dbd8..0x0803dc50 (120 bytes), ending at the next
//! independent factory prologue. Raw words verify three outbound plain BL
//! instructions, no predicated BL, and two inbound plain BL callers.
//!
//! Multiply the result in place by the inverse factor modulo the owner's
//! modulus, then update both factors by modular squaring. Missing factors
//! record diagnostic (3, 0x65, 0x6b, 0, 0) and return zero. Preserve the
//! signed negative-result short circuit: zero still attempts the update.
//! Deliberate deviation: the unported factor-update worker at 0x0803dd00
//! uses a volatile dispatch slot, whose target default calls retailOS.
//! LLVM removes the negative-result branch in the ARM wrapper because the
//! existing `bn_mod_mul` port returns only 0 or 1. The source retains the
//! retail signed rule; host tests exercise it independently.

use super::bn_mod_mul::bn_mod_mul;
use super::bn_num_bits::BigNum;
use crate::heap::tagged_word_buffer_pool::TaggedWordBufferPool;
use crate::heap::two_buffer_owner::TwoBufferOwner;
use crate::kernel::diag_ring_record::diag_ring_record;

/// BN_BLINDING_update: square first and second factors modulo trailing[0].
pub type BlindingUpdateFn = unsafe extern "C" fn(*mut TwoBufferOwner, *mut TaggedWordBufferPool) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_blinding_update(owner: *mut TwoBufferOwner, ctx: *mut TaggedWordBufferPool) -> i32 {
    let worker: BlindingUpdateFn = unsafe { core::mem::transmute(0x0803_dd00usize) };
    unsafe { worker(owner, ctx) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_blinding_update(_owner: *mut TwoBufferOwner, _ctx: *mut TaggedWordBufferPool) -> i32 {
    panic!("bn_blinding_invert requires BN_BLINDING_update at 0x0803dd00")
}

#[cfg(target_os = "none")]
pub static mut BLINDING_UPDATE: BlindingUpdateFn = firmware_blinding_update;
#[cfg(not(target_os = "none"))]
pub static mut BLINDING_UPDATE: BlindingUpdateFn = missing_blinding_update;

#[inline(always)]
fn invert_with(has_factors: bool, multiply: impl FnOnce() -> i32, update: impl FnOnce() -> i32, diagnose: impl FnOnce()) -> i32 {
    if !has_factors {
        diagnose();
        return 0;
    }
    let result = multiply();
    if result < 0 || update() != 0 { result } else { 0 }
}

/// Unblind `value`, then advance the factors (120 bytes; three plain BL).
///
/// # Safety
/// `owner` must be readable and aligned, not NULL. Its nonzero factor words
/// and modulus word must address live BIGNUMs; `value` and `ctx` must meet
/// `bn_mod_mul` and the stock update worker's contracts. No owner NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_blinding_invert(value: *mut BigNum, owner: *mut TwoBufferOwner, ctx: *mut TaggedWordBufferPool) -> i32 {
    let first = unsafe { core::ptr::addr_of!((*owner).first).read() };
    let second = if first != 0 { unsafe { core::ptr::addr_of!((*owner).second).read() } } else { 0 };
    invert_with(first != 0 && second != 0,
        || unsafe {
            let modulus = core::ptr::addr_of!((*owner).trailing[0]).read();
            bn_mod_mul(value, value, second as *const BigNum, modulus as *const BigNum, ctx)
        },
        || unsafe {
            let update = core::ptr::read_volatile(core::ptr::addr_of!(BLINDING_UPDATE));
            update(owner, ctx)
        },
        || unsafe { diag_ring_record(3, 0x65, 0x6b, 0, 0) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn unblinds_and_advances_factors_after_multiplication() {
        let value = Cell::new(8);
        let inverse = Cell::new(7);
        let forward = Cell::new(5);
        let result = invert_with(true,
            || { value.set(value.get() * inverse.get() % 11); 1 },
            || {
                assert_eq!(value.get(), 1);
                inverse.set(inverse.get() * inverse.get() % 11);
                forward.set(forward.get() * forward.get() % 11);
                1
            }, || panic!("unexpected diagnostic"));
        assert_eq!((result, value.get(), forward.get(), inverse.get()), (1, 1, 3, 5));
    }

    #[test]
    fn missing_factors_diagnose_without_mutating_value() {
        let diagnosed = Cell::new(false);
        assert_eq!(invert_with(false, || panic!("multiply"), || panic!("update"), || diagnosed.set(true)), 0);
        assert!(diagnosed.get());
    }

    #[test]
    fn negative_result_preserves_error_and_skips_update() {
        for error in [-1, i32::MIN] {
            assert_eq!(invert_with(true, || error, || panic!("update"), || panic!("diagnostic")), error);
        }
    }

    #[test]
    fn zero_product_still_advances_and_failed_update_does_not_undo_product() {
        for product_status in [0, 1, i32::MAX] {
            for update_status in [0, 1, -1] {
                let value = Cell::new(8);
                let advanced = Cell::new(false);
                let result = invert_with(true,
                    || { value.set(1); product_status },
                    || { advanced.set(true); update_status },
                    || panic!("diagnostic"));
                assert_eq!(result, if update_status == 0 { 0 } else { product_status });
                assert_eq!(value.get(), 1);
                assert!(advanced.get());
            }
        }
    }
}
