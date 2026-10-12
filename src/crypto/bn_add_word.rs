//! OpenSSL `BN_add_word` — load address 0x0803e200, 220 bytes
//! (0x0803e200..0x0803e2dc; next entry has an independent PUSH prologue).
//! Binary-wide raw A32 decoding verifies two incoming plain BLs at
//! 0x0803e8d8 and 0x08040b74, zero predicated BLs; two outgoing plain BLs
//! reach BN_sub_word at 0x08040b30 and the capacity worker at 0x082b8174.
//!
//! For negative inputs clear neg, subtract the word, then invert a zero/one
//! sign only if the resulting magnitude is nonzero. Otherwise reserve top+1
//! limbs before any write, propagate unsigned carry, and extend top only
//! when writing beyond its former end. Even adding zero to top=0 writes a
//! zero limb and sets top=1. Failure retains the stock sign side effects.
//! Deliberate deviations: existing native-pointer repr(C) BigNum on hosts;
//! shared volatile capacity slot instead of direct BL. The already ported
//! subtraction worker is called directly. No normalization or shortcuts.

use super::bn_num_bits::BigNum;
use super::bn_sub_word::bn_sub_word;
use super::bn_lshift1::BN_EXPAND_WORDS;
use core::ptr;

/// Add an unsigned word to a signed magnitude; return one on success.
///
/// # Safety
/// `a` must be a live BigNum with writable, aligned limbs. Its magnitude
/// must satisfy BN_sub_word's normalization requirements on negative paths.
/// The capacity worker must preserve old limbs and provide top+1 writable
/// limbs on success, or return NULL without storage changes on failure.
/// Hosts must install that worker before any expansion path is exercised.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_add_word(a: *mut BigNum, mut word: u32) -> i32 {
    unsafe {
        if (*a).neg != 0 {
            (*a).neg = 0;
            let result = bn_sub_word(a, word);
            if (*a).top != 0 && !((*a).top == 1 && *(*a).d == 0) {
                let sign = (*a).neg as u32;
                (*a).neg = if sign <= 1 { 1 - sign as i32 } else { 0 };
            }
            return result;
        }
        let words = (*a).top.wrapping_add(1);
        if words > (*a).dmax {
            let expand = ptr::read_volatile(ptr::addr_of!(BN_EXPAND_WORDS));
            if expand(a, words).is_null() { return 0; }
        }
        let mut index = 0i32;
        loop {
            let sum = if index < (*a).top {
                (*(*a).d.add(index as usize)).wrapping_add(word)
            } else { word };
            *((*a).d as *mut u32).add(index as usize) = sum;
            if sum >= word { break; }
            word = 1;
            index = index.wrapping_add(1);
        }
        if (*a).top <= index { (*a).top = (*a).top.wrapping_add(1); }
        1
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::bn_lshift1::{BnExpandWordsFn, EXPAND_TEST_LOCK};
    use std::{boxed::Box, vec};

    fn number(limbs: &mut [u32], top: i32, neg: i32) -> BigNum {
        BigNum { d: limbs.as_ptr(), top, dmax: limbs.len() as i32, neg, flags: 0x55 }
    }

    #[test]
    fn signed_word_addition_matches_integer_reference_and_write_bounds() {
        for value in [0u128, 1, 2, u32::MAX as u128, (1u128 << 64) - 1,
            (1u128 << 95) + 3] {
            for word in [0u32, 1, 2, 3, u32::MAX] {
                for neg in [0, 1, 7] {
                    let mut limbs = [value as u32, (value >> 32) as u32,
                        (value >> 64) as u32, 0, 0xa5a5_a5a5];
                    let top = if value >> 64 != 0 { 3 } else if value >> 32 != 0 { 2 }
                        else if value != 0 { 1 } else { 0 };
                    let mut a = number(&mut limbs, top, neg);
                    assert_eq!(unsafe { bn_add_word(&mut a, word) }, 1);
                    let expected = if neg == 0 { value as i128 + word as i128 }
                        else { word as i128 - value as i128 };
                    let magnitude = expected.unsigned_abs();
                    assert_eq!(limbs[..4], [magnitude as u32, (magnitude >> 32) as u32,
                        (magnitude >> 64) as u32, (magnitude >> 96) as u32]);
                    let expected_top = if magnitude >> 96 != 0 { 4 } else if magnitude >> 64 != 0 { 3 }
                        else if magnitude >> 32 != 0 { 2 } else if magnitude != 0 { 1 }
                        else if top == 0 || (neg != 0 && value == 0) { 1 } else { top - i32::from(neg != 0) };
                    assert_eq!(a.top, expected_top);
                    // Stock preserves negative zero on the empty-magnitude recursion.
                    assert_eq!(a.neg, i32::from(expected < 0 || (neg != 0 && value == 0 && word == 0)));
                    assert_eq!(limbs[4], 0xa5a5_a5a5);
                    assert_eq!((a.dmax, a.flags), (5, 0x55));
                }
            }
        }
    }

    unsafe extern "C" fn expand(a: *mut BigNum, words: i32) -> *mut BigNum {
        unsafe {
            if (*a).flags == -1 { return ptr::null_mut(); }
            let mut storage = vec![0xa5a5_a5a5; words as usize].into_boxed_slice();
            ptr::copy_nonoverlapping((*a).d, storage.as_mut_ptr(), (*a).top as usize);
            (*a).d = Box::into_raw(storage) as *const u32;
            (*a).dmax = words;
            a
        }
    }

    #[test]
    fn relocation_and_failure_preserve_magnitude_and_stock_sign_side_effects() {
        let _serial = EXPAND_TEST_LOCK.lock();
        struct Restore(BnExpandWordsFn);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { BN_EXPAND_WORDS = self.0; } }
        }
        let _restore = Restore(unsafe { BN_EXPAND_WORDS });
        unsafe { BN_EXPAND_WORDS = expand; }
        for word in [0, 1] {
            let mut old = [u32::MAX];
            let mut a = number(&mut old, 1, 0);
            assert_eq!(unsafe { bn_add_word(&mut a, word) }, 1);
            assert_ne!(a.d, old.as_ptr());
            assert_eq!(a.top, 1 + word as i32);
            assert_eq!(unsafe { *a.d }, u32::MAX.wrapping_add(word));
            assert_eq!(unsafe { *a.d.add(1) }, if word == 0 { 0xa5a5_a5a5 } else { 1 });
            assert_eq!(old, [u32::MAX]);
            unsafe { drop(Box::from_raw(ptr::slice_from_raw_parts_mut(a.d as *mut u32, 2))); }
        }
        for (top, neg, expected_neg) in [(1, 0, 0), (0, 0, 0), (0, 7, 1)] {
            let mut limbs = [9];
            let mut a = number(&mut limbs, top, neg);
            a.dmax = top;
            a.flags = -1;
            let original = a.d;
            assert_eq!(unsafe { bn_add_word(&mut a, 4) }, 0);
            assert_eq!(limbs, [9]);
            assert_eq!(a.d, original);
            assert_eq!((a.top, a.neg, a.dmax, a.flags), (top, expected_neg, top, -1));
        }
        let mut limbs = [9];
        let mut a = number(&mut limbs, 1, 1);
        a.flags = -1;
        assert_eq!(unsafe { bn_sub_word(&mut a, 4) }, 0);
        assert_eq!(limbs, [9]);
        assert_eq!((a.top, a.neg), (1, 1));
    }
}
