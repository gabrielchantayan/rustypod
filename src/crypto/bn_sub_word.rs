//! OpenSSL `BN_sub_word` — load address 0x08040b30, 192 bytes
//! (0x08040b30..0x08040bf0; next entry has its own PUSH prologue).
//! Raw word decoding verifies two incoming plain BLs, zero predicated BLs,
//! and one outgoing plain BL at 0x08040b74 to BN_add_word (0x0803e200).
//!
//! Subtract an unsigned word from a signed little-endian limb magnitude.
//! Zero or negative inputs clear the sign, call BN_add_word, then set the
//! sign even on failure. Positive single-limb underflow reverses magnitude
//! and sign; otherwise propagate borrow and remove at most one high zero.
//! Deliberate deviations: use the existing native-pointer repr(C) BigNum on
//! hosts; the unported BN_add_word uses a volatile dispatch slot rather than
//! a direct BL. No normalization, validation, or zero-word shortcut added.

use super::bn_num_bits::BigNum;
use core::ptr;

pub type BnAddWordFn = unsafe extern "C" fn(*mut BigNum, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_add_word(a: *mut BigNum, word: u32) -> i32 {
    let worker: BnAddWordFn = unsafe { core::mem::transmute(0x0803_e200usize) };
    unsafe { worker(a, word) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_add_word(_a: *mut BigNum, _word: u32) -> i32 {
    panic!("bn_sub_word requires BN_add_word at 0x0803e200")
}

/// Unported BN_add_word, identified by its carry loop and signed recursion.
#[cfg(target_os = "none")]
pub static mut BN_ADD_WORD: BnAddWordFn = firmware_bn_add_word;
#[cfg(not(target_os = "none"))]
pub static mut BN_ADD_WORD: BnAddWordFn = missing_bn_add_word;

/// Subtract `word`, returning the stock worker's success/failure status.
///
/// # Safety
/// `a` must be a live BigNum with writable limbs despite its const `d` type.
/// Nonzero magnitudes must be normalized; the add worker must be installed
/// on hosts and its storage/capacity requirements must hold on delegated paths.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_sub_word(a: *mut BigNum, mut word: u32) -> i32 {
    unsafe {
        let top = (*a).top;
        if top == 0 || (top == 1 && *(*a).d == 0) || (*a).neg != 0 {
            (*a).neg = 0;
            let add = ptr::read_volatile(ptr::addr_of!(BN_ADD_WORD));
            let result = add(a, word);
            (*a).neg = 1;
            return result;
        }
        let limbs = (*a).d as *mut u32;
        if top == 1 && *limbs < word {
            *limbs = word.wrapping_sub(*limbs);
            (*a).neg = 1;
            return 1;
        }
        let mut index = 0usize;
        loop {
            let limb = *limbs.add(index);
            if limb >= word {
                let remainder = limb.wrapping_sub(word);
                *limbs.add(index) = remainder;
                if remainder == 0 && (*a).top.wrapping_sub(1) == index as i32 {
                    (*a).top = (*a).top.wrapping_sub(1);
                }
                return 1;
            }
            *limbs.add(index) = limb.wrapping_sub(word);
            word = 1;
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(limbs: &mut [u32], top: i32, neg: i32) -> BigNum {
        BigNum { d: limbs.as_ptr(), top, dmax: limbs.len() as i32, neg, flags: 0x55 }
    }

    #[test]
    fn positive_subtraction_matches_signed_reference() {
        let values = [1u128, 2, u32::MAX as u128, 1u128 << 32,
            (1u128 << 64) + 3, (1u128 << 95) + 0xffff_ffff];
        for value in values {
            for word in [0u32, 1, 2, 3, u32::MAX] {
                let mut limbs = [value as u32, (value >> 32) as u32,
                    (value >> 64) as u32, 0xa5a5_a5a5];
                let top = if limbs[2] != 0 { 3 } else if limbs[1] != 0 { 2 } else { 1 };
                let mut a = number(&mut limbs, top, 0);
                assert_eq!(unsafe { bn_sub_word(&mut a, word) }, 1);
                let expected = value as i128 - word as i128;
                let magnitude = expected.unsigned_abs();
                assert_eq!(limbs[..3], [magnitude as u32, (magnitude >> 32) as u32,
                    (magnitude >> 64) as u32]);
                assert_eq!(a.neg, i32::from(expected < 0));
                let expected_top = if magnitude >> 64 != 0 { 3 } else if magnitude >> 32 != 0 { 2 }
                    else if magnitude != 0 { 1 } else { 0 };
                assert_eq!(a.top, expected_top);
                assert_eq!(limbs[3], 0xa5a5_a5a5);
                assert_eq!((a.dmax, a.flags), (4, 0x55));
            }
        }
    }

    // Implements the positive carry path of the verified stock add worker,
    // including capacity failure before any magnitude write.
    unsafe extern "C" fn bounded_add(a: *mut BigNum, mut word: u32) -> i32 {
        unsafe {
            assert_eq!((*a).neg, 0);
            if (*a).dmax < (*a).top + 1 { return 0; }
            let mut index = 0;
            loop {
                let old = if index < (*a).top { *(*a).d.add(index as usize) } else { 0 };
                let sum = old.wrapping_add(word);
                *((*a).d as *mut u32).add(index as usize) = sum;
                if sum >= word { break; }
                word = 1;
                index += 1;
            }
            if (*a).top <= index { (*a).top += 1; }
            1
        }
    }

    #[test]
    fn delegated_zero_negative_and_failure_keep_stock_sign_rules() {
        // This is the only host test that accesses this module's slot.
        struct Restore(BnAddWordFn);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { BN_ADD_WORD = self.0; } }
        }
        let _restore = Restore(unsafe { BN_ADD_WORD });
        unsafe { BN_ADD_WORD = bounded_add; }
        for (initial, top, neg, word, expected, expected_top) in [
            (0, 0, 0, 7, 7u64, 1), (0, 1, 0, 0, 0, 1),
            (u32::MAX, 1, 1, 1, 1u64 << 32, 2), (5, 1, 7, 3, 8, 1),
        ] {
            let mut limbs = [initial, 0, 0];
            let mut a = number(&mut limbs, top, neg);
            assert_eq!(unsafe { bn_sub_word(&mut a, word) }, 1);
            assert_eq!(limbs[0] as u64 | ((limbs[1] as u64) << 32), expected);
            assert_eq!((a.top, a.neg, a.flags), (expected_top, 1, 0x55));
        }
        let mut limbs = [9];
        let mut a = number(&mut limbs, 1, 1);
        assert_eq!(unsafe { bn_sub_word(&mut a, 4) }, 0);
        assert_eq!(limbs, [9]);
        assert_eq!((a.top, a.neg), (1, 1));
    }
}
