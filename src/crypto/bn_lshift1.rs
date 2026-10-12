//! OpenSSL `BN_lshift1` — load address 0x0803f4b8, 216 bytes
//! (0x0803f4b8..0x0803f590; next entry has an independent PUSH prologue).
//! Binary-wide A32 decoding verifies two incoming plain BLs at 0x0803fcb0
//! and 0x0803fdf4, zero predicated incoming BLs, and two outgoing plain BLs
//! to the limb-capacity worker at 0x082b8174.
//!
//! Copy the sign for distinct objects, reserve top+1 limbs, then shift the
//! little-endian magnitude left one bit, propagating carry and appending one
//! high limb if needed. Allocation failure leaves magnitude/top unchanged
//! but retains the copied sign. In-place operation reads each limb first.
//! Deliberate deviations: existing native-pointer repr(C) BigNum on hosts;
//! the unported capacity worker uses a volatile dispatch slot, not direct BL.
//! No normalization, zero shortcut, or extra validation is introduced.

use super::bn_num_bits::BigNum;
use core::ptr;

pub type BnExpandWordsFn = unsafe extern "C" fn(*mut BigNum, i32) -> *mut BigNum;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_expand_words(a: *mut BigNum, words: i32) -> *mut BigNum {
    let worker: BnExpandWordsFn = unsafe { core::mem::transmute(0x082b_8174usize) };
    unsafe { worker(a, words) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_expand_words(_a: *mut BigNum, _words: i32) -> *mut BigNum {
    panic!("bn_lshift1 requires limb-capacity worker at 0x082b8174")
}

/// Stock worker compares dmax, allocates/copies limbs, releases old storage,
/// then updates d and dmax; allocation failure returns NULL without updates.
#[cfg(target_os = "none")]
pub static mut BN_EXPAND_WORDS: BnExpandWordsFn = firmware_bn_expand_words;
#[cfg(not(target_os = "none"))]
pub static mut BN_EXPAND_WORDS: BnExpandWordsFn = missing_bn_expand_words;

/// Shift `a` left one bit into `result`, returning one on success, zero on failure.
///
/// # Safety
/// Objects must be live BigNums with readable source and writable destination
/// limbs. Objects may be identical; otherwise limb buffers must not overlap.
/// The expansion worker must provide top+1 writable limbs and preserve the
/// old magnitude on success, or leave storage unchanged on failure. Hosts
/// must install the worker before any capacity-expansion path is exercised.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_lshift1(result: *mut BigNum, a: *const BigNum) -> i32 {
    unsafe {
        let distinct = !ptr::eq(result as *const BigNum, a);
        if distinct { (*result).neg = (*a).neg; }
        let words = (*a).top.wrapping_add(1);
        if (*result).dmax < words {
            let expand = ptr::read_volatile(ptr::addr_of!(BN_EXPAND_WORDS));
            if expand(result, words).is_null() { return 0; }
        }
        if distinct { (*result).top = (*a).top; }
        let mut source = (*a).d;
        let mut destination = (*result).d as *mut u32;
        let mut carry = 0;
        let mut index = 0i32;
        while index < (*a).top {
            let limb = ptr::read(source);
            ptr::write(destination, (limb << 1) | carry);
            carry = limb >> 31;
            source = source.add(1);
            destination = destination.add(1);
            index += 1;
        }
        if carry != 0 {
            ptr::write(destination, 1);
            (*result).top = (*result).top.wrapping_add(1);
        }
        1
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{boxed::Box, vec};

    fn number(limbs: &mut [u32], top: i32, neg: i32) -> BigNum {
        BigNum { d: limbs.as_ptr(), top, dmax: limbs.len() as i32, neg, flags: 0x55 }
    }

    #[test]
    fn separate_and_in_place_match_double_with_exact_write_bounds() {
        for value in [0u128, 1, 0x8000_0000, u32::MAX as u128,
            (1u128 << 64) - 1, (1u128 << 95) + 3] {
            for neg in [0, 1, 7] {
                let top = if value >> 64 != 0 { 3 } else if value >> 32 != 0 { 2 }
                    else if value != 0 { 1 } else { 0 };
                for in_place in [false, true] {
                    let mut source = [value as u32, (value >> 32) as u32,
                        (value >> 64) as u32, 0xa5a5_a5a5, 0xa5a5_a5a5];
                    let mut output = [0xa5a5_a5a5; 5];
                    let mut a = number(&mut source, top, neg);
                    let mut result = number(&mut output, 4, 9);
                    let destination = if in_place { &mut a } else { &mut result } as *mut BigNum;
                    assert_eq!(unsafe { bn_lshift1(destination, &a) }, 1);
                    let expected = value * 2;
                    let expected_top = if expected >> 96 != 0 { 4 } else if expected >> 64 != 0 { 3 }
                        else if expected >> 32 != 0 { 2 } else if expected != 0 { 1 } else { 0 };
                    let actual = if in_place { &source } else { &output };
                    for i in 0..expected_top as usize {
                        assert_eq!(actual[i], (expected >> (32 * i)) as u32);
                    }
                    let written = expected_top as usize;
                    let original = if in_place {
                        [value as u32, (value >> 32) as u32, (value >> 64) as u32, 0xa5a5_a5a5, 0xa5a5_a5a5]
                    } else { [0xa5a5_a5a5; 5] };
                    assert_eq!(actual[written..], original[written..]);
                    assert_eq!(unsafe { ((*destination).top, (*destination).neg,
                        (*destination).dmax, (*destination).flags) }, (expected_top, neg, 5, 0x55));
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
    fn relocation_and_failure_preserve_stock_state_transitions() {
        // Only this test accesses this module's dispatch slot.
        struct Restore(BnExpandWordsFn);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { BN_EXPAND_WORDS = self.0; } }
        }
        let _restore = Restore(unsafe { BN_EXPAND_WORDS });
        unsafe { BN_EXPAND_WORDS = expand; }
        for in_place in [false, true] {
            let mut source = [u32::MAX];
            let mut old_output = [9];
            let mut a = number(&mut source, 1, 7);
            let mut result = number(&mut old_output, 1, 0);
            let destination = if in_place { &mut a } else { &mut result } as *mut BigNum;
            assert_eq!(unsafe { bn_lshift1(destination, &a) }, 1);
            unsafe {
                assert_eq!(core::slice::from_raw_parts((*destination).d, 2), &[0xffff_fffe, 1]);
                assert_eq!(((*destination).top, (*destination).neg, (*destination).dmax), (2, 7, 2));
                drop(Box::from_raw(ptr::slice_from_raw_parts_mut((*destination).d as *mut u32, 2)));
            }
            assert_eq!(source, [u32::MAX]);
            assert_eq!(old_output, [9]);
        }
        let mut source = [0x8000_0000];
        let mut output = [17];
        let a = number(&mut source, 1, 7);
        let mut result = number(&mut output, 1, 0);
        result.flags = -1;
        assert_eq!(unsafe { bn_lshift1(&mut result, &a) }, 0);
        assert_eq!(output, [17]);
        assert_eq!((result.top, result.neg, result.dmax, result.flags), (1, 7, 1, -1));
        assert_eq!(unsafe { bn_lshift1(&mut result, &result) }, 0);
        assert_eq!(output, [17]);
        assert_eq!((result.top, result.neg, result.dmax, result.flags), (1, 7, 1, -1));
    }
}
