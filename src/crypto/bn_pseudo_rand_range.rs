//! OpenSSL `BN_pseudo_rand_range` — 0x08040538, 16 bytes.
//!
//! Raw words e1a02001 e1a01000 e3a00001 ea010782 move range/result
//! to r2/r1, select pseudo-random mode 1, and tail-branch to the shared
//! range worker at 0x08082354. The next real entry is 0x08040548.
//! Two incoming plain BLs (0x080622a4, 0x0808b324), zero predicated BLs;
//! no outgoing BLs. Return the worker's integer result unchanged.
//! The worker rejects nonpositive ranges, returns zero for range one,
//! and uses rejection sampling (with a two-subtraction optimization).
//! Deliberate deviation: retain the unported worker through the existing
//! volatile dispatch-slot convention. Host models do not prove RNG quality.

use super::bn_num_bits::BigNum;

pub type BnRandomRangeFn = unsafe extern "C" fn(i32, *mut BigNum, *const BigNum) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_random_range(mode: i32, result: *mut BigNum, range: *const BigNum) -> i32 {
    let worker: BnRandomRangeFn = unsafe { core::mem::transmute(0x0808_2354usize) };
    unsafe { worker(mode, result, range) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_random_range(_: i32, _: *mut BigNum, _: *const BigNum) -> i32 {
    panic!("bn_pseudo_rand_range requires the range worker 0x08082354")
}

#[cfg(target_os = "none")]
pub static mut BN_RANDOM_RANGE: BnRandomRangeFn = firmware_bn_random_range;
#[cfg(not(target_os = "none"))]
pub static mut BN_RANDOM_RANGE: BnRandomRangeFn = missing_bn_random_range;

/// Generate a pseudo-random nonnegative integer strictly below `range`.
/// Original: 0x08040538, 16 bytes; two plain BL callers, no predicated BLs.
///
/// # Safety
/// Both bignums must satisfy the stock worker's storage contract. On hosts,
/// install `BN_RANDOM_RANGE` before calling. The source is not guaranteed
/// cryptographically strong; this API deliberately retains stock mode 1.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_pseudo_rand_range(result: *mut BigNum, range: *const BigNum) -> i32 {
    let worker = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_RANDOM_RANGE)) };
    unsafe { worker(1, result, range) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One-limb deterministic source model; rejection consumes successive
    // candidates. Mode zero uses a different source, not an argument echo.
    unsafe extern "C" fn range_model(mode: i32, result: *mut BigNum, range: *const BigNum) -> i32 {
        let limit = unsafe { &*range };
        if limit.neg != 0 || limit.top == 0 { return 0; }
        let bound = unsafe { *limit.d };
        if bound == 0 { return 0; }
        if bound == 1 {
            unsafe { (*result).top = 0; (*result).neg = 0; }
            return 1;
        }
        if unsafe { (*result).dmax } == 0 { return 0; }
        let mask = u32::MAX >> bound.leading_zeros();
        let candidates = if mode == 1 { [u32::MAX, 6, 2] } else { [1, 0, 0] };
        for candidate in candidates {
            let value = candidate & mask;
            if value < bound {
                unsafe {
                    (*result).d.cast_mut().write(value);
                    (*result).top = if value == 0 { 0 } else { 1 };
                    (*result).neg = 0;
                }
                return 1;
            }
        }
        0
    }

    #[test]
    fn rejection_unit_range_and_invalid_ranges() {
        let old = unsafe { BN_RANDOM_RANGE };
        unsafe { BN_RANDOM_RANGE = range_model; }
        let mut output = 0xdead_beef;
        let mut result = BigNum { d: &mut output, top: 1, dmax: 1, neg: 1, flags: 0 };
        for (bound, expected) in [(3, 2), (7, 6), (8, 6), (u32::MAX, 6)] {
            let range = BigNum { d: &bound, top: 1, dmax: 1, neg: 0, flags: 0 };
            assert_eq!(unsafe { bn_pseudo_rand_range(&mut result, &range) }, 1);
            assert_eq!(output, expected);
            assert_eq!((result.top, result.neg), (1, 0));
        }
        let one = 1;
        let mut range = BigNum { d: &one, top: 1, dmax: 1, neg: 0, flags: 0 };
        assert_eq!(unsafe { bn_pseudo_rand_range(&mut result, &range) }, 1);
        assert_eq!((result.top, result.neg), (0, 0));
        let before = output;
        for (top, neg) in [(0, 0), (1, 1)] {
            range.top = top;
            range.neg = neg;
            assert_eq!(unsafe { bn_pseudo_rand_range(&mut result, &range) }, 0);
            assert_eq!(output, before);
            assert_eq!((result.top, result.neg), (0, 0));
        }
        unsafe { BN_RANDOM_RANGE = old; }
    }
}
