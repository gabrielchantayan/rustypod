//! `fixed4_weighted_difference` — `FUN_08243338` at load address 0x08243338.
//!
//! Raw A32 body: 124 bytes, 0x08243338..0x082433b4; the next function
//! starts with its own push at 0x082433b4. Six outgoing plain BLs call
//! `fixed16_mul` (0x080e9878), zero predicated BLs. Whole-image decoding
//! finds two incoming plain BLs at 0x0824c054 and 0x0824c204, zero predicated.
//!
//! For each xyz component, computes right[i]*left.w - left[i]*right.w.
//! Each signed Q16.16 product is independently shifted down by 16 bits
//! (toward negative infinity), narrowed to i32, then subtracted modulo 2^32.
//! All reads precede the three destination stores, preserving overlap.
//! The callers normalize this vector and use it in fixed-point dot products.
//! Deliberate deviations: no behavioral deviations; LLVM may inline the
//! existing fixed16_mul port instead of retaining the six firmware calls.

use crate::util::fixed::fixed16_mul;

/// # Safety
/// Inputs must each contain four aligned readable i32 words. `dst` must
/// contain three aligned writable i32 words. Exact or partial overlap is valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fixed4_weighted_difference")]
#[inline(never)]
pub unsafe extern "C" fn fixed4_weighted_difference(
    dst: *mut i32,
    left: *const i32,
    right: *const i32,
) {
    let x = fixed16_mul(*right, *left.add(3))
        .wrapping_sub(fixed16_mul(*left, *right.add(3)));
    let y = fixed16_mul(*right.add(1), *left.add(3))
        .wrapping_sub(fixed16_mul(*left.add(1), *right.add(3)));
    let z = fixed16_mul(*right.add(2), *left.add(3))
        .wrapping_sub(fixed16_mul(*left.add(2), *right.add(3)));
    *dst = x;
    *dst.add(1) = y;
    *dst.add(2) = z;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(left: [i32; 4], right: [i32; 4]) -> [i32; 3] {
        core::array::from_fn(|i| {
            let positive = (right[i] as i64 * left[3] as i64).div_euclid(65536);
            let negative = (left[i] as i64 * right[3] as i64).div_euclid(65536);
            (positive - negative) as i32
        })
    }

    #[test]
    fn signed_fractional_products_truncate_separately_and_wrap() {
        let cases = [
            ([1, -1, 65535, 1], [2, -2, -65535, 1]),
            ([i32::MIN, i32::MAX, -1, i32::MAX], [i32::MAX, i32::MIN, 1, i32::MIN]),
            ([65536, -131072, 32768, 65536], [-65536, 196608, -32768, 65536]),
            ([i32::MAX, i32::MIN, 42, 0], [1, 2, 3, 0]),
            ([1, 2, 3, 65536], [1, 2, 3, 65536]),
            ([-1, 0, 0, 1], [0, 0, 0, 1]),
        ];
        for (left, right) in cases {
            let mut dst = [0x12345678; 5];
            unsafe { fixed4_weighted_difference(dst.as_mut_ptr().add(1), left.as_ptr(), right.as_ptr()) };
            assert_eq!(&dst[1..4], &reference(left, right));
            assert_eq!([dst[0], dst[4]], [0x12345678; 2]);
        }
        // A single shift after subtraction would produce 0, rather than 1.
        assert_eq!(reference([-1, 0, 0, 1], [0, 0, 0, 1])[0], 1);
    }

    #[test]
    fn preserves_exact_and_partial_overlap_with_either_input() {
        let left = [65537, -131073, i32::MAX, -32769];
        let right = [-65535, 196609, i32::MIN, 98305];
        let expected = reference(left, right);
        for base in [0, 5] {
            for shift in [0, 1] {
                let mut words = [0x12345678; 10];
                words[..4].copy_from_slice(&left);
                words[5..9].copy_from_slice(&right);
                let before = words;
                let dst = base + shift;
                let ptr = words.as_mut_ptr();
                unsafe { fixed4_weighted_difference(ptr.add(dst), ptr, ptr.add(5)) };
                assert_eq!(&words[dst..dst + 3], &expected);
                assert_eq!(&words[..dst], &before[..dst]);
                assert_eq!(&words[dst + 3..], &before[dst + 3..]);
            }
        }
    }
}
