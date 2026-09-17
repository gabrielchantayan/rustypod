//! `fixed4_componentwise_mul` — retailOS `FUN_0829f848` at **0x0829f848**.
//!
//! Raw decoding establishes a **92-byte** body
//! (`0x0829f848..0x0829f8a4`): the next separately linked function begins at
//! `0x0829f8a4`. It has four direct `bl` instructions, all unconditional:
//! three calls to `fixed16_mul` and one to `store_four_u32s`; there are no
//! predicated `bl` forms. The raw binary also has four inbound plain `bl`
//! callers (`0x0824c158`, `0x0824c3c0`, `0x0824c3dc`, and `0x0824c3f8`).
//!
//! Multiplies the first three Q16.16 components of `left` and `right`, then
//! writes those products and the unmodified fourth word of `left` to `dst`.
//! The firmware completes all input reads before the final four-word store, so
//! `dst` may alias either input.
//!
//! Deliberate deviations: the two known retailOS callees are invoked through
//! their existing Rust ports. Their observable arithmetic and store order are
//! identical to the original calls.

use crate::util::fixed::fixed16_mul;
use crate::util::store_four_u32s::store_four_u32s;

/// Multiplies the Q16.16 xyz components of two four-word records, preserving
/// `left[3]` in `dst[3]` — retailOS `FUN_0829f848` at 0x0829f848.
///
/// # Safety
///
/// `dst` must be valid for four writable aligned words; `left` and `right`
/// must each be valid for four readable aligned words. `dst` may alias either
/// input.
#[cfg_attr(target_os = "none", link_section = ".text.fixed4_componentwise_mul")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed4_componentwise_mul(
    dst: *mut u32,
    left: *const i32,
    right: *const i32,
) {
    let z = fixed16_mul(*left.add(2), *right.add(2));
    let y = fixed16_mul(*left.add(1), *right.add(1));
    let x = fixed16_mul(*left, *right);
    let preserved_w = *left.add(3) as u32;
    unsafe { store_four_u32s(dst, x as u32, y as u32, z as u32, preserved_w) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed16_product(a: i32, b: i32) -> u32 {
        (((a as i64 * b as i64) >> 16) as i32) as u32
    }

    #[test]
    fn multiplies_signed_xyz_and_preserves_left_w() {
        let left = [0x0001_8000, -0x0001_0000, i32::MIN, 0x1234_5678];
        let right = [-0x0002_0000, 0x0000_8000, 0x0001_0000, -1];
        let mut dst = [0_u32; 4];

        unsafe { fixed4_componentwise_mul(dst.as_mut_ptr(), left.as_ptr(), right.as_ptr()) };

        assert_eq!(dst, [fixed16_product(left[0], right[0]), fixed16_product(left[1], right[1]), fixed16_product(left[2], right[2]), left[3] as u32]);
    }

    #[test]
    fn reads_both_inputs_before_an_aliasing_destination_store() {
        let mut left = [0x0001_0000, -0x0002_0000, 0x0000_8000, 0x7654_3210];
        let right = [-0x0000_8000, 0x0001_8000, -0x0003_0000, 0x1111_2222];
        let expected = [fixed16_product(left[0], right[0]), fixed16_product(left[1], right[1]), fixed16_product(left[2], right[2]), left[3] as u32];

        unsafe { fixed4_componentwise_mul(left.as_mut_ptr().cast(), left.as_ptr(), right.as_ptr()) };

        assert_eq!(left.map(|value| value as u32), expected);
    }
}
