//! `fixed3_difference` — retailOS `FUN_082a5d54` at **0x082a5d54** (92 bytes,
//! 0x082a5d54..0x082a5db0; **4 direct `bl` call sites**, all unconditional,
//! zero predicated forms, and no tail `b` calls), verified by decoding every
//! ARM B/BL word in `osos.dec`.
//!
//! Subtracts two three-word Q16.16 vectors component-wise with wrapping i32
//! subtraction. The original subtracts z then y through `fixed16_sub_indirect`,
//! subtracts x directly, materializes the three results in a 12-byte stack
//! record via `fixed_point3_set`, and copies that record to `dst` through the
//! ROM `__rt_memcpy` veneer. Materializing first means `dst` may alias either
//! input without changing the result.
//!
//! Deliberate deviations: the ROM veneer at 0x08037db0 is called directly as
//! the established Rust `__rt_memcpy` seam; it is behavior-equivalent here.

use crate::app::fixed_point::{fixed_point3_set, FixedPoint3};
use crate::fp::fp_misc::fixed16_sub_indirect;
use crate::libc::rt_memcpy::__rt_memcpy;

/// fixed3_difference — original: `FUN_082a5d54` @ 0x082a5d54 (92 bytes; 4
/// unconditional `bl` call sites, binary-scanned).
///
/// Subtracts `right` from `left` into `dst` as three wrapping Q16.16 components.
/// The input values are all read before `dst` is written, matching the original
/// stack temporary and final 12-byte copy.
///
/// # Safety
///
/// `dst` must be writable and `left` and `right` readable as aligned
/// [`FixedPoint3`] values. `dst` may alias either input.
#[cfg_attr(target_os = "none", link_section = ".text.fixed3_difference")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed3_difference(
    dst: *mut FixedPoint3,
    left: *const FixedPoint3,
    right: *const FixedPoint3,
) {
    let z = unsafe { fixed16_sub_indirect(core::ptr::addr_of!((*left).z), core::ptr::addr_of!((*right).z)) };
    let y = unsafe { fixed16_sub_indirect(core::ptr::addr_of!((*left).y), core::ptr::addr_of!((*right).y)) };
    let x = unsafe { (*left).x.wrapping_sub((*right).x) };
    let mut difference = FixedPoint3 { x: 0, y: 0, z: 0 };
    unsafe {
        fixed_point3_set(&mut difference, x, y, z);
        __rt_memcpy(dst.cast(), core::ptr::addr_of!(difference).cast(), core::mem::size_of::<FixedPoint3>());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtracts_components_with_i32_wraparound() {
        let left = FixedPoint3 { x: i32::MIN, y: i32::MAX, z: -1 };
        let right = FixedPoint3 { x: 1, y: -1, z: i32::MIN };
        let mut dst = FixedPoint3 { x: 0, y: 0, z: 0 };

        unsafe { fixed3_difference(&mut dst, &left, &right) };

        assert_eq!(dst.x, i32::MAX);
        assert_eq!(dst.y, i32::MIN);
        assert_eq!(dst.z, i32::MAX);
    }

    #[test]
    fn reads_complete_inputs_before_overwriting_either_alias() {
        let right = FixedPoint3 { x: -4, y: 5, z: -6 };
        let mut left = FixedPoint3 { x: 10, y: -20, z: 30 };
        unsafe { fixed3_difference(&mut left, &left, &right) };
        assert_eq!((left.x, left.y, left.z), (14, -25, 36));

        let left = FixedPoint3 { x: 10, y: -20, z: 30 };
        let mut right = FixedPoint3 { x: -4, y: 5, z: -6 };
        unsafe { fixed3_difference(&mut right, &left, &right) };
        assert_eq!((right.x, right.y, right.z), (14, -25, 36));
    }
}
