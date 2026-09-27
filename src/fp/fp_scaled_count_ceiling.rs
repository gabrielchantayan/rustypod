//! Scaled float-to-count conversion used by renderer state setup.
//!
//! `scaled_f32_count_ceiling_to_u32` — original: `FUN_083d27f4` @ 0x083d27f4
//! (60 bytes, 0x083d27f4..0x083d282f). The raw body has five unconditional
//! `bl` instructions and no predicated direct calls.

use crate::fp::fp_dconv::{__u2d, double_to_u32_saturating};
use crate::fp::fp_dmul::__dmul;
use crate::fp::fp_fconv::__f2d;
use crate::libm::ceilfloor::ceil;

/// `scaled_f32_count_ceiling_to_u32` — original: `FUN_083d27f4` @ 0x083d27f4
/// (60 bytes; five verified unconditional in-body `bl` instructions, none
/// predicated).
///
/// Converts the f32 bit pattern at state word +2 to double, multiplies it by
/// the unsigned count at word +6, rounds toward positive infinity, converts
/// the result to a saturating u32, and stores it at word +3. The five helper
/// calls mirror the retail order: `__u2d`, `__f2d`, `__dmul`, `ceil`, then
/// `double_to_u32_saturating`.
///
/// Deliberate deviations: the opaque state is addressed as u32 words, rather
/// than a host-layout struct, so the target's four-byte field offsets remain
/// valid on 64-bit host tests. Function pointers are volatile-loaded to retain
/// the helper call boundaries in target code.
#[inline(never)]
#[cfg_attr(
    target_os = "none",
    unsafe(link_section = ".text.scaled_f32_count_ceiling_to_u32")
)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scaled_f32_count_ceiling_to_u32(state: *mut u32) {
    let u2d: unsafe extern "C" fn(u32) -> u64 =
        core::ptr::read_volatile(&(__u2d as unsafe extern "C" fn(u32) -> u64));
    let f2d: unsafe extern "C" fn(u32) -> u64 =
        core::ptr::read_volatile(&(__f2d as unsafe extern "C" fn(u32) -> u64));
    let dmul: unsafe extern "C" fn(u64, u64) -> u64 =
        core::ptr::read_volatile(&(__dmul as unsafe extern "C" fn(u64, u64) -> u64));
    let ceil_double: unsafe extern "C" fn(u64) -> u64 =
        core::ptr::read_volatile(&(ceil as unsafe extern "C" fn(u64) -> u64));
    let to_u32: unsafe extern "C" fn(u64) -> u32 = core::ptr::read_volatile(
        &(double_to_u32_saturating as unsafe extern "C" fn(u64) -> u32),
    );

    let count = *state.add(6);
    let scale = *state.add(2);
    let count_as_double = u2d(count);
    let scale_as_double = f2d(scale);
    let product = dmul(scale_as_double, count_as_double);
    *state.add(3) = to_u32(ceil_double(product));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(scale: f32, count: u32) -> u32 {
        let mut state = [0xfeed_face; 7];
        state[2] = scale.to_bits();
        state[6] = count;
        unsafe { scaled_f32_count_ceiling_to_u32(state.as_mut_ptr()) };
        assert_eq!(state[0], 0xfeed_face);
        assert_eq!(state[1], 0xfeed_face);
        assert_eq!(state[4], 0xfeed_face);
        assert_eq!(state[5], 0xfeed_face);
        state[3]
    }

    #[test]
    fn rounds_fractional_positive_products_up() {
        assert_eq!(run(1.2, 3), 4);
        assert_eq!(run(0.25, 5), 2);
    }

    #[test]
    fn saturates_negative_and_maximum_products() {
        assert_eq!(run(-1.2, 3), 0);
        assert_eq!(run(-0.2, 3), 0);
        assert_eq!(run(1.0, u32::MAX), u32::MAX);
    }
}
