//! Scaled float-to-count conversion used by renderer state setup.
//!
//! `scaled_f32_count_ceiling_to_u32_083d24cc` — original: `FUN_083d24cc` @
//! 0x083d24cc (60 bytes, 0x083d24cc..0x083d2507). Raw `osos.dec` establishes
//! the 15-word body; 0x083d2508 begins the next function with `push
//! {r0,r1,r2,r4-r11,lr}`. The body has five unconditional `bl` instructions
//! and no predicated direct calls. Its two inbound plain `bl` sites are
//! 0x083d2198 and 0x083d24b8; no inbound predicated call was found.
//!
//! It converts the u32 count at `state + 0x18` and the f32 bit pattern at
//! `state + 0x08` to doubles, multiplies them, rounds toward positive infinity,
//! saturates the result to u32, and writes it at `state + 0x0c`.
//!
//! Deliberate deviations: Rust addresses the opaque state as u32 words so the
//! target's four-byte field offsets remain valid on 64-bit hosts. Volatile
//! function-pointer loads preserve the five helper call boundaries rather than
//! allowing LLVM to inline or fold them.

use crate::fp::fp_dconv::{__u2d, double_to_u32_saturating};
use crate::fp::fp_dmul::__dmul;
use crate::fp::fp_fconv::__f2d;
use crate::libm::ceilfloor::ceil;

/// Computes and stores the rounded-up scaled count in an opaque renderer state.
///
/// # Safety
///
/// `state` must be four-byte aligned, readable at word indices 2 and 6, and
/// writable at word index 3. The retail function has no null or alignment guards.
#[inline(never)]
#[cfg_attr(
    target_os = "none",
    unsafe(link_section = ".text.scaled_f32_count_ceiling_to_u32_083d24cc")
)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scaled_f32_count_ceiling_to_u32_083d24cc(state: *mut u32) {
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
        unsafe { scaled_f32_count_ceiling_to_u32_083d24cc(state.as_mut_ptr()) };
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
        assert_eq!(run(1.5, 2), 3);
    }

    #[test]
    fn saturates_negative_and_maximum_products() {
        assert_eq!(run(-1.2, 3), 0);
        assert_eq!(run(-0.2, 3), 0);
        assert_eq!(run(1.0, u32::MAX), u32::MAX);
        assert_eq!(run(f32::INFINITY, 1), u32::MAX);
    }
}
