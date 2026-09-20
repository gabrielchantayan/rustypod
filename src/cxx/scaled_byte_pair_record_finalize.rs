//! `scaled_byte_pair_record_finalize` — original: `FUN_083d2e44` @
//! 0x083d2e44 (60 bytes; 2 verified plain `bl` callers — 0x083d2378 and
//! 0x083d2e30 — and no predicated callers).
//!
//! # Extent, calls, and algorithm
//!
//! Raw `osos.dec` words establish the exact 15-word body from `push
//! {r4,r5,r6,lr}` at 0x083d2e44 through `pop {r4,r5,r6,pc}` at 0x083d2e7c;
//! 0x083d2e80 begins the next function with `push {r0,r1,r2,r4-r11,lr}`.
//! The body calls `__u2d`, `__f2d`, `__dmul`, `ceil`, and
//! `double_to_u32_saturating`, in that order. It converts the u32 table value
//! at `this + 0x18` and the f32 bit pattern at `this + 0x08` to doubles,
//! multiplies them, rounds toward positive infinity, then stores the saturated
//! u32 conversion at `this + 0x0c`.
//!
//! The full-image aligned ARM immediate scan also finds an `blhi`-encoding
//! word at 0x088a5b70 targeting this address, but that location is not within
//! any decompiled function and is data, not a predicated call site.
//!
//! # Deliberate deviations
//!
//! Rust cannot preserve the original's r4-r6 saves or its r0:r1 register
//! choreography. Volatile function-pointer loads deliberately preserve each
//! verified helper call boundary rather than allowing LLVM to inline or fold
//! the soft-float operations.

use crate::fp::fp_dconv::{__u2d, double_to_u32_saturating};
use crate::fp::fp_dmul::__dmul;
use crate::fp::fp_fconv::__f2d;
use crate::libm::ceilfloor::ceil;

/// Finalizes a scaled byte-pair record's derived count.
///
/// # Safety
///
/// `this` must be four-byte aligned and readable at offsets 0x08 and 0x18,
/// and writable at offset 0x0c. The retail function has no null or alignment
/// guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scaled_byte_pair_record_finalize(this: *mut u8) {
    let table_value = core::ptr::read_volatile(this.add(0x18).cast::<u32>());
    let u2d: unsafe extern "C" fn(u32) -> u64 =
        core::ptr::read_volatile(&(__u2d as unsafe extern "C" fn(u32) -> u64));
    let table_as_double = u2d(table_value);

    let scale = core::ptr::read_volatile(this.add(0x08).cast::<u32>());
    let f2d: unsafe extern "C" fn(u32) -> u64 =
        core::ptr::read_volatile(&(__f2d as unsafe extern "C" fn(u32) -> u64));
    let scale_as_double = f2d(scale);

    let dmul: unsafe extern "C" fn(u64, u64) -> u64 =
        core::ptr::read_volatile(&(__dmul as unsafe extern "C" fn(u64, u64) -> u64));
    let product = dmul(scale_as_double, table_as_double);
    let round_up: unsafe extern "C" fn(u64) -> u64 =
        core::ptr::read_volatile(&(ceil as unsafe extern "C" fn(u64) -> u64));
    let rounded_product = round_up(product);
    let to_u32: unsafe extern "C" fn(u64) -> u32 = core::ptr::read_volatile(
        &(double_to_u32_saturating as unsafe extern "C" fn(u64) -> u32),
    );
    core::ptr::write_volatile(this.add(0x0c).cast::<u32>(), to_u32(rounded_product));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(align(4))]
    struct Record([u32; 9]);

    fn finalize(scale: u32, table_value: u32) -> u32 {
        let mut record = Record([0; 9]);
        record.0[2] = scale;
        record.0[6] = table_value;
        unsafe { scaled_byte_pair_record_finalize(record.0.as_mut_ptr().cast()) };
        record.0[3]
    }

    #[test]
    fn rounds_scaled_values_up_and_preserves_exact_integers() {
        assert_eq!(finalize(0x3f80_0000, 3), 3); // 1.0 * 3
        assert_eq!(finalize(0x3f00_0000, 3), 2); // 0.5 * 3
        assert_eq!(finalize(0x3fc0_0000, 3), 5); // 1.5 * 3
        assert_eq!(finalize(0x0000_0000, u32::MAX), 0);
    }

    #[test]
    fn saturates_large_and_negative_rounded_products() {
        assert_eq!(finalize(0x3f80_0000, u32::MAX), u32::MAX);
        assert_eq!(finalize(0x7f80_0000, 1), u32::MAX); // +Inf
        assert_eq!(finalize(0xbf00_0000, 3), 0); // ceil(-1.5), then saturate
    }
}
