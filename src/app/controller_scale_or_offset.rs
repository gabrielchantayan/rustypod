//! Controller value scaling — FUN_082004b4 @ 0x082004b4, 60 bytes.
//!
//! Raw A32 extent: 0x082004b4..0x082004f0; the next function starts with
//! push {r4, lr}. One outbound plain BL to __rt_udiv (0x08036f14), zero
//! predicated BLs; two inbound plain BLs at 0x081ffc48 and 0x08200c18,
//! zero predicated BLs. Read the scale word at controller+0x2d4. Unless
//! it equals 255, return the unsigned quotient of the wrapping low-word
//! product value*scale divided by 255. For scale 255, read +0x2d8 and
//! return zero when that unsigned threshold exceeds value, otherwise
//! return the wrapping sum threshold+value (not subtraction).
//!
//! Deviations: Rust control flow replaces ARM predication and register
//! shuffling; LLVM tail-branches to the existing ported unsigned divider
//! instead of BL followed by return. No behavioral deviation.
//! The controller's higher-level identity remains unresolved.

/// Transform a value using the controller's scale/threshold words.
///
/// # Safety
/// `controller` must be word-aligned and readable through offset 0x2d7;
/// when the scale is 255 it must also be readable through offset 0x2db.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_scale_or_offset(controller: *const u32, value: u32) -> u32 {
    let scale = unsafe { controller.add(0x2d4 / 4).read() };
    if scale == 255 {
        let threshold = unsafe { controller.add(0x2d8 / 4).read() };
        if threshold <= value { threshold.wrapping_add(value) } else { 0 }
    } else {
        unsafe { crate::rt_div::__rt_udiv(value.wrapping_mul(scale), 255) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transform(scale: u32, threshold: u32, value: u32) -> u32 {
        let mut controller = [0u32; 0x2dc / 4];
        controller[0x2d4 / 4] = scale;
        controller[0x2d8 / 4] = threshold;
        unsafe { controller_scale_or_offset(controller.as_ptr(), value) }
    }

    #[test]
    fn threshold_unsigned_boundaries_and_wrapping_sum() {
        for (threshold, value, expected) in [
            (0, 0, 0), (7, 6, 0), (7, 7, 14), (7, 8, 15),
            (0x8000_0000, 0x7fff_ffff, 0),
            (0x7fff_ffff, 0x8000_0000, u32::MAX),
            (u32::MAX, u32::MAX, 0xffff_fffe),
        ] {
            assert_eq!(transform(255, threshold, value), expected);
        }
    }

    #[test]
    fn scaling_uses_low_product_word_and_unsigned_truncation() {
        for scale in [0, 1, 2, 254, 256, 0x8000_0000, u32::MAX] {
            for value in [0, 1, 254, 255, 256, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                let low_product = ((scale as u64 * value as u64) & 0xffff_ffff) as u32;
                assert_eq!(transform(scale, u32::MAX, value), low_product / 255);
            }
        }
        assert_eq!(transform(2, 0, u32::MAX), 16_843_008);
    }
}
