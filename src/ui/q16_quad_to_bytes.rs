//! Four signed Q16 components to four bytes.
//!
//! Original: `FUN_0829f7c8` @ 0x0829f7c8, 128 bytes, ending before the
//! independent prologue at 0x0829f848. Whole-image ARM decoding verifies
//! two incoming plain BLs, four outgoing plain BLs to 0x080f0f44, and zero
//! predicated BLs in either direction. Clamp each signed word to 0..65536,
//! multiply by 511, arithmetic-shift right 17, and store four bytes in order.
//! All four source words are consumed before any destination write, allowing
//! overlap. Component/domain names are unproven; no color ordering is assumed.
//! No deliberate behavioral deviations.

use crate::signed_clamp_i32::signed_clamp_i32_q16;

/// Source must contain four aligned, readable i32 words; destination must
/// contain four writable bytes. The two ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn q16_quad_to_bytes(dst: *mut u8, src: *const i32) {
    let first = signed_clamp_i32_q16(src.read(), 0, 0x10000);
    let second = signed_clamp_i32_q16(src.add(1).read(), 0, 0x10000);
    let third = signed_clamp_i32_q16(src.add(2).read(), 0, 0x10000);
    let fourth = signed_clamp_i32_q16(src.add(3).read(), 0, 0x10000);
    dst.write(((first * 511) >> 17) as u8);
    dst.add(1).write(((second * 511) >> 17) as u8);
    dst.add(2).write(((third * 511) >> 17) as u8);
    dst.add(3).write(((fourth * 511) >> 17) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(value: i32) -> u8 {
        let bounded = if value < 0 { 0 } else if value > 65536 { 65536 } else { value };
        ((i64::from(bounded) * 511) / 131072) as u8
    }

    #[test]
    fn signed_extrema_and_every_quantization_boundary() {
        for value in -1..=65537 {
            let src = [value, i32::MIN, i32::MAX, 32768];
            let mut dst = [0xa5; 6];
            unsafe { q16_quad_to_bytes(dst.as_mut_ptr().add(1), src.as_ptr()); }
            assert_eq!(dst, [0xa5, reference(value), 0, 255, 127, 0xa5]);
        }
    }

    #[test]
    fn every_overlapping_byte_offset_uses_original_source_words() {
        for offset in 0..=12 {
            let mut words = [65536i32, 32768, 257, 65535];
            let expected = words.map(reference);
            let bytes = words.as_mut_ptr().cast::<u8>();
            let before = unsafe { core::slice::from_raw_parts(bytes, 16) }.to_vec();
            unsafe { q16_quad_to_bytes(bytes.add(offset), words.as_ptr()); }
            let after = unsafe { core::slice::from_raw_parts(bytes, 16) };
            assert_eq!(&after[offset..offset + 4], &expected);
            assert_eq!(&after[..offset], &before[..offset]);
            assert_eq!(&after[offset + 4..], &before[offset + 4..]);
        }
    }
}
