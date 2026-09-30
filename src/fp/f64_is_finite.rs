//! Binary64 finiteness classification without floating-point operations.
//!
//! Original: `FUN_082ab120` @ load address **0x082ab120**. True extent:
//! **0x082ab120..0x082ab144 (36 bytes)**, comprising 32 instruction bytes
//! and the four-byte literal 0xffe00000. The next independent push prologue
//! is at 0x082ab144. Whole-image aligned ARM-word decoding finds two plain
//! inbound BLs (0x08031c24, 0x08031c88), zero predicated inbound BLs, and
//! zero plain or predicated outbound BLs.
//!
//! The original shifts the high input word right 20, then left 21, dropping
//! the sign and fraction. Equality with 0xffe00000 means exponent 0x7ff:
//! return zero for either infinity and every NaN, one for all finite values.
//! The caller at 0x08031c10 classifies both its binary64 input and a result.
//!
//! Deliberate deviations: accept the register pair as raw u64 bits, mask
//! the exponent directly, and omit the original stack spills and literal
//! load. No floating-point operation, NaN quieting, or callee seam is needed.

/// Return exactly 1 for finite binary64 bits and 0 for infinities or NaNs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn f64_is_finite(bits: u64) -> u32 {
    ((bits >> 52) & 0x7ff != 0x7ff) as u32
}

#[cfg(test)]
mod tests {
    use super::f64_is_finite;

    #[test]
    fn classifies_every_sign_and_exponent_with_fraction_boundaries() {
        // Include low-word-only NaNs, signaling/quiet payloads, subnormals,
        // both signed zeros, and the finite/infinity boundary.
        for sign in 0..=1u64 {
            for exponent in 0..=0x7ffu64 {
                for fraction in [0, 1, 0xffff_ffff, 1u64 << 32,
                                 (1u64 << 51) - 1, 1u64 << 51,
                                 (1u64 << 52) - 1] {
                    let bits = (sign << 63) | (exponent << 52) | fraction;
                    let expected = f64::from_bits(bits).is_finite() as u32;
                    assert_eq!(f64_is_finite(bits), expected, "bits={bits:016x}");
                }
            }
        }
    }
}
