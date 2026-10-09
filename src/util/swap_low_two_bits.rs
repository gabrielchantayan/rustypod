//! Swap the two low flag bits and discard all other bits.
//!
//! Original: `FUN_080d87d4`, load address **0x080d87d4**, true size
//! **28 bytes** ([0x080d87d4, 0x080d87f0)). The next function begins
//! with `push {r4, r5, lr}`. Verified whole-image aligned A32 BL scan:
//! two plain inbound calls (0x0812e490, 0x0812e618), zero predicated
//! inbound calls; zero plain or predicated outbound calls.
//!
//! Raw words: `e1a01000 e3110001 e3a00000 13a00002 e3110002 13800001
//! e12fff1e`. Bit 0 contributes output bit 1 and bit 1 contributes
//! output bit 0. Both callers convert a word at object +0x0c into a byte
//! of flags. No callee seams or deliberate behavioral deviations.

/// Converts the low two flags to the opposite bit order, clearing higher bits.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn swap_low_two_bits(flags: u32) -> u32 {
    ((flags & 1) << 1) | ((flags & 2) >> 1)
}

#[cfg(test)]
mod tests {
    use super::swap_low_two_bits;

    #[test]
    fn converts_each_low_flag_combination() {
        for (flags, expected) in [(0, 0), (1, 2), (2, 1), (3, 3)] {
            assert_eq!(swap_low_two_bits(flags), expected);
        }
    }

    #[test]
    fn ignores_every_high_bit_for_each_low_flag_combination() {
        for bit in 2..32 {
            for (flags, expected) in [(0, 0), (1, 2), (2, 1), (3, 3)] {
                assert_eq!(swap_low_two_bits((1u32 << bit) | flags), expected);
                assert_eq!(swap_low_two_bits(0xffff_fffc | flags), expected);
            }
        }
    }
}
