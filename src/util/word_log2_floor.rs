//! Floor-log2 word helper used when deriving texture mipmap counts.
//!
//! Original: `FUN_08260534` at load address 0x08260534, 36 bytes, ending
//! immediately before the separate alignment leaf at 0x08260558. Raw A32
//! decoding finds two inbound plain BLs (0x082507dc, 0x082507ec), zero
//! predicated BLs, and no outbound BLs or direct tail-B callers.
//!
//! Also ports `FUN_0823664c` at 0x0823664c: the nine A32 words are
//! byte-identical, with `bx lr` at 0x0823666c and the next real function's
//! push at 0x08236670 (true size 36 bytes). Independent raw BL decoding
//! finds two plain inbound calls at 0x08256bc8 and 0x08256bd4, zero
//! predicated inbound calls, and no outbound calls. That caller stores
//! the floor-log2 of each buffer dimension. Both stock entries share this
//! already-registered Rust symbol deliberately; no duplicate seam is needed.
//!
//! Start with result zero and mask one. While the input has bits outside
//! the mask, increment the result and grow the mask as `(mask << 1) | 1`.
//! Returns floor(log2(value)) for nonzero words, and zero for zero.
//! Deliberate deviations: none; the bounded mask-growth loop is preserved.

/// Return the zero-based highest set-bit index, or zero for an empty word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn word_log2_floor(value: u32) -> u32 {
    let mut result = 0;
    let mut mask = 1;
    while value & !mask != 0 {
        result += 1;
        mask = (mask << 1) | 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::word_log2_floor;

    fn reference(mut value: u32) -> u32 {
        let mut index = 0;
        while value > 1 {
            value >>= 1;
            index += 1;
        }
        index
    }

    #[test]
    fn zero_and_every_power_of_two_boundary() {
        assert_eq!(word_log2_floor(0), 0);
        assert_eq!(word_log2_floor(1), 0);
        for bit in 0..32 {
            let power = 1u32 << bit;
            for value in [power - 1, power, power + 1, power | (power - 1)] {
                assert_eq!(word_log2_floor(value), reference(value), "value={value:#x}");
            }
        }
        assert_eq!(word_log2_floor(u32::MAX), 31);
    }

    #[test]
    fn mixed_bits_and_small_words() {
        for value in 0..=65535 {
            assert_eq!(word_log2_floor(value), reference(value));
        }
        for value in [0x5555_5555, 0xaaaa_aaaa, 0x8000_0001, 0x7fff_fffe] {
            assert_eq!(word_log2_floor(value), reference(value));
        }
    }

    #[test]
    fn highest_bit_dominates_every_single_lower_bit() {
        for highest in 1..32 {
            for lower in 0..highest {
                let value = (1u32 << highest) | (1u32 << lower);
                assert_eq!(word_log2_floor(value), highest, "value={value:#x}");
            }
        }
    }
}
