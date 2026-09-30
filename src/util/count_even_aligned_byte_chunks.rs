//! Greedy immediate byte-window count — `FUN_082b47bc` @ 0x082b47bc.
//! True extent: 0x082b47bc..0x082b47f8 (60 bytes); 1 internal plain BL,
//! 2 incoming plain BL call sites; no predicated BLs in either count.
//!
//! While bits remain, find the lowest set bit, round its zero-based index
//! down to an even position, clear the eight-bit window starting there,
//! and increment the count. Callers use this cost to choose between a
//! constant and its complement when emitting ARM immediate instructions.
//! Windows truncate at bit 31, rather than wrapping. Deliberate deviations:
//! none; the existing lowest-set-bit seam retains the original helper call.

use super::lowest_set_bit_one_based::lowest_set_bit_one_based;

/// Count the greedy even-aligned byte windows needed to clear `value`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn count_even_aligned_byte_chunks(mut value: u32) -> u32 {
    let mut count = 0;
    while value != 0 {
        let shift = (lowest_set_bit_one_based(value) - 1) & !1;
        value &= !(0xffu32 << shift);
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::count_even_aligned_byte_chunks;

    fn reference(value: u32) -> u32 {
        let mut count = 0;
        let mut bit = 0;
        while bit < 32 {
            if value & (1u32 << bit) == 0 {
                bit += 1;
            } else {
                count += 1;
                bit = (bit & !1) + 8;
            }
        }
        count
    }

    #[test]
    fn zero_single_bits_and_full_word() {
        assert_eq!(count_even_aligned_byte_chunks(0), 0);
        for bit in 0..32 {
            assert_eq!(count_even_aligned_byte_chunks(1 << bit), 1);
        }
        assert_eq!(count_even_aligned_byte_chunks(u32::MAX), 4);
    }

    #[test]
    fn odd_starts_round_down_and_high_windows_do_not_wrap() {
        assert_eq!(count_even_aligned_byte_chunks(0x82), 1);
        assert_eq!(count_even_aligned_byte_chunks(0x102), 2);
        assert_eq!(count_even_aligned_byte_chunks(0x204), 1);
        assert_eq!(count_even_aligned_byte_chunks(0x404), 2);
        assert_eq!(count_even_aligned_byte_chunks(0xc000_0001), 2);
        assert_eq!(count_even_aligned_byte_chunks(0x8000_0080), 2);
    }

    #[test]
    fn shifted_patterns_match_independent_bit_scan() {
        for pattern in 0..=0xffffu32 {
            for shift in [0, 1, 8, 15, 16] {
                let value = pattern << shift;
                assert_eq!(count_even_aligned_byte_chunks(value), reference(value),
                    "value={value:#010x}");
            }
        }
        for low in 0..32 {
            for high in low..32 {
                let value = (1u32 << low) | (1u32 << high);
                assert_eq!(count_even_aligned_byte_chunks(value), reference(value));
            }
        }
    }
}
