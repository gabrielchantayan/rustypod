//! One-based index of the lowest set bit — `FUN_082b478c` @ 0x082b478c
//! (48 bytes; 0 internal `bl` instructions, 3 incoming `bl` call sites).
//!
//! The firmware returns zero for a zero input. Otherwise it walks masks from
//! bit 0 through bit 31 and returns that bit's one-based index. This is the
//! equivalent of `trailing_zeros() + 1` for nonzero values, but retains the
//! original mask-walk structure. Deliberate deviation: none.

/// `lowest_set_bit_one_based` — original: `FUN_082b478c` @ 0x082b478c
/// (48 bytes).
///
/// Returns zero when `value` is zero; otherwise returns the one-based index
/// of its least-significant set bit.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn lowest_set_bit_one_based(value: u32) -> u32 {
    if value == 0 {
        return 0;
    }

    let mut index = 1;
    let mut bit = 1;
    loop {
        if value & bit != 0 {
            return index;
        }
        index += 1;
        bit <<= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::lowest_set_bit_one_based;

    #[test]
    fn zero_returns_zero() {
        assert_eq!(lowest_set_bit_one_based(0), 0);
    }

    #[test]
    fn each_single_bit_has_a_one_based_index() {
        for bit in 0..32 {
            assert_eq!(lowest_set_bit_one_based(1 << bit), bit + 1);
        }
    }

    #[test]
    fn higher_bits_do_not_change_the_lowest_set_bit() {
        assert_eq!(lowest_set_bit_one_based(0x8000_0001), 1);
        assert_eq!(lowest_set_bit_one_based(0x8000_0010), 5);
        assert_eq!(lowest_set_bit_one_based(0xffff_8000), 16);
    }
}
