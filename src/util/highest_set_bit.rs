//! Index of the highest set bit — `FUN_080377d8` @ 0x080377d8 (12 bytes;
//! 5 `bl` call sites).
//!
//! A pure leaf: `31 - clz(x)`, i.e. the 0-based position of the
//! most-significant set bit, or −1 when no bit is set (`clz(0) == 32`).
//! This is integer `floor(log2)` for nonzero inputs, with a defined −1
//! answer for zero rather than a trap.
//!
//! The original is three instructions:
//!
//! ```text
//! clz r0, r0
//! rsb r0, r0, #0x1f
//! bx  lr
//! ```

/// highest_set_bit — original: `FUN_080377d8` @ 0x080377d8 (12 bytes).
///
/// Returns the 0-based index of the most-significant set bit of `value`,
/// or −1 when `value` is 0. `leading_zeros` lowers to ARM `clz`, so the
/// port is instruction-faithful.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn highest_set_bit(value: u32) -> i32 {
    31 - value.leading_zeros() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_has_no_set_bit() {
        assert_eq!(highest_set_bit(0), -1);
    }

    #[test]
    fn low_values_index_the_top_bit() {
        assert_eq!(highest_set_bit(1), 0);
        assert_eq!(highest_set_bit(2), 1);
        assert_eq!(highest_set_bit(3), 1); // 0b11 -> top bit is bit 1
    }

    #[test]
    fn byte_boundary() {
        assert_eq!(highest_set_bit(0xFF), 7);
        assert_eq!(highest_set_bit(0x100), 8);
    }

    #[test]
    fn top_bit_is_thirty_one() {
        assert_eq!(highest_set_bit(0x8000_0000), 31);
    }

    #[test]
    fn each_single_bit_reports_its_own_index() {
        for k in 0..32 {
            assert_eq!(highest_set_bit(1 << k), k as i32, "single bit {k}");
        }
    }

    #[test]
    fn lower_bits_below_the_msb_do_not_change_the_answer() {
        for k in 0..32 {
            let filled = (1u32 << k) | ((1u32 << k) - 1); // all bits 0..=k set
            assert_eq!(highest_set_bit(filled), k as i32, "filled up to {k}");
        }
    }
}
