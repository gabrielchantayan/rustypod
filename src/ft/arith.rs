//! Small FreeType arithmetic helpers whose semantics are defined by the
//! retailOS ARM implementation rather than an identified upstream API.

/// ft_round_add_clear_bit16 — original: `FUN_08044200` @ 0x08044200
/// (36 bytes; 2 direct callers).
///
/// Treats both unsigned 32-bit operands independently: an odd operand is
/// incremented with 32-bit wraparound and then has bit 16 cleared. The
/// resulting words are added with 32-bit wraparound and bit 16 of that sum
/// is cleared. Even operands retain bit 16 until the final result clear, as
/// required by the ARM's conditional `bic` instructions. At both call sites
/// `left` is a byte- or halfword field plus 1 or 2; `right` is passed through
/// in a register, and the result is consumed by unsigned comparisons. That
/// establishes the `u32` ABI but not a more specific upstream representation.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ft_round_add_clear_bit16(mut left: u32, mut right: u32) -> u32 {
    const BIT_16: u32 = 1 << 16;

    if left & 1 != 0 {
        left = left.wrapping_add(1) & !BIT_16;
    }
    if right & 1 != 0 {
        right = right.wrapping_add(1) & !BIT_16;
    }

    left.wrapping_add(right) & !BIT_16
}

#[cfg(test)]
mod tests {
    use super::ft_round_add_clear_bit16;

    const BIT_16: u32 = 1 << 16;

    // A widened arithmetic model, kept separate from the port's control
    // flow, so the test checks operand rounding, final masking, and u32
    // truncation independently.
    fn reference_operand(value: u32) -> u32 {
        if value % 2 == 0 {
            value
        } else {
            (((value as u64) + 1) & !(BIT_16 as u64)) as u32
        }
    }

    fn reference(left: u32, right: u32) -> u32 {
        ((reference_operand(left) as u64 + reference_operand(right) as u64) as u32) & !BIT_16
    }

    #[test]
    fn rounds_each_odd_operand_through_bit16() {
        for &(left, right) in &[
            (0x0000_ffff, 0),
            (0, 0x0000_ffff),
            (0x0000_ffff, 0x0000_ffff),
            (0x0001_0001, 0x0003_0001),
        ] {
            assert_eq!(
                ft_round_add_clear_bit16(left, right),
                reference(left, right),
                "{left:#010x} + {right:#010x}",
            );
        }
    }

    #[test]
    fn clears_bit16_created_by_addition() {
        let left = 0x0000_8000;
        let right = 0x0000_8000;
        assert_eq!(ft_round_add_clear_bit16(left, right), 0);
        assert_eq!(
            ft_round_add_clear_bit16(left, right),
            reference(left, right),
        );
    }

    #[test]
    fn preserves_u32_wrapping_boundaries() {
        for &(left, right) in &[
            (u32::MAX, 0),
            (u32::MAX, u32::MAX),
            (0xffff_fffe, 2),
            (0xffff_7ffe, 2),
        ] {
            assert_eq!(
                ft_round_add_clear_bit16(left, right),
                reference(left, right),
                "{left:#010x} + {right:#010x}",
            );
        }
    }

    #[test]
    fn agrees_with_reference_on_rounding_and_mask_boundaries() {
        let boundaries = [
            0,
            1,
            0xfffe,
            0xffff,
            0x1_0000,
            0x1_0001,
            0xffff_ffff,
            0xffff_0000,
        ];
        for &left in &boundaries {
            for &right in &boundaries {
                assert_eq!(
                    ft_round_add_clear_bit16(left, right),
                    reference(left, right),
                    "{left:#010x} + {right:#010x}",
                );
            }
        }
    }
}
