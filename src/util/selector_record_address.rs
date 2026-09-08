//! `selector_record_address` — original: `FUN_08218aec` @ `0x08218aec`
//! (36 bytes; `0x08218aec..0x08218b10`).
//!
//! # Algorithm
//!
//! The ARM leaf accepts selector values `0x801c..=0x8029`. For a selector in
//! that inclusive range, it returns the address of its 12-byte record in a
//! table whose effective base is `base - 0x60144`: `base + selector * 12 -
//! 0x60144`. Its two subtractions and `cmp` make the range test unsigned, so
//! every other `u32` selector returns zero. Arithmetic deliberately wraps at
//! 32 bits, matching ARM `sub` and `add`.
//!
//! Deliberate deviations: none.
//!
//! Raw osos.dec decoding finds exactly 19 direct call sites, all unconditional
//! `bl`; there are no predicated calls or plain branches to this entry.

/// selector_record_address — original: `FUN_08218aec` @ `0x08218aec`
/// (36 bytes).
///
/// Returns the table record address for a selector in `0x801c..=0x8029`, or
/// zero when the selector lies outside that range.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn selector_record_address(base: u32, selector: u32) -> u32 {
    if selector.wrapping_sub(0x801c) < 14 {
        base.wrapping_add(selector.wrapping_mul(12)).wrapping_sub(0x60144)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arm_reference(base: u32, selector: u32) -> u32 {
        let range_index = selector.wrapping_sub(0x8000).wrapping_sub(0x1c);
        if range_index < 14 {
            let tripled_selector = selector.wrapping_add(selector.wrapping_shl(1));
            base.wrapping_add(tripled_selector.wrapping_shl(2))
                .wrapping_sub(0x60000)
                .wrapping_sub(0x144)
        } else {
            0
        }
    }

    #[test]
    fn maps_each_of_the_fourteen_valid_selectors() {
        for selector in 0x801c..=0x8029 {
            assert_eq!(selector_record_address(0x089c_a674, selector),
                       arm_reference(0x089c_a674, selector));
        }
    }

    #[test]
    fn rejects_selectors_immediately_outside_the_unsigned_range() {
        for selector in [0, 0x801b, 0x802a, u32::MAX] {
            assert_eq!(selector_record_address(0x089c_a674, selector), 0);
            assert_eq!(selector_record_address(0x089c_a674, selector),
                       arm_reference(0x089c_a674, selector));
        }
    }

    #[test]
    fn preserves_arm_wrapping_arithmetic_for_valid_selectors() {
        for base in [0, 1, 0xffff_ffff, 0xffff_f000] {
            for selector in [0x801c, 0x8022, 0x8029] {
                assert_eq!(selector_record_address(base, selector),
                           arm_reference(base, selector));
            }
        }
    }
}
