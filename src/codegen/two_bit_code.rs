//! cg_two_bit_code_or_zero — `FUN_082b4964` @ 0x082b4964 (40 bytes; 12 `bl` call sites, all unconditional).
//!
//! The code-generator's leaf preserves two-bit codes 1, 2, and 3 exactly;
//! it maps zero and every out-of-range 32-bit representation to zero.  The
//! original implements the inclusive range with three comparisons and early
//! returns.  This port expresses the same C-ABI result directly; no
//! deliberate behavioural deviations.

/// Preserves a nonzero two-bit `code`, or returns zero when it is invalid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn cg_two_bit_code_or_zero(code: u32) -> u32 {
    if code <= 3 { code } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_two_bit_code_or_zero(code: u32) -> u32 {
        if code == 0 {
            0
        } else if code == 1 {
            1
        } else if code == 2 {
            2
        } else if code == 3 {
            3
        } else {
            0
        }
    }

    #[test]
    fn preserves_only_encodable_two_bit_codes() {
        for code in [0, 1, 2, 3, 4, u32::MAX] {
            assert_eq!(cg_two_bit_code_or_zero(code), reference_two_bit_code_or_zero(code));
        }
    }

    #[test]
    fn rejects_every_non_two_bit_byte_value() {
        for code in 0_u32..=u8::MAX.into() {
            assert_eq!(cg_two_bit_code_or_zero(code), reference_two_bit_code_or_zero(code));
        }
    }
}
