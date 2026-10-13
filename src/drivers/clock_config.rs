//! CLKCON1 divider-ratio encoding dispatch.
//!
//! Original `FUN_08003508` @ 0x08003508: true extent 8 bytes through the
//! next veneer at 0x08003510 (instruction e51ff004, literal 080d2e08).
//! Whole-image aligned A32 decoding verifies two plain inbound BL calls
//! (0x08001fe8, 0x08002120), zero predicated calls, and no outgoing BL.
//! Startup @ 0x080046e0 relocates the image by 0xaed8; the literal resolves
//! to raw 0x080ddce0, not the interior byte-swap block at raw 0x080d2e08.
//! That 68-byte body ends at the next prologue @ 0x080ddd24 and makes one
//! plain BL to __rt_udiv @ 0x08036f14.
//!
//! Divide ([12:8] + 1) by ([20:16] + 1), map quotient 1 to 0, 2 to 1,
//! and all others to quotient - 2; clear bits [5:0] and OR the encoding.
//! Deliberate deviation: implement the resolved body directly, using Rust
//! unsigned division instead of the existing ADS division helper. Quotient
//! zero deliberately wraps to 0xfffffffe and sets bits beyond [5:0].

/// Transform a CLKCON1 control word without touching MMIO.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn encode_clkcon1_divider_ratio(control: u32) -> u32 {
    let numerator = ((control >> 8) & 31) + 1;
    let denominator = ((control >> 16) & 31) + 1;
    let quotient = numerator / denominator;
    let encoded = match quotient {
        1 => 0,
        2 => 1,
        _ => quotient.wrapping_sub(2),
    };
    (control & !63) | encoded
}

#[cfg(test)]
mod tests {
    use super::encode_clkcon1_divider_ratio;

    #[test]
    fn all_divider_pairs_and_preserved_control_bits() {
        for numerator in 1u32..=32 {
            for denominator in 1u32..=32 {
                for preserved in [0, 0xa5e0_e0c0, 0xffe0_e0c0] {
                    let control = preserved | ((numerator - 1) << 8)
                        | ((denominator - 1) << 16) | 63;
                    // Independent repeated-subtraction quotient oracle.
                    let mut remainder = numerator;
                    let mut quotient = 0u32;
                    while remainder >= denominator {
                        remainder -= denominator;
                        quotient += 1;
                    }
                    let expected = if quotient == 1 { 0 } else if quotient == 2 {
                        1
                    } else { quotient.wrapping_sub(2) };
                    assert_eq!(encode_clkcon1_divider_ratio(control),
                        (control & !63) | expected);
                }
            }
        }
    }

    #[test]
    fn zero_quotient_is_not_masked_to_six_bits() {
        assert_eq!(encode_clkcon1_divider_ratio(0x001f_0000), 0xffff_fffe);
        assert_eq!(encode_clkcon1_divider_ratio(0x001f_0001), 0xffff_fffe);
        assert_eq!(encode_clkcon1_divider_ratio(0x8000_1f3f), 0x8000_1f1e);
        assert_eq!(encode_clkcon1_divider_ratio(0xffff_ffff), 0xffff_ffc0);
    }
}
